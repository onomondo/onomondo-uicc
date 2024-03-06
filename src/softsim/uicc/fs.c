/*
 * Copyright (c) 2024 Onomondo ApS. All rights reserved.
 *
 * SPDX-License-Identifier: GPL-3.0-only
 *
 * Author: Philipp Maier
 */

#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <errno.h>
#include <onomondo/softsim/softsim.h>
#include <onomondo/softsim/log.h>
#include <onomondo/softsim/storage.h>
#include <onomondo/softsim/list.h>
#include <onomondo/softsim/file.h>
#include <onomondo/softsim/utils.h>
#include <onomondo/softsim/mem.h>
#include "btlv.h"
#include "fs.h"
#include "fs_utils.h"
#include "fcp.h"
#include "access.h"
#define FILE_MF 0x3f00

/* Allocate a new file struct and extend the current file path */
static struct ss_file *path_add(struct ss_list *path, uint32_t fid)
{
	struct ss_file *file;

	file = SS_ALLOC(struct ss_file);
	memset(file, 0, sizeof(*file));
	file->fid = fid;
	ss_list_put(path, &file->list);

	return file;
}

/* Free a file struct and its contents. */
void file_free(struct ss_file *file)
{
	if (!file)
		return;
	ss_buf_free(file->fci);
	ss_btlv_free(file->fcp_decoded);
	SS_FREE(file->fcp_file_descr);
	ss_btlv_free(file->access);
	SS_FREE(file);
}

/* Remove last entry from the current path (when another file in the same DF is
 * selected)
 *
 * Note that while being a "select" call, this does not populate the file's
 * indirect details -- but if the file was previously accessed through \ref
 * ss_fs_select, they will also be present after calling this function.
 * */
int ss_fs_select_parent(const struct ss_list *path)
{
	struct ss_file *file;

	if (ss_list_empty(path))
		return -EINVAL;

	file = SS_LIST_GET(path->previous, struct ss_file, list);
	ss_list_remove(&file->list);
	file_free(file);

	/* There must be still a file (parent) in the path after we have
	 * selected the parent! */
	if (ss_list_empty(path))
		return -EINVAL;

	return 0;
}

/*! Clear path completely (when MF is selected).
 *  \param[inout] path path to reset. */
void ss_path_reset(struct ss_list *path)
{
	/*! NOTE: This is essentially freeing all items from the path list.
	 *  this function can be used to free copies made with ss_fs_utils_path_clone() */

	int rc;
	do {
		rc = ss_fs_select_parent(path);
	} while (rc == 0);
}

static struct ss_buf *file_descr_from_fcp(const struct ss_list *fcp_decoded_envelope)
{
	struct ber_tlv_ie *fcp_decoded_file_descr;

	if (!fcp_decoded_envelope)
		return NULL;
	fcp_decoded_file_descr = ss_btlv_get_ie_minlen(fcp_decoded_envelope, 0x82, 2);
	if (!fcp_decoded_file_descr)
		return NULL;

	/* NOTE: The caller must not take ownership of the value */
	return fcp_decoded_file_descr->value;
}

/**
 * Find a file relative to a given one, and read a record
 *
 * This implements the rules for location of the access rules of TS 102 221 V15
 * section 9.2.7, but is phrased in the general terms of file system access.
 *
 * \pre file_path contains some file.
 *
 * \pre record_number != 0
 *
 * \return a buffer containing the full record (or NULL if no file was found /
 *   the indicated record was not present)
 */
struct ss_buf *ss_fs_read_relative_file_record(const struct ss_list *path, uint16_t file_id, uint8_t record_number)
{
	struct ss_list efarr_path;
	if (ss_fs_utils_path_clone(&efarr_path, path) != 0) {
		SS_LOGP(SFS, LERROR, "Insufficient memory to discover file.\n");
		return NULL;
	}

	/* ADFs are specified to look up their EF.ARR in the master file */
	if (ss_get_file_from_path(path)->aid != NULL) {
		while (ss_get_file_from_path(path)->fid != FILE_MF)
			ss_fs_select_parent(&efarr_path);
	}

	/* selecting the indicated file_id in a DF would produce an EF.ARR in
	 * the selected directory -- but TS 102 221 V15.0.0 Section 9.2.7,
	 * second list, second bullet tells us to look above.
	 *
	 * The MF is excluded from that rule for obvious reasons.
	 * */
	if (ss_get_file_from_path(path)->fcp_file_descr->type == SS_FCP_DF_OR_ADF &&
	    ss_get_file_from_path(path)->fid != FILE_MF)
		ss_fs_select_parent(&efarr_path);

	int select_rc = -1;
	while (!ss_list_empty(&efarr_path)) {
		select_rc = ss_fs_select(&efarr_path, file_id);
		if (select_rc == 0)
			break;
		ss_fs_select_parent(&efarr_path);
	}
	if (select_rc != 0) {
		SS_LOGP(SFS, LERROR, "Reference pointed to nonexistent file\n");
		return NULL;
	}

	struct ss_buf *result = ss_fs_read_file_record(&efarr_path, record_number);

	ss_path_reset(&efarr_path);
	return result;
}

/*! Select a file from the file system
 *
 *  \param[inout] path File path to manipulate.
 *  \param[in] fid file ID to select.
 *
 *  \returns zero on success, or an error number
 *
 *  \post On success, there is a file selected in @p path.
 *
 */
int ss_fs_select(struct ss_list *path, uint32_t fid)
{
	int rc;
	struct ss_file *selected_file;
	struct ss_buf *file_descr;

	/* Selection of the MF always resets the path */
	if (fid == FILE_MF)
		ss_path_reset(path);

	/* When the currently selected file is an EF, then we must remove this
	 * file first. */
	selected_file = ss_get_file_from_path(path);
	if (selected_file) {
		if (selected_file->fcp_file_descr->type != SS_FCP_DF_OR_ADF)
			ss_fs_select_parent(path);
	}

	/* Add a new file to the path */
	selected_file = path_add(path, fid);

	/* Read the file defintion from storage */
	rc = ss_storage_get_file_def(path);
	if (rc < 0) {
		ss_fs_select_parent(path);
		SS_LOGP(SFS, LINFO, "select fid=%04x failed, path=%s\n", fid, ss_fs_utils_dump_path(path));
		return -EINVAL;
	}

	/* Store parsed representation of the FCP */
	selected_file->fcp_decoded = NULL;
	struct ss_list *fci_decoded = ss_fcp_decode(selected_file->fci);
	struct ber_tlv_ie *fcp_decoded_envelope = NULL;

	if (fci_decoded)
		fcp_decoded_envelope = ss_btlv_get_ie(fci_decoded, TS_102_221_IEI_FCP_TMPL);
	if (fcp_decoded_envelope) {
		selected_file->fcp_decoded = fcp_decoded_envelope->nested;
		/* We're moved responsibility for freeing the nested elements to the
		 * file; breaking the link allows easy cleanup. */
		fcp_decoded_envelope->nested = NULL;
		ss_btlv_free(fci_decoded);
	}

	if (!selected_file->fcp_decoded) {
		ss_fs_select_parent(path);
		SS_LOGP(SBTLV, LERROR, "select fid=%04x failed, path=%s, unable to decode FCP\n", fid,
			ss_fs_utils_dump_path(path));
		return -EINVAL;
	}

	file_descr = file_descr_from_fcp(selected_file->fcp_decoded);
	if (!file_descr) {
		ss_fs_select_parent(path);
		SS_LOGP(SBTLV, LERROR, "select fid=%04x failed, path=%s, unable to decode FD\n", fid,
			ss_fs_utils_dump_path(path));
	}

	selected_file->fcp_file_descr = SS_ALLOC(struct ss_fcp_file_descr);
	ss_fcp_dec_file_descr(selected_file->fcp_file_descr, file_descr);
	return 0;
}

/*! Read record from file (tip of the path).
 *  \param[in] path path to the file to be read.
 *  \param[in] record_no number of the record to be read.
 *  \returns buffer with record data on success, NULL on failure */
struct ss_buf *ss_fs_read_file_record(const struct ss_list *path, size_t record_no)
{
	struct ss_file *file;

	file = ss_get_file_from_path(path);
	if (!file)
		return NULL;

	/* Reacord number 0 always points to the current record. The caller
	 * has to maintain this state and then call this function with the
	 * absolue record number. */
	if (record_no == 0) {
		SS_LOGP(SFS, LINFO, "non existing record (%lu) referenced in file (%04x)\n", record_no, file->fid);
		return NULL;
	}

	if (record_no > file->fcp_file_descr->number_of_records + 1) {
		SS_LOGP(SFS, LINFO, "non existing record (%lu) referenced in file (%04x)\n", record_no, file->fid);
		return NULL;
	}

	if (file->fcp_file_descr->structure != SS_FCP_LINEAR_FIXED &&
	    file->fcp_file_descr->structure != SS_FCP_CYCLIC) {
		SS_LOGP(SFS, LINFO, "cannot read record from non record oriented file (%04x)\n", file->fid);
		return NULL;
	}

	return ss_storage_read_file(path, (record_no - 1) * file->fcp_file_descr->record_len,
				    file->fcp_file_descr->record_len);
}

/*! Write record to file (tip of the path).
 *  \param[in] path path to the file to write.
 *  \param[in] record_no number of the record to write.
 *  \param[in] data user provided memory with record data.
 *  \param[in] data record data length (checked against FCP).
 *  \returns 0 on success, -EINVAL on failure */
int ss_fs_write_file_record(const struct ss_list *path, size_t record_no, const uint8_t *data, size_t len)
{
	struct ss_file *file;

	file = ss_get_file_from_path(path);
	if (!file)
		return -EINVAL;

	/* See also note in ss_fs_get_file_record() */
	if (record_no == 0) {
		SS_LOGP(SFS, LINFO, "non existing record (%lu) referenced in file (%04x)\n", record_no, file->fid);
		return -EINVAL;
	}

	if (record_no > file->fcp_file_descr->number_of_records + 1) {
		SS_LOGP(SFS, LINFO, "non existing record (%lu) referenced in file (%04x), file has %u records\n",
			record_no, file->fid, file->fcp_file_descr->number_of_records);
		return -EINVAL;
	}

	if (file->fcp_file_descr->structure != SS_FCP_LINEAR_FIXED &&
	    file->fcp_file_descr->structure != SS_FCP_CYCLIC) {
		SS_LOGP(SFS, LINFO, "cannot write record on non record oriented file (%04x)\n", file->fid);
		return -EINVAL;
	}

	if (file->fcp_file_descr->record_len != len) {
		SS_LOGP(SFS, LINFO, "cannot write record with improper length (%u != %lu) to file (%04x)\n",
			file->fcp_file_descr->record_len, len, file->fid);
		return -EINVAL;
	}

	return ss_storage_write_file(path, data, (record_no - 1) * file->fcp_file_descr->record_len,
				     file->fcp_file_descr->record_len);
}

/*! Initialize filesystem.
 *  \param[inout] path to initialize. */
void ss_fs_init(struct ss_list *path)
{
	ss_list_init(path);

	/* Make sure the MF is selected on startup */
	ss_fs_select(path, FILE_MF);
}

/*! Create a file or directory on the file system.
 *  \param[inout] path directory where the file or directory shall be created.
 *  \param[in] fci file control information for the file or directory to
 *      create, in particular containing FCP (file control parameters).
 *  \returns 0 success, -EINVAL on failure */
int ss_fs_create(struct ss_list *path, const uint8_t *fci_data, size_t fci_len)
{
	/*! NOTE: This function will only create the file in the file system
	 *  along with a vaild definition file. It will not write ARR or SFID
	 *  entries or select the file. Those tasks have to be done in seperate
	 *  steps by the caller. */

	int rc = 0;
	struct ss_file *file;
	struct ss_list *fci_decoded;
	struct ber_tlv_ie *fcp_tmpl_ie;
	struct ber_tlv_ie *fcp_fid_ie;
	struct ber_tlv_ie *fcp_file_size_ie;
	struct ber_tlv_ie *fcp_file_descr_ie;

	uint32_t fid;
	uint32_t size;
	struct ss_fcp_file_descr file_descr;
	struct ss_buf *fci;

	/* Decode FCP template (envelope) */
	fci_decoded = ss_btlv_decode(fci_data, fci_len, NULL);
	if (!fci_decoded) {
		SS_LOGP(SFS, LERROR, "Failed to decode BTLV in file creation\n");
		return -EINVAL;
	}
	fcp_tmpl_ie = ss_btlv_get_ie(fci_decoded, TS_102_221_IEI_FCP_TMPL);
	if (!fcp_tmpl_ie) {
		SS_LOGP(SFS, LERROR, "Missing FCP TMPL in file creation\n");
		rc = -EINVAL;
		goto leave;
	}

	/* Decode FID */
	fcp_fid_ie = ss_btlv_get_ie_minlen(fcp_tmpl_ie->nested, TS_102_221_IEI_FCP_FILE_ID, 2);
	if (!fcp_fid_ie) {
		SS_LOGP(SFS, LERROR, "Missing FID IE in file creation\n");
		rc = -EINVAL;
		goto leave;
	}
	fid = ss_uint32_from_array(fcp_fid_ie->value->data, fcp_fid_ie->value->len);

	/* Decode File descriptor */
	fcp_file_descr_ie = ss_btlv_get_ie_minlen(fcp_tmpl_ie->nested, TS_102_221_IEI_FCP_FILE_DESCR, 2);
	if (!fcp_file_descr_ie) {
		SS_LOGP(SFS, LERROR, "Missing file descriptor in file creation\n");
		rc = -EINVAL;
		goto leave;
	}
	if (ss_fcp_dec_file_descr(&file_descr, fcp_file_descr_ie->value) < 0) {
		SS_LOGP(SFS, LERROR, "Error decoding file descriptor file creation\n");
		rc = -EINVAL;
		goto leave;
	}

	/* Make sure that the supplied path points to a DF or ADF. */
	file = ss_get_file_from_path(path);
	if (file && file->fcp_file_descr->type != SS_FCP_DF_OR_ADF) {
		ss_fs_select_parent(path);
	}

	/* Add a file with the supplied FCP to the path. This must not be
	 * confused with a proper select. We just fullfill the bare minimum
	 * requirements that the storage layer will accept */
	file = path_add(path, fid);

	/* Note: When the file is removed from the path again (see below),
	 * the fci we allocate here is freed. */
	fci = ss_buf_alloc_and_cpy(fci_data, fci_len);
	file->fci = fci;

	if (file_descr.type == SS_FCP_DF_OR_ADF)
		rc = ss_storage_create_dir(path);
	else {
		/* Decode file size */
		fcp_file_size_ie = ss_btlv_get_ie_minlen(fcp_tmpl_ie->nested, TS_102_221_IEI_FCP_FILE_SIZE, 1);
		if (!fcp_file_size_ie) {
			SS_LOGP(SFS, LERROR, "Missing file size file creation\n");
			rc = -EINVAL;
			/* Remove file from the path and leave */
			ss_fs_select_parent(path);
			goto leave;
		}
		size = ss_uint32_from_array(fcp_file_size_ie->value->data, fcp_file_size_ie->value->len);
		rc = ss_storage_create_file(path, size);
	}

	/* Remove the file from the path again */
	ss_fs_select_parent(path);

leave:
	ss_btlv_free(fci_decoded);
	return rc;
}
