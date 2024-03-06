/*
 * Copyright (c) 2024 Onomondo ApS. All rights reserved.
 *
 * SPDX-License-Identifier: GPL-3.0-only
 *
 * Author: Philipp Maier
 */

#include <stdio.h>
#include <stdbool.h>
#include <errno.h>
#include <onomondo/softsim/file.h>
#include <onomondo/softsim/utils.h>
#include <onomondo/softsim/list.h>
#include "fs.h"
#include "fs_utils.h"
#include "fcp.h"
#include "btlv.h"

#define DF_NAME_FID 0xA1DF1D01

/*! Register a FID in the internal SFI to FID translation file.
 *  \param[inout] path path to the file that shall be registered.
 *  \returns 0 success, -EINVAL on failure. */
int ss_df_name_update(struct ss_list *path)
{
	struct ss_file *file;
	struct ber_tlv_ie *fcp_df_name_ie;
	struct ber_tlv_ie *fcp_fid_ie;
	int rc;
	uint8_t record[16 + 2];
	size_t free_record;
	struct ss_list path_copy;

	/* ensure we won't work on an uninitialized list */
	ss_list_init(&path_copy);

	/*! NOTE: This function will always search in the currently selected DF
	 *  or ADF for the DF_NAME to FID lookup file */

	file = ss_get_file_from_path(path);

	/* get FID */
	fcp_fid_ie = ss_btlv_get_ie_minlen(file->fcp_decoded, TS_102_221_IEI_FCP_FILE_ID, 2);
	if (!fcp_fid_ie)
		return -EINVAL;

	/* Extract DF Name (if present) */
	fcp_df_name_ie = ss_btlv_get_ie_minlen(file->fcp_decoded, TS_102_221_IEI_FCP_DF_NAME, 1);
	if (!fcp_df_name_ie) {
		/* Nothing to do, This file just has no DF_NAME assigned */
		return 0;
	}

	if (fcp_df_name_ie->value->len > 16) {
		SS_LOGP(SDFNAME, LERROR, "cannot register too long DF_NAME %s, len=%lu > 16\n",
			ss_hexdump(fcp_df_name_ie->value->data, fcp_df_name_ie->value->len),
			fcp_df_name_ie->value->len);
		return -EINVAL;
	}
	memset(record, 0, sizeof(record));
	memcpy(record, fcp_df_name_ie->value->data, fcp_df_name_ie->value->len);
	assert(fcp_fid_ie->value->len == 2);
	memcpy(record + 16, fcp_fid_ie->value->data, fcp_fid_ie->value->len);

	/* select lookup file and add new DF_NAME/FID_RECORD. If the file does
	 * not exist, create it. */
	rc = ss_fs_utils_path_clone(&path_copy, path);
	if (rc < 0)
		return -EINVAL;
	rc = ss_fs_select_parent(&path_copy);
	if (rc < 0) {
		/* Under normal conditions this shouldn't happen. If it does,
		 * then an inconsistent file system or a bug/misuse of this
		 * function might be the cause. */
		SS_LOGP(SDFNAME, LERROR,
			"failed to select parent directory - this is where we would expect the lookup file to be\n");
		rc = -EINVAL;
		goto leave;
	}

	/* Select lookup file. If it does not exist, create a new one. */
	rc = ss_fs_select(&path_copy, DF_NAME_FID);
	if (rc < 0) {
		SS_LOGP(SDFNAME, LERROR, "lookup file %s does not exist, creating a new one.\n",
			ss_fs_utils_dump_path(&path_copy));
		rc = ss_fs_utils_create_record_file(&path_copy, DF_NAME_FID, 16 + 2, 16);
		rc += ss_fs_select(&path_copy, DF_NAME_FID);
		if (rc < 0) {
			SS_LOGP(SDFNAME, LERROR, "failed to create lookup file %s\n",
				ss_fs_utils_dump_path(&path_copy));
			rc = -EINVAL;
			goto leave;
		}
	}

	/* Find a free record */
	free_record = ss_fs_utils_find_free_record(&path_copy);
	if (!free_record) {
		SS_LOGP(SDFNAME, LERROR, "failed to register DF_NAME=%s in lookup file %s - no free record found\n",
			ss_hexdump(fcp_df_name_ie->value->data, fcp_df_name_ie->value->len),
			ss_fs_utils_dump_path(&path_copy));
		rc = -EINVAL;
		goto leave;
	}

	rc = ss_fs_write_file_record(&path_copy, free_record, record, sizeof(record));
	if (rc < 0) {
		SS_LOGP(SDFNAME, LERROR, "failed to register DF_NAME=%s in lookup file %s - could not write record\n",
			ss_hexdump(fcp_df_name_ie->value->data, fcp_df_name_ie->value->len),
			ss_fs_utils_dump_path(&path_copy));
		rc = -EINVAL;
		goto leave;
	}

	SS_LOGP(SDFNAME, LDEBUG, "registered DF_NAME=%s for FID=%02x%02x in file %s on record number %lu\n",
		ss_hexdump(fcp_df_name_ie->value->data, fcp_df_name_ie->value->len), fcp_fid_ie->value->data[0],
		fcp_fid_ie->value->data[1], ss_fs_utils_dump_path(&path_copy), free_record);
	rc = 0;
leave:
	ss_path_reset(&path_copy);
	return rc;
}

/*! Resolve an DF NAME (AID) to FID by querying the DF NAME to FID translation file.
 *  \param[inout] path path to the current directory.
 *  \param[in] df_name DF NAME to look for.
 *  \param[in] df_name_len length of the DF NAME.
 *  \returns 0 success, -EINVAL on failure */
int ss_df_name_resolve(struct ss_list *path, const uint8_t *df_name, size_t df_name_len)
{
	struct ss_list path_copy;
	int rc;
	uint32_t fid;
	struct ss_buf *record;
	struct ss_file *file;
	size_t record_number;
	uint8_t template[16 + 2];
	uint8_t mask[16 + 2];

	/*! NOTE: This function will always search in the currently selected DF
	 *  or ADF for the SFI to FID translation file */

	/* A DF_name can only be max. 16 bytes long */
	if (df_name_len > 16)
		return -EINVAL;

	/* ensure we won't work on an uninitialized list */
	ss_list_init(&path_copy);

	/* select lookup file */
	rc = ss_fs_utils_path_clone(&path_copy, path);
	if (rc < 0)
		return -EINVAL;
	rc = ss_fs_select(&path_copy, DF_NAME_FID);
	if (rc < 0) {
		SS_LOGP(SDFNAME, LERROR, "cannot resolve DF_NAME=%s, unable to select lookup file in %s\n",
			ss_hexdump(df_name, df_name_len), ss_fs_utils_dump_path(&path_copy));
		rc = -EINVAL;
		goto leave;
	}

	/* search for DF_NAME in file to find related FID */
	file = ss_get_file_from_path(&path_copy);
	if (!file) {
		rc = -EINVAL;
		goto leave;
	}

	memcpy(template, df_name, df_name_len);
	memset(mask, 0x00, sizeof(mask));
	memset(mask, 0xff, df_name_len);

	record_number = ss_fs_utils_find_record(&path_copy, template, mask, sizeof(template));
	if (!record_number) {
		SS_LOGP(SDFNAME, LERROR,
			"unable to resolve DF_NAME=%s to FID - lookup file %s has no matching record\n",
			ss_hexdump(df_name, df_name_len), ss_fs_utils_dump_path(&path_copy));
		rc = -EINVAL;
		goto leave;
	}

	record = ss_fs_read_file_record(&path_copy, record_number);
	if (!record) {
		SS_LOGP(SDFNAME, LERROR,
			"unable to resolve DF_NAME=%s to FID - lookup file %s is not readable at record number %lu\n",
			ss_hexdump(df_name, df_name_len), ss_fs_utils_dump_path(&path_copy), record_number);
		rc = -EINVAL;
		goto leave;
	}

	fid = ss_uint32_from_array(record->data + 16, 2);
	SS_LOGP(SDFNAME, LDEBUG, "resolved DF_NAME=%s to FID=%04x using lookup file %s\n",
		ss_hexdump(df_name, df_name_len), fid, ss_fs_utils_dump_path(&path_copy));
	ss_buf_free(record);
	rc = fid;

leave:
	ss_path_reset(&path_copy);
	return rc;
}
