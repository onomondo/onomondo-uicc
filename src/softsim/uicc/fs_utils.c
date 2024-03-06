/*
 * Copyright (c) 2024 Onomondo ApS. All rights reserved.
 * 
 * SPDX-License-Identifier: GPL-3.0-only 
 */

#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <errno.h>
#include <onomondo/softsim/file.h>
#include <onomondo/softsim/utils.h>
#include <onomondo/softsim/log.h>
#include "fs.h"
#include "fs_utils.h"
#include "fcp.h"
#include "btlv.h"

/*! Dump path to a human readable string (row of selected FIDs).
 *  \param[in] path path to dump.
 *  \returns string with path in human readable form. */
char *ss_fs_utils_dump_path(const struct ss_list *path)
{
	static char result[1024];
	static char *result_ptr;
	struct ss_file *path_cursor;
	int rc;

	/* Don't accept uninitialized pathes! */
	assert(path);

	if (ss_list_empty(path))
		return "(no file selected)";

	memset(result, 0, sizeof(result));
	result_ptr = result;

	SS_LIST_FOR_EACH(path, path_cursor, struct ss_file, list) {
		rc = snprintf(result_ptr, sizeof(result) - (result_ptr - result), "/%04x", path_cursor->fid);
		result_ptr += rc;
	}

	return result;
}

/*! Find first free record in a record oriented file.
 *  \param[in] path path to the file to examine.
 *  \returns 0 on failure, record number on success. */
size_t ss_fs_utils_find_free_record(const struct ss_list *path)
{
	size_t i;
	size_t k;
	struct ss_file *file;
	struct ss_buf *record;
	bool free;

	file = ss_get_file_from_path(path);
	if (!file)
		return 0;

	for (i = 0; i < file->fcp_file_descr->number_of_records; i++) {
		record = ss_fs_read_file_record(path, i + 1);
		if (!record) {
			SS_LOGP(SFS, LERROR, "cannot read record %lu in internal file: %s\n", i + 1,
				ss_fs_utils_dump_path(path));
			return 0;
		}
		if (record->len == 0) {
			SS_LOGP(SFS, LERROR, "file (%s) seems to contain zero length record (bad file descriptor?)\n",
				ss_fs_utils_dump_path(path));
			return 0;
		}

		free = true;
		for (k = 0; k < record->len; k++) {
			if (record->data[k] != 0xff) {
				free = false;
				break;
			}
		}
		ss_buf_free(record);
		if (free)
			return i + 1;
	}

	/* No free record found */
	return 0;
}

/*! Find first free record in a record oriented file.
 *  \param[in] path path to the file to examine.
 *  \param[in] template to compare against record content.
 *  \param[in] mask a mask to tell which bits in the template matter.
 *  \param[in] len length of template and mask (both must be equal in length).
 *  \returns 0 on failure, record number on success. */
size_t ss_fs_utils_find_record(const struct ss_list *path, const uint8_t *template, const uint8_t *mask, size_t len)
{
	struct ss_file *file;
	size_t i;
	size_t k;
	struct ss_buf *record;
	bool mismatch;

	file = ss_get_file_from_path(path);
	if (!file)
		return 0;

	if (len > file->fcp_file_descr->record_len)
		return 0;

	for (i = 0; i < file->fcp_file_descr->number_of_records; i++) {
		record = ss_fs_read_file_record(path, i + 1);
		if (!record) {
			SS_LOGP(SFS, LERROR, "cannot read record %lu in internal file: %s\n", i + 1,
				ss_fs_utils_dump_path(path));
			return 0;
		}

		mismatch = false;
		for (k = 0; k < len; k++) {
			if ((record->data[k] & mask[k]) != (template[k] & mask[k]))
				mismatch = true;
		}

		ss_buf_free(record);

		if (!mismatch)
			return i + 1;
	}

	return 0;
}

/*! Create an internal record oriented file to manage internal tasks.
 *  \param[in] path directory where the file shall be created.
 *  \param[in] fid file identifier to use.
 *  \param[in] record_len length of the records in the file.
 *  \param[in] number_of_records number of records in the file.
 *  \returns 0 success, -EINVAL on failure */
int ss_fs_utils_create_record_file(const struct ss_list *path, uint32_t fid, uint16_t record_len,
				   uint8_t number_of_records)
{
	struct ss_buf *fcp;
	struct ss_fcp_file_descr fd;
	int rc;
	struct ss_list path_copy;

	/*! This function must not be used to create normal files (16 bit FID),
	 *  which are accessible from outside. */
	assert(fid > 0xffff);

	/* ensure we won't work on an uninitialized list */
	ss_list_init(&path_copy);

	/* generate FCP for interhal SFI file */
	memset(&fd, 0, sizeof(fd));
	fd.type = SS_FCP_WORKING_EF;
	fd.structure = SS_FCP_LINEAR_FIXED;
	fd.record_len = record_len;
	fd.number_of_records = number_of_records;
	fcp = ss_fcp_gen(&fd, fid, fd.record_len * fd.number_of_records);
	if (!fcp)
		return -EINVAL;

	/* create new internal SFI file */
	rc = ss_fs_utils_path_clone(&path_copy, path);
	if (rc < 0) {
		rc = -EINVAL;
		goto leave;
	}
	rc = ss_fs_create(&path_copy, fcp->data, fcp->len);
	if (rc < 0) {
		SS_LOGP(SFS, LERROR, "cannot create internal file %08x in directory: %s\n", fid,
			ss_fs_utils_dump_path(path));
		rc = -EINVAL;
		goto leave;
	}

	SS_LOGP(SFS, LDEBUG, "created new internal record oriented file %08x in directory: %s\n", fid,
		ss_fs_utils_dump_path(path));
	rc = 0;
leave:
	ss_buf_free(fcp);
	ss_path_reset(&path_copy);
	return 0;
}

/*! Obtain a deep copy of a path.
 *  \param[out] path_copy user provided memory to store the copyied path.
 *  \param[in] path path that shall be copied.
 *  \returns 0 success, -ENOMEM on failure */
int ss_fs_utils_path_clone(struct ss_list *path_copy, const struct ss_list *path)
{
	struct ss_file *path_cursor;

	/*! NOTE: This currently does not copy the (original and decoded) FCP data, as it is
	 * not needed by the function's callers -- and would be even more
	 * computationally expensive. */

	ss_list_init(path_copy);

	SS_LIST_FOR_EACH(path, path_cursor, struct ss_file, list) {
		struct ss_file *latest;
		struct ss_fcp_file_descr *cloned_details;

		latest = SS_ALLOC(struct ss_file);
		if (!latest)
			goto err;
		cloned_details = SS_ALLOC(struct ss_fcp_file_descr);
		if (!cloned_details) {
			SS_FREE(latest);
			goto err;
		}
		memcpy(latest, path_cursor, sizeof(*path_cursor));
		latest->fcp_file_descr =
			memcpy(cloned_details, latest->fcp_file_descr, sizeof(struct ss_fcp_file_descr));
		latest->fci = NULL;
		latest->fcp_decoded = NULL;
		latest->aid = NULL;
		latest->access = NULL;
		latest->list.previous = NULL;
		latest->list.next = NULL;
		ss_list_put(path_copy, &latest->list);
	}

	return 0;
err:
	/* Exit point for when out_path has been initialized but needs to be
	 * drained because it can not be allocated in full */
	ss_path_reset(path_copy);
	return -ENOMEM;
}

/*! Select a path by using the FIDs from another path.
 *  \param[out] path_out user provided memory to store the output path.
 *  \param[in] path path that shall be used as input for select.
 *  \returns 0 success, -EINVAL on failure
 *
 *  In the failure case, the output path can be incomplete, and is selected up
 *  to the point in the path where that was possible.
 *  */
int ss_fs_utils_path_select(struct ss_list *path_out, const struct ss_list *path)
{
	struct ss_file *path_cursor;
	int rc;

	/*! The output path must not contain any previously selected files.
	 *  it must be empty! (memoy leaks) */
	ss_list_init(path_out);

	SS_LIST_FOR_EACH(path, path_cursor, struct ss_file, list) {
		rc = ss_fs_select(path_out, path_cursor->fid);
		if (rc < 0) {
			return -EINVAL;
		}
	}

	return 0;
}

/*! Compare two path lists by checking whether both contain the same series of FIDs.
 *  \param[in] path_a first path to compare.
 *  \param[in] path_b second path to compare.
 *  \returns true when both path are equal, false otherwise. */
bool ss_fs_utils_path_equals(const struct ss_list *path_a, const struct ss_list *path_b)
{
	struct ss_file *path_cursor_a;
	struct ss_file *path_cursor_b;

	path_cursor_b = SS_LIST_GET_NEXT(path_b, struct ss_file, list);
	SS_LIST_FOR_EACH(path_a, path_cursor_a, struct ss_file, list) {
		if (path_cursor_b == SS_LIST_GET(path_b, struct ss_file, list))
			return false;
		if (path_cursor_a->fid != path_cursor_b->fid)
			return false;
		path_cursor_b = SS_LIST_GET_NEXT(&path_cursor_b->list, struct ss_file, list);
	}

	/* Check that there are no remaining items in path_b, this is the case
	 * when path_a is shorter then path_b. */
	if (path_cursor_b == SS_LIST_GET(path_b, struct ss_file, list))
		return true;

	return false;
}

/*! Get the selected DF from a path.
 *  \param[in] path path to search for the currently selected ADF.
 *  \returns DF on success, NULL on failure */
struct ss_file *ss_fs_utils_get_current_df_from_path(const struct ss_list *path)
{
	struct ss_file *selected_file;

	if (ss_list_empty(path))
		return NULL;

	selected_file = ss_get_file_from_path(path);
	if (!selected_file)
		return NULL;

	/* The tip of the path is already a DF (or ADF) */
	if (selected_file->fcp_file_descr->type == SS_FCP_DF_OR_ADF) {
		return selected_file;
	}

	/* If the tip ia an EF, we can simply select the parent file as the
	 * parent of an EF must always be a DF (or ADF) */
	return ss_get_parent_file_from_path(path);
}
