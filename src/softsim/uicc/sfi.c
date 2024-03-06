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

#define SFI_FID 0x5F100001

/*! Create an internal record to manage SFI to FID translation.
 *  \param[in] path directory where the file shall be created.
 *  \returns 0 success, -EINVAL on failure. */
int ss_sfi_create(const struct ss_list *path)
{
	return ss_fs_utils_create_record_file(path, SFI_FID, 2, 0x1f);
}

/*! Register a FID in the internal SFI to FID translation file.
 *  \param[in] path path to the file that shall be registered.
 *  \returns 0 success, -EINVAL on failure. */
int ss_sfi_update(const struct ss_list *path)
{
	struct ss_list path_copy;
	struct ss_file *file;
	struct ber_tlv_ie *fcp_sfi_ie;
	struct ber_tlv_ie *fcp_fid_ie;
	int rc;
	uint8_t sfi;

	/*! NOTE: This function will always search in the currently selected DF
	 *  or ADF for the SFI to FID translation file */

	/* ensure we won't work on an uninitialized list */
	ss_list_init(&path_copy);

	file = ss_get_file_from_path(path);

	/* get FID */
	fcp_fid_ie = ss_btlv_get_ie_minlen(file->fcp_decoded, TS_102_221_IEI_FCP_FILE_ID, 2);
	if (!fcp_fid_ie)
		return -EINVAL;

	/* get SFI */
	fcp_sfi_ie = ss_btlv_get_ie(file->fcp_decoded, TS_102_221_IEI_FCP_SHORT_FILE_ID);
	if (!fcp_sfi_ie) {
		/* See also ETSI TS 102 221 11.1.1.4.8 */
		sfi = fcp_fid_ie->value->data[1] & 0x1f;
	} else {
		if (fcp_sfi_ie->value->len == 0) {
			/* Files without SFI are accepted */
			rc = 0;
			goto leave;
		} else {
			sfi = fcp_sfi_ie->value->data[0] >> 3;
		}
	}

	/* select SFI file and update record nr. SFI with FID */
	rc = ss_fs_utils_path_clone(&path_copy, path);
	if (rc < 0)
		return -EINVAL;
	rc = ss_fs_select(&path_copy, SFI_FID);
	if (rc < 0) {
		SS_LOGP(SSFI, LERROR, "cannot register SFI=%02x, unable to select lookup file %s\n", sfi,
			ss_fs_utils_dump_path(&path_copy));
		rc = -EINVAL;
		goto leave;
	}
	rc = ss_fs_write_file_record(&path_copy, sfi, fcp_fid_ie->value->data, fcp_fid_ie->value->len);
	if (rc < 0) {
		rc = -EINVAL;
		goto leave;
	}

	SS_LOGP(SSFI, LDEBUG, "registered SFI=%02x for FID=%s in lookup file %s\n", sfi,
		ss_hexdump(fcp_fid_ie->value->data, fcp_fid_ie->value->len), ss_fs_utils_dump_path(&path_copy));
	rc = 0;
leave:
	ss_path_reset(&path_copy);
	return rc;
}

/*! Resolve an SFI to FID by quering the SFI to FID translation file.
 *  \param[in] path path to the current directory.
 *  \param[in] sfi SFI to look for.
 *  \returns 0 success, -EINVAL on failure. */
int ss_sfi_resolve(const struct ss_list *path, uint8_t sfi)
{
	struct ss_list path_copy;
	int rc;
	struct ss_buf *fid = NULL;

	/*! NOTE: This function will always search in the currently selected DF
	 *  or ADF for the SFI to FID translation file */

	/* ensure we won't work on an uninitialized list */
	ss_list_init(&path_copy);

	/* read full FID from SFI file */
	rc = ss_fs_utils_path_clone(&path_copy, path);
	if (rc < 0)
		return -EINVAL;
	rc = ss_fs_select(&path_copy, SFI_FID);
	if (rc < 0) {
		SS_LOGP(SSFI, LERROR, "cannot resolve SFI=%02x, unable to select lookup file %s\n", sfi,
			ss_fs_utils_dump_path(&path_copy));
		rc = -EINVAL;
		goto leave;
	}
	fid = ss_fs_read_file_record(&path_copy, sfi);
	if (!fid) {
		SS_LOGP(SSFI, LERROR, "unable to resolve SFI=%02x to FID - lookup file %s is not readable\n", sfi,
			ss_fs_utils_dump_path(&path_copy));
		rc = -EINVAL;
		goto leave;
	}

	rc = ss_uint32_from_array(fid->data, fid->len);
	SS_LOGP(SSFI, LDEBUG, "resolved SFI=%02x to FID=%04x using lookup file %s\n", sfi, rc,
		ss_fs_utils_dump_path(&path_copy));
leave:
	ss_path_reset(&path_copy);
	return rc;
}
