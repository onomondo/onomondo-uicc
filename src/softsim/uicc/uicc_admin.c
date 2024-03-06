/*
 * Copyright (c) 2024 Onomondo ApS. All rights reserved.
 * 
 * SPDX-License-Identifier: GPL-3.0-only 
 */

#include <errno.h>
#include <onomondo/softsim/log.h>
#include <onomondo/softsim/storage.h>
#include <onomondo/softsim/utils.h>
#include <onomondo/softsim/file.h>
#include "access.h"
#include "sw.h"
#include "btlv.h"
#include "uicc_lchan.h"
#include "fs.h"
#include "command.h"
#include "uicc_ins.h"
#include "uicc_admin.h"
#include "fcp.h"
#include "sfi.h"
#include "df_name.h"
#include "apdu.h"

/* In some dialects files are sometimes created with an FCP that contains a
 * shortended file descriptor. The number of records is then missing and it
 * is expected to calculate the number of records from the record length
 * and the file size. This function will do exactly that and will fix the
 * file descriptor so that it is spec compliant. */
static int fix_short_fd(struct ss_list *fcp_decoded_envelope)
{
	struct ss_buf *fd_fixed;
	struct ss_fcp_file_descr fd_decoded;
	struct ber_tlv_ie *fcp_ie_fd;
	struct ber_tlv_ie *fcp_ie_file_size;
	size_t file_size;
	uint8_t number_of_records;
	int rc;

	fcp_ie_fd = ss_btlv_get_ie_minlen(fcp_decoded_envelope, TS_102_221_IEI_FCP_FILE_DESCR, 2);
	if (!fcp_ie_fd) {
		SS_LOGP(SADMIN, LERROR, "invalid FCP: no file descriptor (%02X), cannot fix!\n",
			TS_102_221_IEI_FCP_FILE_DESCR);
		rc = -EINVAL;
	}

	fcp_ie_file_size = ss_btlv_get_ie_minlen(fcp_decoded_envelope, TS_102_221_IEI_FCP_FILE_SIZE, 1);
	if (!fcp_ie_file_size) {
		SS_LOGP(SADMIN, LERROR, "invalid FCP: short file descr -- no size IE (%02X), cannot fix!\n",
			TS_102_221_IEI_FCP_FILE_SIZE);
		rc = -EINVAL;
	}

	/* A file descriptor for a record oriented file is always 5 bytes long.
	 * the shortended format is 4 bytes long. (file descriptors for non
	 * record oriented files are 3 byte long. */
	if (fcp_ie_fd->value->len == 4) {
		/* extend the length of the file descriptor length */
		fd_fixed = ss_buf_alloc(5);
		memcpy(fd_fixed->data, fcp_ie_fd->value->data, fcp_ie_fd->value->len);
		fd_fixed->data[4] = 0x00;

		/* we should now be able to decode the file descriptor */
		rc = ss_fcp_dec_file_descr(&fd_decoded, fd_fixed);
		if (rc < 0) {
			ss_buf_free(fd_fixed);
			SS_LOGP(SADMIN, LERROR, "invalid FCP: short file descr -- cannot fix!\n");
			return -EINVAL;
		}

		/* make sure the file descriptor is indeed describing a record
		 * oriented file */
		if (fd_decoded.structure != SS_FCP_LINEAR_FIXED && fd_decoded.structure != SS_FCP_CYCLIC) {
			ss_buf_free(fd_fixed);
			SS_LOGP(SADMIN, LERROR, "invalid FCP: short file descr -- cannot fix!\n");
			return -EINVAL;
		}

		/* calculate missing number of records */
		file_size = ss_uint32_from_array(fcp_ie_file_size->value->data, fcp_ie_file_size->value->len);
		number_of_records = file_size / fd_decoded.record_len;
		if (number_of_records > 254)
			number_of_records = 254;
		else
			number_of_records = (uint8_t)number_of_records;
		fd_fixed->data[4] = number_of_records;

		/* replace fd in TLV structure */
		ss_buf_free(fcp_ie_fd->value);
		fcp_ie_fd->value = fd_fixed;

		SS_LOGP(SADMIN, LERROR, "invalid FCP: short file descr -- fixed (%s)\n",
			ss_hexdump(fcp_ie_fd->value->data, fcp_ie_fd->value->len));
		return 0;
	}

	SS_LOGP(SADMIN, LERROR, "invalid FCP: short file descr -- cannot fix!\n");
	return -EINVAL;
}

/* Validate the FCP, make sure mandatory information elements are present.
 *
 * This calls out to \ref fix_short_fd to populate missing information, see
 * there.
 *
 * This returns as late as possible to gather as much debug output as
 * practical, as long as the basic structure is present.
 * */
static int validate_fcp(struct ss_list *fcp_decoded_envelope)
{
	int rc = 0;
	struct ber_tlv_ie *fcp_ie;
	struct ss_fcp_file_descr file_descr;
	if (!fcp_decoded_envelope) {
		SS_LOGP(SADMIN, LERROR, "invalid FCP: no data\n");
		return -EINVAL;
	}

	fcp_ie = ss_btlv_get_ie_minlen(fcp_decoded_envelope, TS_102_221_IEI_FCP_FILE_DESCR, 2);
	if (!fcp_ie) {
		SS_LOGP(SADMIN, LERROR, "invalid FCP: no file descriptor (%02X)\n", TS_102_221_IEI_FCP_FILE_DESCR);
		rc = -EINVAL;
	} else {
		rc = ss_fcp_dec_file_descr(&file_descr, fcp_ie->value);
		if (rc < 0) {
			SS_LOGP(SADMIN, LERROR, "invalid FCP: unable to decode file descriptor -- trying to fix (%s)\n",
				ss_hexdump(fcp_ie->value->data, fcp_ie->value->len));
			rc = fix_short_fd(fcp_decoded_envelope);
			if (rc < 0)
				rc = -EINVAL;
			else
				rc = 0;
		}
	}

	fcp_ie = ss_btlv_get_ie_minlen(fcp_decoded_envelope, TS_102_221_IEI_FCP_FILE_ID, 2);
	if (!fcp_ie) {
		SS_LOGP(SADMIN, LERROR, "invalid FCP: no file identifier (%02X)\n", TS_102_221_IEI_FCP_FILE_ID);
		rc = -EINVAL;
	}

	fcp_ie = ss_btlv_get_ie_minlen(fcp_decoded_envelope, TS_102_221_IEI_FCP_LIFE_CYCLE_ST, 1);
	if (!fcp_ie) {
		SS_LOGP(SADMIN, LERROR, "invalid FCP: no file lifecycle status byte (%02X)\n",
			TS_102_221_IEI_FCP_LIFE_CYCLE_ST);
		rc = -EINVAL;
	}

	/* we don't support compact or expanded security attributes */
	if (ss_btlv_get_ie(fcp_decoded_envelope, TS_102_221_IEI_FCP_SEC_ATTR_8C) ||
	    ss_btlv_get_ie(fcp_decoded_envelope, TS_102_221_IEI_FCP_SEC_ATTR_AB)) {
		SS_LOGP(SADMIN, LERROR,
			"invalid FCP: compact or expanded security rules not supported (%02X || %02X)\n",
			TS_102_221_IEI_FCP_SEC_ATTR_8C, TS_102_221_IEI_FCP_SEC_ATTR_AB);
		rc = -EINVAL;
	}

	/* we must have referenced security attributes */
	fcp_ie = ss_btlv_get_ie(fcp_decoded_envelope, TS_102_221_IEI_FCP_SEC_ATTR_8B);
	if (!fcp_ie) {
		SS_LOGP(SADMIN, LERROR, "invalid FCP: no referenced security attributes (%02X)\n",
			TS_102_221_IEI_FCP_SEC_ATTR_8B);
		rc = -EINVAL;
	}

	switch (file_descr.type) {
	case SS_FCP_WORKING_EF:
		fcp_ie = ss_btlv_get_ie_minlen(fcp_decoded_envelope, TS_102_221_IEI_FCP_FILE_SIZE, 1);
		if (!fcp_ie) {
			SS_LOGP(SADMIN, LERROR, "invalid FCP: no size (%02X)\n", TS_102_221_IEI_FCP_FILE_SIZE);
			rc = -EINVAL;
		}

		switch (file_descr.structure) {
		case SS_FCP_TRANSPARENT:
		case SS_FCP_LINEAR_FIXED:
			break;
		default:
			SS_LOGP(SADMIN, LERROR, "invalid FCP: unsupported file struture (%u)\n", file_descr.structure);
			rc = -EINVAL;
		}

		break;
	case SS_FCP_DF_OR_ADF:
		fcp_ie = ss_btlv_get_ie(fcp_decoded_envelope, TS_102_221_IEI_FCP_PIN_STAT_TMPL);
		if (fcp_ie) {
			SS_LOGP(SADMIN, LERROR, "FCP needlessly contains pin status template (%02X)\n",
				TS_102_221_IEI_FCP_PIN_STAT_TMPL);
			rc = -EINVAL;
		}

		break;
	default:
		SS_LOGP(SADMIN, LERROR, "invalid FCP: unsupported file type (%u)\n", file_descr.type);
		rc = -EINVAL;
	}

	return rc;
}

/** If an EF is currently selected, select the enclosing DF
 *
 * This is necessary in operations that generally work on DFs but can also be
 * performed when there is an EF selected, such as CREATE FILE or DELETE FILE.
 *
 * The rewinding could be deferred to performing the operation if not for
 * access control: That check must happen with the right kind of selected file
 * for its scope, for otherwise the wrong file's access control would be
 * checked, which on top of it has completely different meaning for its bits.
 *
 * (There is no strong need to defer rewinding, though: commands may alter the
 * selected path before failing, and the path is restored automatically).
 */
static void rewind_to_df(struct ss_apdu *apdu)
{
	struct ss_file *selected_file = ss_get_file_from_path(&apdu->lchan->fs_path);
	if (!selected_file)
		return;

	if (selected_file->fcp_file_descr->type != SS_FCP_DF_OR_ADF) {
		ss_fs_select_parent(&apdu->lchan->fs_path);
	}
}

/*! CREATE FILE (TS 102 222 Section 6.3) */
int ss_uicc_admin_cmd_create_file(struct ss_apdu *apdu)
{
	struct ss_list *fcp_decoded;
	struct ss_buf *fcp_reencoded;
	struct ber_tlv_ie *fcp_fid_ie;
	struct ber_tlv_ie *fcp_file_descr_ie;
	struct ss_fcp_file_descr file_descr;
	struct ber_tlv_ie *fcp_tmpl_ie;
	uint32_t fid;
	int rc;
	struct ss_file *selected_file;

	/* Reset current record for record oriented files. */
	apdu->lchan->current_record = 0;

	if (apdu->hdr.p1 != 0 || apdu->hdr.p2 != 0)
		return SS_SW_ERR_CHECKING_WRONG_P1_P2;

	fcp_decoded = ss_btlv_decode(apdu->cmd, apdu->lc, ss_fcp_get_descr());
	if (!fcp_decoded) {
		SS_LOGP(SADMIN, LERROR, "unable to decode FCP template -- cannot create file\n");
		goto err_inval;
	}

	ss_btlv_dump(fcp_decoded, 0, SFS, LINFO);

	/* Extract fid */
	fcp_tmpl_ie = ss_btlv_get_ie(fcp_decoded, TS_102_221_IEI_FCP_TMPL);
	if (!fcp_tmpl_ie) {
		SS_LOGP(SADMIN, LERROR, "missing FCP template -- cannot create file\n");
		goto err_inval;
	}

	rc = validate_fcp(fcp_tmpl_ie->nested);
	if (rc < 0) {
		SS_LOGP(SADMIN, LERROR, "invalid or incomplete FCP -- cannot create file\n");
		goto err_inval;
	}

	fcp_fid_ie = ss_btlv_get_ie_minlen(fcp_tmpl_ie->nested, TS_102_221_IEI_FCP_FILE_ID, 2);
	if (!fcp_fid_ie) {
		SS_LOGP(SADMIN, LERROR, "unable to decode FCP template -- cannot create file\n");
		goto err_inval;
	}
	fid = ss_uint32_from_array(fcp_fid_ie->value->data, fcp_fid_ie->value->len);

	/* Extract description to determine type (EF or DF) to decide which
	 * access rules to apply */
	/* FIXME #57: After FID decoding, this is the second step that is performed
	 * twice, here and in ss_fs_create; consider refactoring. */
	fcp_file_descr_ie = ss_btlv_get_ie_minlen(fcp_tmpl_ie->nested, TS_102_221_IEI_FCP_FILE_DESCR, 2);
	if (!fcp_file_descr_ie) {
		SS_LOGP(SADMIN, LERROR, "missing FILE DESCR template -- cannot create file\n");
		goto err_inval;
	}
	if (ss_fcp_dec_file_descr(&file_descr, fcp_file_descr_ie->value) < 0) {
		SS_LOGP(SADMIN, LERROR, "malformed FILE DESCR template -- cannot create file\n");
		goto err_inval;
	}

	SS_LOGP(SADMIN, LDEBUG, "file descriptor:\n");
	ss_fcp_dump_file_descr(&file_descr, 1, SFILE, LDEBUG);

	rewind_to_df(apdu);

	if (!ss_access_check_command(apdu, file_descr.type == SS_FCP_DF_OR_ADF ? SS_ACCESS_INTENTION_DF_CREATE_DF :
										 SS_ACCESS_INTENTION_DF_CREATE_EF)) {
		ss_btlv_free(fcp_decoded);
		return SS_SW_ERR_CMD_NOT_ALLOWED_NO_INFO;
	}

	/* FIXME #58: check we don't already have a file with that FID or SFID */

	fcp_reencoded = ss_btlv_encode_to_ss_buf(fcp_decoded);
	if (!fcp_reencoded) {
		SS_LOGP(SADMIN, LERROR, "unable to reencode FCP -- cannot create file\n");
		goto err_inval;
	}

	rc = ss_fs_create(&apdu->lchan->fs_path, fcp_reencoded->data, fcp_reencoded->len);
	ss_btlv_free(fcp_decoded);
	ss_buf_free(fcp_reencoded);

	if (rc < 0)
		return SS_SW_ERR_WRONG_PARAM_FUNCTION_NOT_SUPPORTED;

	/* Select the file we just created so that the file definition is
	 * reloaded and properly parsed. */
	rc = ss_fs_select(&apdu->lchan->fs_path, fid);
	if (rc < 0) {
		ss_storage_delete(&apdu->lchan->fs_path);
		return SS_SW_ERR_EXEC_MEMORY_PROBLEM;
	}

	/* Create lookup files, register FID. */
	selected_file = ss_get_file_from_path(&apdu->lchan->fs_path);
	if (selected_file->fcp_file_descr->type == SS_FCP_DF_OR_ADF) {
		rc = ss_sfi_create(&apdu->lchan->fs_path);
		rc += ss_df_name_update(&apdu->lchan->fs_path);
	} else {
		rc = ss_sfi_update(&apdu->lchan->fs_path);
	}
	if (rc < 0) {
		ss_storage_delete(&apdu->lchan->fs_path);
		return SS_SW_ERR_EXEC_MEMORY_PROBLEM;
	}

	return 0;

err_inval:
	ss_btlv_free(fcp_decoded);

	return SS_SW_ERR_WRONG_PARAM_INCORRECT_DATA;
}

/*! DELETE FILE (TS 102 222 Section 6.4) */
int ss_uicc_admin_cmd_delete_file(struct ss_apdu *apdu)
{
	uint32_t fid;
	int rc;

	if (apdu->hdr.p1 != 0 || apdu->hdr.p2 != 0)
		return SS_SW_ERR_CHECKING_WRONG_P1_P2;

	if (apdu->lc != 2)
		return SS_SW_ERR_CHECKING_WRONG_LENGTH;

	fid = ss_uint32_from_array(apdu->cmd, apdu->lc);

	rewind_to_df(apdu);

	/* Not checking for SS_ACCESS_INTENTION_DF_DELETE_FILE (child) on the
	 * container as per TS 102 222 V6.6.0 6.4.1: 'The access condition "DELETE
	 * FILE (child)" shall not be used.' */

	rc = ss_fs_select(&apdu->lchan->fs_path, fid);
	if (rc < 0)
		return SS_SW_ERR_WRONG_PARAM_FILE_NOT_FOUND;

	if (!ss_access_check_command(apdu, SS_ACCESS_INTENTION_EFDF_DELETE_FILE_SELF))
		return SS_SW_ERR_CMD_NOT_ALLOWED_NO_INFO;

	rc = ss_storage_delete(&apdu->lchan->fs_path);
	if (rc < 0)
		return SS_SW_ERR_EXEC_MEMORY_PROBLEM;

	/* make sure that the file we just deleted is no longer selected. */
	ss_fs_select_parent(&apdu->lchan->fs_path);

	return 0;
}

/*! ACTIVATE FILE (TS 102 221 Section 11.1.15)
 *
 * This is implemented only to the extent to which it is necessary to bring the
 * MF from the personalization into the operational phase.
 * */
int ss_uicc_admin_cmd_activate_file(struct ss_apdu *apdu)
{
	uint32_t fid;
	int rc;

	/* P1 would have allowed values, but they are not implemented here */
	if (apdu->hdr.p1 != 0 || apdu->hdr.p2 != 0)
		return SS_SW_ERR_CHECKING_WRONG_P1_P2;

	/* Different lengths would be allowed, but are not implemented here */
	if (apdu->lc != 2)
		return SS_SW_ERR_CHECKING_WRONG_LENGTH;

	fid = ss_uint32_from_array(apdu->cmd, apdu->lc);

	rc = ss_fs_select(&apdu->lchan->fs_path, fid);
	if (rc < 0)
		return SS_SW_ERR_WRONG_PARAM_FILE_NOT_FOUND;

	/* Practically, this will likely not be set -- but in personalization mode it
	 * can be set anyway. */
	if (!ss_access_check_command(apdu, SS_ACCESS_INTENTION_EFDF_ACTIVATE_FILE))
		return SS_SW_ERR_CMD_NOT_ALLOWED_NO_INFO;

	struct ber_tlv_ie *fcp_decoded_lifecycle;
	struct ss_file *selected_file = ss_get_file_from_path(&apdu->lchan->fs_path);
	fcp_decoded_lifecycle = ss_btlv_get_ie_minlen(selected_file->fcp_decoded, TS_102_221_IEI_FCP_LIFE_CYCLE_ST, 1);
	fcp_decoded_lifecycle->value->data[0] = 0x05;

	/* Store encoded FCP again */
	rc = ss_fcp_reencode(selected_file);
	if (rc < 0)
		return SS_SW_ERR_EXEC_MEMORY_PROBLEM;

	rc = ss_storage_update_def(&apdu->lchan->fs_path);
	if (rc < 0)
		return SS_SW_ERR_EXEC_MEMORY_PROBLEM;

	return 0;
}

/*! TODO #63: implemet the following missing commands:
 *  - TERMINATE DF (TS 102 222 Section 6.7)
 *  - TERMINATE EF (TS 102 222 Section 6.8)
 *  - TERMINATE CARD USAGE (TS 102 222 Section 6.9)
 *  - RESIZE FILE (TS 102 222 Section 6.10) */
