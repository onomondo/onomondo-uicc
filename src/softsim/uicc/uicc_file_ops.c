/*
 * Copyright (c) 2024 Onomondo ApS. All rights reserved.
 *
 * SPDX-License-Identifier: GPL-3.0-only
 *
 * Author: Philipp Maier
 */

#include <stdbool.h>
#include <string.h>
#include <errno.h>
#include <onomondo/softsim/log.h>
#include <onomondo/softsim/storage.h>
#include <onomondo/softsim/file.h>
#include <onomondo/softsim/utils.h>
#include "access.h"
#include "sw.h"
#include "fs.h"
#include "fs_chg.h"
#include "fs_utils.h"
#include "uicc_file_ops.h"
#include "uicc_lchan.h"
#include "fcp.h"
#include "sfi.h"
#include "df_name.h"
#include "apdu.h"
#include "btlv.h"
#include "uicc_pin.h"
#include "context.h"

/* The reserved FID '7FFF' can be used as a FID for the ADF
 * of the current active application on a given logical channel. */
#define FID_CURRENT_APP 0x7fff

/* Record a file change in the context file list. This data can be used to
 * inform the terminal about file changes at a later point
 * (e.g. REFRESH after RFM operation) */
static void record_file_change(struct ss_apdu *apdu)
{
	int rc = 0;

	if (apdu->ctx->fs_chg_record)
		rc = ss_fs_chg_add(apdu->ctx->fs_chg_filelist, &apdu->lchan->fs_path);
	if (rc < 0)
		SS_LOGP(SFILE, LERROR, "file change not recorded!\n");
}

/* Generate the FCP string as it is returned by the card to the outside world.
 * This is essentially the FCP string that is read from the definition files
 * but with additional IEs that reflect the current card state (PIN status) */
static int fcp_reencode_full(struct ss_file *selected_file, char *command_name)
{
	struct ber_tlv_ie *pin_stat_templ_ie;
	struct ss_buf *pin_stat_templ;
	int rc;

	/* Get information element (IE) for tag C6, PIN Status Template */
	pin_stat_templ_ie = ss_btlv_get_ie(selected_file->fcp_decoded, TS_102_221_IEI_FCP_PIN_STAT_TMPL);

	/* PIN Status Template (tag C6) should only be added for DF/ADF files, not EF files.
	 * See ETSI TS 102.221, Section 11.1.1.3.2, Table 11.4 - "Response for an EF with FCP template" */
	if (!pin_stat_templ_ie && selected_file->fcp_file_descr->type == SS_FCP_DF_OR_ADF) {
		pin_stat_templ = ss_uicc_pin_gen_pst_do();
		if (!pin_stat_templ) {
			SS_LOGP(SFILE, LDEBUG, "%s failed, could not generate PIN status template.\n", command_name);
			return -EINVAL;
		}
		pin_stat_templ_ie = ss_btlv_new_ie(selected_file->fcp_decoded, "pin_status_template_do",
						   TS_102_221_IEI_FCP_PIN_STAT_TMPL, pin_stat_templ->len,
						   pin_stat_templ->data);
		ss_buf_free(pin_stat_templ);
		/* Note: There is no need to free the IE that we have just
		 * created. Since it is now liked into the TLV tree it will
		 * be freed along with all other elements in the tree when the
		 * file struct is freed. Contrary to the IE, the pin_stat_templ,
		 * we use as input for ss_btlv_new_ie(), must be freed. */
		goto reencode;
	} else if (pin_stat_templ_ie) {
		/* The PIN Status Template should not be present on EF files.
		 * If we encounter a template on a non-DF/ADF file, log it at error 
		 * level for later investigation allow the template to be updated. */
		if (selected_file->fcp_file_descr->type != SS_FCP_DF_OR_ADF) {
			SS_LOGP(SFILE, LERROR,
				"%s: PIN Status Template (C6) present on non-DF/ADF file (fid=%04x). Updating anyway.\n",
				command_name, selected_file->fid);
		}

		/* No further checks performed if template already exists */
		rc = ss_uicc_pin_update_pst_do(pin_stat_templ_ie->value);
		if (rc < 0) {
			SS_LOGP(SFILE, LDEBUG, "%s failed, could not update PIN status template.\n", command_name);
			return -EINVAL;
		}
		goto reencode;
	}

reencode:
	rc = ss_fcp_reencode(selected_file);
	if (rc < 0) {
		SS_LOGP(SFILE, LDEBUG, "%s failed, unable to re-encode FCP data.\n", command_name);
		return -EINVAL;
	}

	return 0;
}

/*! STATUS (TS 102 221 Section 11.1.2) */
int ss_uicc_file_ops_cmd_status(struct ss_apdu *apdu)
{
	struct ss_file *current_df;
	struct ss_file *active_adf;
	struct ber_tlv_ie *df_name;
	int rc;

	switch (apdu->hdr.p1) {
	case 0x00: /* no indication */
	case 0x01: /* Current application is initialized in the terminal */
	case 0x02: /* The terminal will initiate the termination of the current application */
		break;
	default:
		return SS_SW_ERR_CHECKING_WRONG_P1_P2;
	}

	switch (apdu->hdr.p2) {
	case 0x00:
		current_df = ss_fs_utils_get_current_df_from_path(&apdu->lchan->fs_path);
		if (!current_df)
			return SS_SW_ERR_CMD_NOT_ALLOWED_NO_EF_SELECTED;

		rc = fcp_reencode_full(current_df, "status");
		if (rc < 0) {
			SS_LOGP(SFILE, LDEBUG, "status failed, unable to re-encode FCP data.\n");
			return SS_SW_ERR_EXEC_MEMORY_PROBLEM;
		}

		/* Per TS 102 221, Le=0 (Case 2 short), Le=256 (0x00), or Le=65535
		 * (extended) means "return all available data". Also accept Le=0
		 * for Case 1 APDUs (no Le byte) as some modems like nRF91 use this. */
		if (apdu->le != 0 && apdu->le != 256 && apdu->le != 65535 &&
		    apdu->le != current_df->fci->len) {
			SS_LOGP(SFILE, LDEBUG,
				"Terminal requested status expecting length %u, returning actual FCI length %u\n",
				apdu->le, (unsigned)current_df->fci->len);
			apdu->le = 0;
			return 0x6c00 | (current_df->fci->len);
		}

		memcpy(apdu->rsp, current_df->fci->data, current_df->fci->len);
		apdu->rsp_len = current_df->fci->len;
		break;
	case 0x01:
		active_adf = ss_get_file_from_path(&apdu->lchan->adf_path);
		if (!active_adf)
			return SS_SW_ERR_CMD_NOT_ALLOWED_NO_EF_SELECTED;

		df_name = ss_btlv_get_ie(active_adf->fcp_decoded, TS_102_221_IEI_FCP_DF_NAME);
		if (df_name) {
			apdu->rsp[0] = TS_102_221_IEI_FCP_DF_NAME;
			apdu->rsp[1] = df_name->value->len;
			memcpy(apdu->rsp + 2, df_name->value->data, df_name->value->len);
			apdu->rsp_len = df_name->value->len + 2;
			return 0;
		}

		return SS_SW_ERR_CMD_NOT_ALLOWED_NO_EF_SELECTED;
	case 0x0c:
		/* no data is returned */
		break;
	default:
		return SS_SW_ERR_CHECKING_WRONG_P1_P2;
	}

	return 0;
}

/* Calculate the read/write offset for a transparent file */
static size_t calc_read_write_offset(struct ss_apdu *apdu)
{
	size_t result = apdu->hdr.p2;

	/* See also ETSI TS 102 221, table 11.10 */
	if ((apdu->hdr.p1 & 0x80) == 0)
		result |= (apdu->hdr.p1 << 8);

	return result;
}

/* Make sure that it is valid to operate with READ BINARY and UPDATE BINARY on
 * the specified file. */
static int verify_file_struct(struct ss_apdu *apdu, struct ss_file *file, bool record_oriented)
{
	if (!file) {
		apdu->le = 0;
		return SS_SW_ERR_CMD_NOT_ALLOWED_NO_EF_SELECTED;
	}

	if (file->fcp_file_descr->type != SS_FCP_WORKING_EF) {
		apdu->le = 0;
		return SS_SW_ERR_CMD_NOT_ALLOWED_INCOMP_FILE_STRUCT;
	}

	if (record_oriented) {
		if (file->fcp_file_descr->structure != SS_FCP_LINEAR_FIXED &&
		    file->fcp_file_descr->structure != SS_FCP_CYCLIC) {
			apdu->le = 0;
			return SS_SW_ERR_CMD_NOT_ALLOWED_INCOMP_FILE_STRUCT;
		}
	} else {
		if (file->fcp_file_descr->structure != SS_FCP_TRANSPARENT) {
			apdu->le = 0;
			return SS_SW_ERR_CMD_NOT_ALLOWED_INCOMP_FILE_STRUCT;
		}
	}

	return 0;
}

/* Select a file by SFI
 *
 * This is usually used through \ref select_by_sfi_binarystyle or similar.
 *
 * \param[inout] apdu Current command, including lchan
 * \param[in] sfi SFI dissected from the command's P1 / P2.
 *
 * On error, the ADPU is configured for immediate error return.
 *
 * \return 0 if successful, or a status word to immediately return
 * */
static int select_by_sfi(struct ss_apdu *apdu, uint8_t sfi)
{
	int rc = ss_sfi_resolve(&apdu->lchan->fs_path, sfi);
	if (rc < 0) {
		apdu->le = 0;
		return SS_SW_ERR_CMD_NOT_ALLOWED_NO_EF_SELECTED;
	}
	ss_fs_select(&apdu->lchan->fs_path, rc);
	ss_access_populate(apdu->lchan);

	/* Reset current record for record oriented files. */
	apdu->lchan->current_record = 0;

	return 0;
}

/* Select a file by SFI if present in P1
 *
 * This is applicable for READ BINARY and similar commands that follow IEC-7816
 * section 7.2.2, in which bit 1 of INS is 0.
 *
 * This acts like \ref select_by_sfi, but also return 0 immediately if no SFI
 * is indicated.
 */
static int select_by_sfi_binarystyle(struct ss_apdu *apdu)
{
	if (apdu->hdr.p1 & 0x80)
		return select_by_sfi(apdu, apdu->hdr.p1 & 0x1f);
	return 0;
}

/* Select a file by SFI if present in P2
 *
 * This is applicable for READ RECORD and similar commands that follow IEC-7816
 * table 49.
 *
 * This acts like \ref select_by_sfi, but also return 0 immediately if no SFI
 * is indicated.
 */
static int select_by_sfi_recordstyle(struct ss_apdu *apdu)
{
	if (apdu->hdr.p2 & 0xf8)
		return select_by_sfi(apdu, apdu->hdr.p2 >> 3);
	return 0;
}

/*! READ BINARY (TS 102 221 Section 11.1.3) */
int ss_uicc_file_ops_cmd_read_binary(struct ss_apdu *apdu)
{
	struct ss_file *selected_file;
	size_t file_len;
	struct ss_buf *buf;
	size_t offset;
	int rc;
	size_t read_len = apdu->le;

	rc = select_by_sfi_binarystyle(apdu);
	if (rc != 0)
		return rc;

	/* Get currently selected file and verify that the structure is suitable
	 * to carry out the intended file operation. */
	selected_file = ss_get_file_from_path(&apdu->lchan->fs_path);
	rc = verify_file_struct(apdu, selected_file, false);
	if (rc != 0)
		return rc;

	if (!ss_access_check_command(apdu, SS_ACCESS_INTENTION_EF_READ)) {
		apdu->le = 0;
		return SS_SW_ERR_CMD_NOT_ALLOWED_NO_INFO;
	}

	/* FIXME #60: check invalidated / terminated */

	offset = calc_read_write_offset(apdu);
	file_len = ss_storage_get_file_len(&apdu->lchan->fs_path);
	if (offset > file_len) {
		apdu->le = 0;
		return SS_SW_ERR_CHECKING_WRONG_P1_P2;
	}
	if (offset + apdu->le > file_len) {
		/* return actual length */
		apdu->le = 0;
		return 0x6c00 | (file_len - offset);
	}

	if (read_len == 0) {
		read_len = file_len - offset;
	}

	buf = ss_storage_read_file(&apdu->lchan->fs_path, offset, read_len);
	if (!buf)
		return SS_SW_ERR_WRONG_PARAM_ENOMEM;

	memcpy(apdu->rsp, buf->data, buf->len);
	apdu->rsp_len = buf->len;
	ss_buf_free(buf);

	return 0;
}

/*! UPDATE BINARY (TS 102 221 Section 11.1.4) */
int ss_uicc_file_ops_cmd_update_binary(struct ss_apdu *apdu)
{
	struct ss_file *selected_file;
	size_t file_len;
	size_t offset;
	int rc;

	rc = select_by_sfi_binarystyle(apdu);
	if (rc != 0)
		return rc;

	/* Get currently selected file and verify that the structure is suitable
	 * to carry out the intended file operation. */
	selected_file = ss_get_file_from_path(&apdu->lchan->fs_path);
	rc = verify_file_struct(apdu, selected_file, false);
	if (rc != 0)
		return rc;

	if (!ss_access_check_command(apdu, SS_ACCESS_INTENTION_EF_UPDATE_ERASE)) {
		apdu->le = 0;
		return SS_SW_ERR_CMD_NOT_ALLOWED_NO_INFO;
	}

	/* FIXME #60: check invalidated / terminated */

	offset = calc_read_write_offset(apdu);
	file_len = ss_storage_get_file_len(&apdu->lchan->fs_path);
	if (offset > file_len) {
		apdu->le = 0;
		return SS_SW_ERR_CHECKING_WRONG_P1_P2;
	}
	if (offset + apdu->lc > file_len)
		return SS_SW_ERR_CHECKING_WRONG_LENGTH;

	rc = ss_storage_write_file(&apdu->lchan->fs_path, apdu->cmd, offset, apdu->lc);
	if (rc < 0)
		return SS_SW_ERR_WRONG_PARAM_ENOMEM;

	record_file_change(apdu);

	return 0;
}

/* Calculate the record number depending on the parameters P1, P2 and the
 * current record pointer. */
static int calc_record_number(uint8_t *record_number_new, uint8_t *record_number, struct ss_apdu *apdu,
			      struct ss_file *selected_file)
{
	uint8_t n_records = selected_file->fcp_file_descr->number_of_records;

	/* Determine record number */
	switch (apdu->hdr.p2 & 0x07) {
	case 0x02:
		*record_number = apdu->lchan->current_record;

		/* Only linear cyclic files may wrap around, see also ETSI TS 102 221,
		   section 11.1.5.1 */
		if (*record_number == 0) {
			/* See also ETSI TS 102 221, section 11.1.6.1, parapgraph "PREVIOUS" */
			*record_number = 1;
		} else if (*record_number == n_records) {
			if (selected_file->fcp_file_descr->structure == SS_FCP_CYCLIC)
				*record_number = 1;
			else {
				SS_LOGP(SFILE, LERROR,
					"last record (%u) of %u records, but not a cyclic file (%04x), cannot wrap around\n",
					*record_number, n_records, selected_file->fid);
				return SS_SW_ERR_WRONG_PARAM_RECORD_NOT_FOUND;
			}
		} else
			(*record_number)++;

		*record_number_new = *record_number;
		break;
	case 0x03:
		*record_number = apdu->lchan->current_record;

		/* See comment above */
		if (*record_number == 0) {
			/* See also ETSI TS 102 221, section 11.1.6.1, parapgraph "PREVIOUS" */
			*record_number = n_records;
		} else if (*record_number == 1) {
			if (selected_file->fcp_file_descr->structure == SS_FCP_CYCLIC)
				*record_number = n_records;
			else {
				SS_LOGP(SFILE, LERROR,
					"first record (%u) of %u records, but not a cyclic file (%04x), cannot wrap around\n",
					*record_number, n_records, selected_file->fid);
				return SS_SW_ERR_WRONG_PARAM_RECORD_NOT_FOUND;
			}
		} else
			(*record_number)--;

		*record_number_new = *record_number;
		break;
	case 0x04:
		*record_number = apdu->hdr.p1;

		/* Keep record number as it is */
		*record_number_new = apdu->lchan->current_record;
		break;
	default:
		return SS_SW_ERR_CHECKING_WRONG_P1_P2;
	}

	return 0;
}

/*! READ RECORD (TS 102 221 Section 11.1.5) */
int ss_uicc_file_ops_cmd_read_record(struct ss_apdu *apdu)
{
	struct ss_file *selected_file;
	struct ss_buf *buf;
	uint8_t record_number;
	uint8_t record_number_new;
	int rc;

	rc = select_by_sfi_recordstyle(apdu);
	if (rc != 0)
		return rc;

	/* Get currently selected file and verify that the structure is suitable
	 * to carry out the intended file operation. */
	selected_file = ss_get_file_from_path(&apdu->lchan->fs_path);
	rc = verify_file_struct(apdu, selected_file, true);
	if (rc != 0) {
		apdu->le = 0;
		return rc;
	}

	if (!ss_access_check_command(apdu, SS_ACCESS_INTENTION_EF_READ)) {
		apdu->le = 0;
		return SS_SW_ERR_CMD_NOT_ALLOWED_NO_INFO;
	}

	/* FIXME #60: check invalidated / terminated */

	/* Determine record number */
	rc = calc_record_number(&record_number_new, &record_number, apdu, selected_file);
	if (rc != 0)
		return rc;

	if (apdu->le != selected_file->fcp_file_descr->record_len) {
		/* return actual length */
		apdu->le = 0;
		return 0x6c00 | selected_file->fcp_file_descr->record_len;
	}

	buf = ss_fs_read_file_record(&apdu->lchan->fs_path, record_number);
	if (!buf)
		return SS_SW_ERR_WRONG_PARAM_ENOMEM;

	memcpy(apdu->rsp, buf->data, buf->len);
	apdu->rsp_len = buf->len;
	ss_buf_free(buf);

	/* Everything went successful, update record pointer */
	apdu->lchan->current_record = record_number_new;
	return 0;
}

/*! UPDATE RECORD (TS 102 221 Section 11.1.6) */
int ss_uicc_file_ops_cmd_update_record(struct ss_apdu *apdu)
{
	struct ss_file *selected_file;
	uint8_t record_number;
	uint8_t record_number_new;
	int rc;

	rc = select_by_sfi_recordstyle(apdu);
	if (rc != 0)
		return rc;

	/* Get currently selected file and verify that the structure is suitable
	 * to carry out the intended file operation. */
	selected_file = ss_get_file_from_path(&apdu->lchan->fs_path);
	rc = verify_file_struct(apdu, selected_file, true);
	if (rc != 0)
		return rc;

	if (!ss_access_check_command(apdu, SS_ACCESS_INTENTION_EF_UPDATE_ERASE)) {
		apdu->le = 0;
		return SS_SW_ERR_CMD_NOT_ALLOWED_NO_INFO;
	}

	/* FIXME #60: check invalidated / terminated */

	/* Determine record number */
	rc = calc_record_number(&record_number_new, &record_number, apdu, selected_file);
	if (rc != 0)
		return rc;

	if (apdu->lc != selected_file->fcp_file_descr->record_len) {
		return SS_SW_ERR_CMD_NOT_ALLOWED_INCOMP_FILE_STRUCT;
	}

	rc = ss_fs_write_file_record(&apdu->lchan->fs_path, record_number, apdu->cmd,
				     selected_file->fcp_file_descr->record_len);
	if (rc != 0)
		return SS_SW_ERR_WRONG_PARAM_ENOMEM;

	/* Everything went successful, update record pointer */
	apdu->lchan->current_record = record_number_new;

	record_file_change(apdu);

	return 0;
}

enum search_mode {
	SEARCH_SIMPLE_FORWARD = 0x04,
	SEARCH_SIMPLE_BACKWARD = 0x05,
	SEARCH_ENHANCED = 0x06,
};

static int find_offset(struct ss_buf *buf, uint8_t search_byte)
{
	uint8_t i;

	/* It makes no sense to find an offset in a string smaller than 2
	 * bytes. */
	if (buf->len < 2)
		return -EINVAL;

	for (i = 0; i < buf->len - 1; i++) {
		/* Search begins after the occurrence of the search byte,
		 * see also ETSI TS 102 221, table Table 11.13 */
		if (buf->data[i] == search_byte)
			return i + 1;
	}

	return -EINVAL;
}

/*! SEARCH RECORD (TS 102 221 Section 11.1.7) */
int ss_uicc_file_ops_cmd_search_record(struct ss_apdu *apdu)
{
	struct ss_file *selected_file;
	uint8_t n_records;
	int rc;
	struct ss_buf *buf;
	uint8_t n_results = 0;

	/* search parameter */
	enum search_mode search_mode;
	uint8_t *search_string;
	uint8_t search_string_len;
	uint8_t search_offset = 0xff;
	uint8_t search_byte;
	bool search_offset_dyn;
	bool search_dir_forward;
	uint8_t search_record_number;
	uint8_t enchanced_search_mode;

	rc = select_by_sfi_recordstyle(apdu);
	if (rc != 0)
		return rc;

	/* Get currently selected file and verify that the structure is suitable
	 * to carry out the intended file operation. */
	selected_file = ss_get_file_from_path(&apdu->lchan->fs_path);
	rc = verify_file_struct(apdu, selected_file, true);
	if (rc != 0)
		return rc;

	n_records = selected_file->fcp_file_descr->number_of_records;
	SS_LOGP(SFILE, LDEBUG, "number of records: %u\n", n_records);

	/* See also ETSI TS 102 221, table Table 11.12 */
	search_mode = apdu->hdr.p2 & 0x07;

	switch (search_mode) {
	case SEARCH_ENHANCED:
		/* See also ETSI TS 102 221, table Table 11.13 */
		enchanced_search_mode = apdu->cmd[0];

		SS_LOGP(SFILE, LDEBUG, "search mode: \"enhanced search\"\n");
		if (apdu->lc < 3) {
			SS_LOGP(SFILE, LERROR, "no search string!\n");
			return SS_SW_ERR_CHECKING_WRONG_P1_P2;
		}

		search_string = apdu->cmd + 2;
		search_string_len = apdu->lc - 2;

		if ((enchanced_search_mode >> 3 & 1) == 0) {
			/* search byte encodes the offset */
			search_offset = apdu->cmd[1];
			search_offset_dyn = false;
		} else {
			/* search byte defines the offset dynamically
			 * by its first occurrence. */
			search_byte = apdu->cmd[1];
			search_offset_dyn = true;
		}

		/* This search mode does not support using the current record */
		if (apdu->hdr.p1 == 0x00) {
			SS_LOGP(SFILE, LERROR, "record pointer not usable in enhanced search mode!\n");
			return SS_SW_ERR_CHECKING_WRONG_P1_P2;
		}

		if (enchanced_search_mode >> 2 & 1) {
			if (apdu->hdr.p1 == 0x00)
				search_record_number = apdu->lchan->current_record;
			else
				search_record_number = apdu->hdr.p1;
		} else {
			SS_LOGP(SFILE, LERROR, "invalid enhanced search mode (%02x)!\n", enchanced_search_mode);
			return SS_SW_ERR_WRONG_PARAM_FUNCTION_NOT_SUPPORTED;
		}

		switch (enchanced_search_mode & 0x03) {
		case 0:
			search_dir_forward = true;
			break;
		case 1:
			search_dir_forward = false;
			break;
		case 2:
			/* When we are already at the last record but the search shall begin at
			 * the following record, then the search makes no sense since there is
			 * nothing left to search. The command will execute successful though, but
			 * there will be no search results. */
			if (search_record_number == n_records) {
				SS_LOGP(SFILE, LERROR, "no next record, skipping search...\n");
				return 0;
			}
			search_record_number++;
			search_dir_forward = true;
			break;
		case 3:
			/* See comment above */
			if (search_record_number == 1) {
				SS_LOGP(SFILE, LERROR, "no previous record, skipping search...\n");
				return 0;
			}
			search_record_number--;
			search_dir_forward = false;
			break;
		default:
			/* Numerically unreachable, but -Werror=maybe-uninitialized doesn't know
			 * that */
			assert(false);
		}

		break;
	case SEARCH_SIMPLE_FORWARD:
	case SEARCH_SIMPLE_BACKWARD:
		SS_LOGP(SFILE, LDEBUG, "search mode: \"simple search\"\n");
		if (apdu->lc < 1) {
			SS_LOGP(SFILE, LERROR, "no search string!\n");
			return SS_SW_ERR_CHECKING_WRONG_P1_P2;
		}
		search_string = apdu->cmd;
		search_string_len = apdu->lc;
		search_offset = 0;
		search_offset_dyn = false;
		if (apdu->hdr.p1 == 0x00)
			search_record_number = apdu->lchan->current_record;
		else
			search_record_number = apdu->hdr.p1;

		if (search_mode == SEARCH_SIMPLE_FORWARD)
			search_dir_forward = true;
		else
			search_dir_forward = false;
		break;
	default:
		SS_LOGP(SFILE, LERROR, "invalid search mode (%02x)!\n", search_mode);
		return SS_SW_ERR_WRONG_PARAM_FUNCTION_NOT_SUPPORTED;
	}

	SS_LOGP(SFILE, LDEBUG, "search parameter:\n");
	SS_LOGP(SFILE, LDEBUG, " search string: %s\n", ss_hexdump(search_string, search_string_len));
	if (search_offset_dyn)
		SS_LOGP(SFILE, LDEBUG, " search offset: first occurrence of %02x in record\n", search_byte);
	else
		SS_LOGP(SFILE, LDEBUG, " search offset: %u\n", search_offset);
	SS_LOGP(SFILE, LDEBUG, " search begins at record: %u\n", search_record_number);
	SS_LOGP(SFILE, LDEBUG, " search direction: %s\n", search_dir_forward ? "forward" : "backward");

	while (1) {
		buf = ss_fs_read_file_record(&apdu->lchan->fs_path, search_record_number);
		if (!buf)
			return SS_SW_ERR_WRONG_PARAM_ENOMEM;

		/* Find dynamic offset */
		if (search_offset_dyn) {
			rc = find_offset(buf, search_byte);
			if (rc < 0) {
				SS_LOGP(SFILE, LDEBUG,
					"skipping record %u since it does not contain a byte with vale %02x\n",
					search_record_number, search_byte);
				goto skip;
			} else
				search_offset = (uint8_t)rc;
		}

		/* Ensure meaningful length parameters */
		if (search_offset >= buf->len)
			goto skip;
		if (search_string_len > buf->len - search_offset)
			goto skip;

		if (memcmp(search_string, buf->data + search_offset, search_string_len) == 0) {
			SS_LOGP(SFILE, LDEBUG, "comparing record %u to search string at offset %u <== MATCH\n",
				search_record_number, search_offset);
			apdu->rsp[n_results] = search_record_number;
			n_results++;
		} else {
			SS_LOGP(SFILE, LDEBUG, "comparing record %u to search string at offset %u\n",
				search_record_number, search_offset);
		}

skip:
		ss_buf_free(buf);

		if (search_dir_forward) {
			if (search_record_number < n_records)
				search_record_number++;
			else
				break;
		} else {
			if (search_record_number > 1)
				search_record_number--;
			else
				break;
		}
	}

	apdu->rsp_len = n_results;

	return 0;
}

static int select_by_fid(struct ss_apdu *apdu)
{
	uint16_t fid;
	int rc;
	struct ss_file *selected_file;

	/* See also: ETSI TS 102 221, section 8.4.1 */

	if (apdu->lc != 2) {
		SS_LOGP(SFILE, LDEBUG, "selecting by FID: (invalid)\n");
		return -1;
	}

	fid = apdu->cmd[0] << 8 | apdu->cmd[1];
	SS_LOGP(SFILE, LDEBUG, "selecting by FID: %04x\n", fid);

	/* NOTE: The function ss_fs_select() will handle the priority of the
	 * MF. There is no need to implement it here. */

	/* Select the currently active application by its alias,
	   see also ETSI TS 102 221 section 8.4.1 */
	if (fid == FID_CURRENT_APP) {
		ss_path_reset(&apdu->lchan->fs_path);
		rc = ss_fs_utils_path_select(&apdu->lchan->fs_path, &apdu->lchan->adf_path);
		if (rc < 0)
			return SS_SW_ERR_WRONG_PARAM_FILE_NOT_FOUND;
		goto leave;
	}

	/* Try to find a DF or EF in the current directory */
	rc = ss_fs_select(&apdu->lchan->fs_path, fid);
	if (rc == 0) {
		SS_LOGP(SFILE, LDEBUG, "success: file (%04x) found in the current DF.\n", fid);
		goto leave;
	}

	/* A failed select beforehand leaves us with the current DF. If the
	 * FID of the current DF matches the FID we intend to select, then
	 * the select was indeed successful. */
	SS_LOGP(SFILE, LDEBUG, "selecting by FID: %04x (2nd try)\n", fid);
	selected_file = ss_get_file_from_path(&apdu->lchan->fs_path);
	if (!selected_file)
		return SS_SW_ERR_WRONG_PARAM_FILE_NOT_FOUND;
	if (selected_file->fid == fid) {
		SS_LOGP(SFILE, LDEBUG, "success: file (%04x) matches the current DF.\n", fid);
		goto leave;
	}

	/* We now select the parent of the current directory. If the FID of
	 * that parent matches the FID we intend to select, then the select
	 * is successful. */
	SS_LOGP(SFILE, LDEBUG, "selecting by FID: %04x (3rd try)\n", fid);
	rc = ss_fs_select_parent(&apdu->lchan->fs_path);
	if (rc < 0)
		return SS_SW_ERR_WRONG_PARAM_FILE_NOT_FOUND;
	selected_file = ss_get_file_from_path(&apdu->lchan->fs_path);
	if (!selected_file)
		return SS_SW_ERR_WRONG_PARAM_FILE_NOT_FOUND;
	if (selected_file->fid == fid) {
		SS_LOGP(SFILE, LDEBUG, "success: file (%04x) matches the parent of the current DF.\n", fid);
		goto leave;
	}

	/* Next we try to select the fid again. If we manage to select a DF
	 * (not an EF), then the correct file is selected and the select was
	 * successful */
	SS_LOGP(SFILE, LDEBUG, "selecting by FID: %04x (4th try)\n", fid);
	rc = ss_fs_select(&apdu->lchan->fs_path, fid);
	if (rc == 0) {
		selected_file = ss_get_file_from_path(&apdu->lchan->fs_path);
		if (!selected_file)
			return SS_SW_ERR_WRONG_PARAM_FILE_NOT_FOUND;
		if (selected_file->fcp_file_descr->type == SS_FCP_DF_OR_ADF) {
			SS_LOGP(SFILE, LDEBUG, "success: file (%04x) found in the parent of the current DF.\n", fid);
			goto leave;
		}
		ss_fs_select_parent(&apdu->lchan->fs_path);
	}

	/* As a last resort we may try to walk up the path and check if we meet
	 * a matching ADF at some point. (This would be unusual, since
	 * applications are usually selected via DF name.) */
	SS_LOGP(SFILE, LDEBUG, "selecting by FID: %04x (6th try)\n", fid);
	while (1) {
		rc = ss_fs_select_parent(&apdu->lchan->fs_path);
		if (rc < 0)
			break;
		selected_file = ss_get_file_from_path(&apdu->lchan->fs_path);
		if (!selected_file)
			break;

		/* Check if the file has a DF name, then check if the FID of
		 * that file matches the FID we intended to select. */
		if (ss_fcp_get_df_name(selected_file->fcp_decoded)) {
			if (selected_file->fid == fid) {
				SS_LOGP(SFILE, LDEBUG,
					"success: file (%04x) is an ADF and was found in the current path.\n", fid);
				goto leave;
			}
		}
	}

	return SS_SW_ERR_WRONG_PARAM_FILE_NOT_FOUND;
leave:
	ss_access_populate(apdu->lchan);

	return 0;
}

static int select_by_df_name(struct ss_apdu *apdu)
{
	int rc;
	uint32_t fid;
	struct ss_buf *df_name;
	struct ss_file *selected_file;

	SS_LOGP(SFILE, LDEBUG, "selecting DF by name: %s\n", ss_hexdump(apdu->cmd, apdu->lc));

	rc = ss_df_name_resolve(&apdu->lchan->fs_path, apdu->cmd, apdu->lc);
	if (rc < 0) {
		/* If we cannot resolve the DF_name, the reason might be that
		 * we are deeper in the path. In this case will go back up and
		 * stop at the ADF. */
		while (1) {
			rc = ss_fs_select_parent(&apdu->lchan->fs_path);
			if (rc < 0)
				break;
			selected_file = ss_get_file_from_path(&apdu->lchan->fs_path);
			if (!selected_file)
				break;

			/* NOTE: we are not taking ownership of the returned df_name. */
			df_name = ss_fcp_get_df_name(selected_file->fcp_decoded);
			if (df_name) {
				SS_LOGP(SFILE, LDEBUG, "trying parent file: %s, DF_name: %s\n",
					ss_fs_utils_dump_path(&apdu->lchan->fs_path),
					ss_hexdump(df_name->data, df_name->len));
				if (memcmp(df_name->data, apdu->cmd, apdu->lc) == 0)
					goto leave;
			}
		}

		/* Last we can try is to select the MF and then try to select
		 * the supplied DF_name. */
		rc = ss_fs_select(&apdu->lchan->fs_path, 0x3f00);
		if (rc < 0)
			return SS_SW_ERR_WRONG_PARAM_FILE_NOT_FOUND;
		rc = ss_df_name_resolve(&apdu->lchan->fs_path, apdu->cmd, apdu->lc);
		if (rc < 0)
			return SS_SW_ERR_WRONG_PARAM_REFERENCED_DATA_NOT_FOUND;
	}

	/* Select ADF by the resolved FID */
	fid = (uint32_t)(rc & 0xffff);
	rc = ss_fs_select(&apdu->lchan->fs_path, fid);
	if (rc < 0)
		return SS_SW_ERR_WRONG_PARAM_FILE_NOT_FOUND;
leave:
	ss_access_populate(apdu->lchan);

	return 0;
}

static int select_parent_df_of_current_df(struct ss_apdu *apdu)
{
	int rc;
	struct ss_file *selected_file;

	SS_LOGP(SFILE, LDEBUG, "selecting parent DF of current DF\n");

	/* Make sure the current DF is selected */
	selected_file = ss_get_file_from_path(&apdu->lchan->fs_path);
	if (!selected_file)
		return SS_SW_ERR_WRONG_PARAM_FILE_NOT_FOUND;
	if (selected_file->fcp_file_descr->type != SS_FCP_DF_OR_ADF) {
		rc = ss_fs_select_parent(&apdu->lchan->fs_path);
		if (rc < 0)
			return SS_SW_ERR_WRONG_PARAM_FILE_NOT_FOUND;
	}

	/* Select the parent of the current DF */
	rc = ss_fs_select_parent(&apdu->lchan->fs_path);
	if (rc < 0)
		return SS_SW_ERR_WRONG_PARAM_FILE_NOT_FOUND;

	ss_access_populate(apdu->lchan);

	return 0;
}

static int select_path(struct ss_apdu *apdu, bool from_mf)
{
	unsigned int i;
	uint32_t fid;
	struct ss_file *selected_file;
	int rc;

	if (from_mf)
		SS_LOGP(SFILE, LDEBUG, "selecting by path from MF\n");
	else
		SS_LOGP(SFILE, LDEBUG, "selecting by path from current DF\n");

	/* Check for a messed up path. */
	if (apdu->lc % 2)
		return SS_SW_ERR_WRONG_PARAM_INCORRECT_DATA;

	/* Select start position */
	if (from_mf) {
		rc = ss_fs_select(&apdu->lchan->fs_path, 0x3f00);
		if (rc < 0)
			return SS_SW_ERR_WRONG_PARAM_FILE_NOT_FOUND;
	} else {
		selected_file = ss_get_file_from_path(&apdu->lchan->fs_path);
		if (!selected_file)
			return SS_SW_ERR_WRONG_PARAM_FILE_NOT_FOUND;
		if (selected_file->fcp_file_descr->type != SS_FCP_DF_OR_ADF) {
			rc = ss_fs_select_parent(&apdu->lchan->fs_path);
			if (rc < 0)
				return SS_SW_ERR_WRONG_PARAM_FILE_NOT_FOUND;
		}
	}

	/* Select path */
	for (i = 0; i < apdu->lc / 2; i++) {
		fid = ss_uint32_from_array(apdu->cmd + i * 2, 2);

		if (fid == FID_CURRENT_APP) {
			/* Select the currently active application by its alias,
			   see also ETSI TS 102 221 section 8.4.2 */
			ss_path_reset(&apdu->lchan->fs_path);
			rc = ss_fs_utils_path_select(&apdu->lchan->fs_path, &apdu->lchan->adf_path);
		} else {
			rc = ss_fs_select(&apdu->lchan->fs_path, fid);
		}

		if (rc < 0)
			return SS_SW_ERR_WRONG_PARAM_FILE_NOT_FOUND;
	}

	ss_access_populate(apdu->lchan);

	return 0;
}

/* Update path to active ADF path. This is called after each select. The
 * pathes are only updated when the currently active ADF changes. */
static int update_active_adf(struct ss_lchan *lchan)
{
	struct ss_file *selected_file;
	int rc;

	selected_file = ss_get_file_from_path(&lchan->fs_path);
	assert(selected_file);

	/* Update active ADF (we recognize ADFs by the assigned DF Name) */
	if (ss_fcp_get_df_name(selected_file->fcp_decoded) &&
	    ss_fs_utils_path_equals(&lchan->fs_path, &lchan->adf_path) == false) {
		ss_path_reset(&lchan->adf_path);
		rc = ss_fs_utils_path_select(&lchan->adf_path, &lchan->fs_path);
		if (rc < 0) {
			SS_LOGP(SFILE, LERROR, "cannot update path to active ADF!\n");
			return -EINVAL;
		}
	}

	return 0;
}

/* SELECT, see also ETSI TS 102 221, section 11.1.1 */
int ss_uicc_file_ops_cmd_select(struct ss_apdu *apdu)
{
	int rc;
	struct ss_file *selected_file;

	/* Reset current record for record oriented files. */
	apdu->lchan->current_record = 0;

	switch (apdu->hdr.p1) {
	case 0x00: /* DF, EF or MF by file ID */
		rc = select_by_fid(apdu);
		break;
	case 0x01: /* child DF of the current DF */
		/* TODO #62: The specification is not clear how this select
		 * method should be implemented. In particular it is unclear
		 * about which child DF should be picked in case the DF has
		 * more than a single child DF. If we manage to solve this
		 * problem, we can implement this selection method. */
		rc = SS_SW_ERR_WRONG_PARAM_FUNCTION_NOT_SUPPORTED;
		break;
	case 0x03: /* parent DF of current DF */
		rc = select_parent_df_of_current_df(apdu);
		break;
	case 0x04: /* DF name (AID) */
		rc = select_by_df_name(apdu);
		break;
	case 0x08: /* path from MF */
		rc = select_path(apdu, true);
		break;
	case 0x09: /* path from current DF */
		rc = select_path(apdu, false);
		break;
	default:
		return SS_SW_ERR_CHECKING_WRONG_P1_P2;
	}

	if (rc != 0) {
		SS_LOGP(SFILE, LDEBUG, "select failed!\n");
		return rc;
	}
	selected_file = ss_get_file_from_path(&apdu->lchan->fs_path);
	if (!selected_file) {
		SS_LOGP(SFILE, LDEBUG, "select failed -- no file selected!\n");
		return SS_SW_ERR_EXEC_MEMORY_PROBLEM;
	}

	/* generate full FCP string */
	rc = fcp_reencode_full(selected_file, "select");
	if (rc < 0)
		return SS_SW_ERR_EXEC_MEMORY_PROBLEM;

	/* Update path to currently active ADF */
	rc = update_active_adf(apdu->lchan);
	if (rc < 0)
		return SS_SW_ERR_EXEC_MEMORY_PROBLEM;

	/* Return FCP template if requested */
	if ((apdu->hdr.p2 & 0x0c) == 0x04) {
		memcpy(apdu->rsp, selected_file->fci->data, selected_file->fci->len);
		apdu->rsp_len = selected_file->fci->len;
	}

	SS_LOGP(SFILE, LDEBUG, "Successfully selected: %s\n", ss_fs_utils_dump_path(&apdu->lchan->fs_path));
	ss_btlv_dump(selected_file->fcp_decoded, 1, SFILE, LDEBUG);

	return 0;
}
