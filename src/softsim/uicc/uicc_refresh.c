/*
 * Copyright (c) 2024 Onomondo ApS. All rights reserved.
 *
 * SPDX-License-Identifier: GPL-3.0-only
 *
 * Author: Philipp Maier
 */

#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <errno.h>
#include <onomondo/softsim/utils.h>
#include <onomondo/softsim/log.h>
#include <onomondo/softsim/storage.h>
#include "context.h"
#include "fs.h"
#include "uicc_cat.h"
#include "uicc_refresh.h"
#include "ctlv.h"

#define MAX_REFRESH_RETRYS 3

/* REFRESH modes, see also ETSI TS 102 223, section 8.6 */
#define MODE_FULL_FILE_CHANGE_NOTIFICATION 0x00
#define MODE_FILE_CHANGE_NOTIFICATION 0x01
#define MODE_UICC_RESET 0x04

static void term_response_cb(struct ss_context *ctx, uint8_t *resp_data, uint8_t resp_data_len)
{
	struct ss_uicc_refresh_state *state = &ctx->proactive.refresh_state;
	int rc;

	rc = ss_proactive_get_rc(resp_data, resp_data_len, SREFRESH);

	if (ss_proactive_rc_retry(rc) && state->retry_counter < MAX_REFRESH_RETRYS) {
		SS_LOGP(SREFRESH, LERROR, "unsuccessful REFRESH command, retrying...\n");
		/* Unfortunately there is not much that can be done at this point other
		 * than trying again. */
		state->state = SS_REFRESH_PENDING;
		state->retry_counter++;
	} else if (!ss_proactive_rc_performed(rc)) {
		SS_LOGP(SREFRESH, LERROR, "unsuccessful REFRESH command, giving up...\n");
		state->state = SS_REFRESH_READY;
		state->retry_counter = 0;
	} else {
		SS_LOGP(SREFRESH, LDEBUG, "successful REFRESH command, done!\n");
		state->state = SS_REFRESH_READY;
		state->retry_counter = 0;
	}
}

/* TS 31.111, 6.4.7.1 rules out file change notification for a changed
 * EF.IMSI. The list holds 2-byte FIDs after the count. */
static bool imsi_changed(const uint8_t *filelist, int filelist_len)
{
	int i;

	for (i = 1; i + 1 < filelist_len; i += 2) {
		if (filelist[i] == 0x6f && filelist[i + 1] == 0x07)
			return true;
	}
	return false;
}

/* "Not updated" location files: LAC/TAC '0000' marks a deleted area (TS 24.008
 * 10.5.1.3), status 01 (TS 31.102 4.2.17, 4.2.23, 4.2.91); no DF.5GS files. */
static const uint8_t loci_not_updated[] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0xff, 0x01 };
static const uint8_t psloci_not_updated[] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
					      0xff, 0xff, 0xff, 0x00, 0x00, 0xff, 0x01 };
static const uint8_t epsloci_not_updated[] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
					       0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x01 };

static const struct {
	uint16_t fid;
	const uint8_t *content;
	size_t len;
} loci_files[] = {
	{ 0x6f7e, loci_not_updated, sizeof(loci_not_updated) },
	{ 0x6f73, psloci_not_updated, sizeof(psloci_not_updated) },
	{ 0x6fe3, epsloci_not_updated, sizeof(epsloci_not_updated) },
};

/*! Reset the location files after a remote EF.IMSI change, when the card
 *  session ends (TS 31.111, 6.4.7.1; TS 31.124, 27.22.4.7.2). */
void ss_uicc_refresh_session_end(struct ss_context *ctx)
{
	struct ss_uicc_refresh_state *state = &ctx->proactive.refresh_state;
	struct ss_list path;
	size_t i;
	int rc;

	/* An EF.IMSI change still waiting for its REFRESH is owed the reset too */
	if (!ctx->fs_chg_is_borrowed && imsi_changed(ctx->fs_chg_filelist, ss_fs_chg_len(ctx->fs_chg_filelist)))
		state->loci_reset_pending = true;
	if (!state->loci_reset_pending)
		return;

	ss_fs_init(&path);
	/* ADF.USIM, as the file system TARs preselect it (uicc_remote_cmd.c) */
	rc = ss_fs_select(&path, 0x7ff0);
	if (rc < 0) {
		SS_LOGP(SREFRESH, LERROR, "cannot select the ADF, location files not reset\n");
		ss_path_reset(&path);
		return;
	}
	state->loci_reset_pending = false;

	for (i = 0; i < SS_ARRAY_SIZE(loci_files); i++) {
		/* An optional file the profile lacks is skipped */
		if (ss_fs_select(&path, loci_files[i].fid) < 0)
			continue;
		if (ss_storage_get_file_len(&path) != loci_files[i].len) {
			SS_LOGP(SREFRESH, LERROR, "file %04x has an unexpected size, not reset\n", loci_files[i].fid);
			continue;
		}
		rc = ss_storage_write_file(&path, loci_files[i].content, 0, loci_files[i].len);
		if (rc < 0)
			SS_LOGP(SREFRESH, LERROR, "file %04x not writeable\n", loci_files[i].fid);
		else
			SS_LOGP(SREFRESH, LINFO, "file %04x reset after the EF.IMSI change\n", loci_files[i].fid);
	}
	ss_path_reset(&path);
}

/* Encode and queue a REFRESH command, see also ETSI TS 102 223, section 6.6.13 */
static int put_refresh(struct ss_context *ctx, uint8_t mode, const uint8_t *filelist, int filelist_len)
{
	struct ss_list *cmd_list;
	struct ss_buf *cmd;
	int rc;
	uint8_t cmd_details[] = { 0x01, TS_102_223_TOC_REFRESH, mode };
	/* ETSI TS 102 223, section 8.7: from the UICC to the terminal */
	uint8_t device_id[] = { 0x81, 0x82 };

	cmd_list = SS_ALLOC(struct ss_list);
	ss_list_init(cmd_list);
	ss_ctlv_new_ie(cmd_list, TS_101_220_IEI_CMD_DETAILS, true, sizeof(cmd_details), cmd_details);
	ss_ctlv_new_ie(cmd_list, TS_101_220_IEI_DEV_ID, true, sizeof(device_id), device_id);
	/* Only a File Change Notification names the files (TS 31.124, 27.22.4.7.1 seq 1.5 for the UICC Reset) */
	if (mode == MODE_FILE_CHANGE_NOTIFICATION)
		ss_ctlv_new_ie(cmd_list, TS_101_220_IEI_FILE_LST_OR_CAT_SERV_LST, true, filelist_len, filelist);
	SS_LOGP(SREFRESH, LDEBUG, "resulting message IEs:\n");
	ss_ctlv_dump(cmd_list, 2, SREFRESH, LDEBUG);
	cmd = ss_ctlv_encode_to_ss_buf(cmd_list);
	ss_ctlv_free(cmd_list);

	if (!cmd) {
		SS_LOGP(SREFRESH, LERROR, "Sending REFRESH failed -- cannot encode command!\n");
		return -EINVAL;
	}
	rc = ss_proactive_put(ctx, term_response_cb, cmd->data, cmd->len);
	ss_buf_free(cmd);
	return rc;
}

/* Generate REFRESH command from the data in the state and send it */
static int send_refresh(struct ss_context *ctx, struct ss_uicc_refresh_state *state)
{
	uint8_t mode = MODE_FILE_CHANGE_NOTIFICATION;
	int filelist_len;
	int rc;

	filelist_len = ss_fs_chg_len(state->filelist);
	if (filelist_len < 0) {
		SS_LOGP(SREFRESH, LDEBUG, "Sending REFRESH command failed -- file list is invalid!\n");
		return -EINVAL;
	}
	if (imsi_changed(state->filelist, filelist_len))
		mode = MODE_UICC_RESET;

	rc = put_refresh(ctx, mode, state->filelist, filelist_len);

	/* A list too long for one proactive command: have the terminal read
	 * every file of the application again instead (section 8.6). */
	if (rc == -EINVAL && mode == MODE_FILE_CHANGE_NOTIFICATION) {
		SS_LOGP(SREFRESH, LINFO,
			"file list too long for a REFRESH, requesting a full file change notification\n");
		rc = put_refresh(ctx, MODE_FULL_FILE_CHANGE_NOTIFICATION, NULL, 0);
	}
	return rc;
}

/*! Poll proactive task "REFRESH".
 *  \param[inout] ctx softsim context. */
void ss_uicc_refresh_poll(struct ss_context *ctx)
{
	struct ss_uicc_refresh_state *state = &ctx->proactive.refresh_state;
	int rc;

	switch (state->state) {
	case SS_REFRESH_READY:
		if (ctx->fs_chg_filelist[0] == 0x00) {
			SS_LOGP(SREFRESH, LDEBUG, "no file changes detected, skipping...\n");
			return;
		}
		/* Owed to the IMSI change itself, with or without REFRESH support */
		if (imsi_changed(ctx->fs_chg_filelist, ss_fs_chg_len(ctx->fs_chg_filelist)))
			state->loci_reset_pending = true;
		/* Check REFRESH support, see also ETSI TS 131 111 section 5.2 */
		if (!ss_proactive_term_prof_bit(ctx, 3, 8)) {
			SS_LOGP(SREFRESH, LINFO, "TERMINAL PROFILE does not support REFRESH, file changes dropped\n");
			ctx->fs_chg_filelist[0] = 0;
			return;
		}
		SS_LOGP(SREFRESH, LDEBUG, "following file changes will be refreshed:\n");
		ss_fs_chg_dump(ctx->fs_chg_filelist, 2, SREFRESH, LDEBUG);
		memcpy(state->filelist, ctx->fs_chg_filelist, SS_FS_CHG_BUF_SIZE);
		ctx->fs_chg_filelist[0] = 0;
		state->state = SS_REFRESH_PENDING;
		/* fallthrough */
	case SS_REFRESH_PENDING:
		rc = send_refresh(ctx, state);
		if (rc == -EBUSY) {
			SS_LOGP(SREFRESH, LERROR, "cannot send REFRESH, another command is busy, retrying...\n");
			return;
		} else if (rc < 0) {
			/* Note: This should not happen since it would mean
			 * that the data we give to send_refresh is garbled,
			 * since we are generating it internally the data
			 * should always be fine. */
			SS_LOGP(SREFRESH, LERROR, "cannot send REFRESH, data is not accepted, giving up...\n");
			state->state = SS_REFRESH_READY;
			return;
		}
		SS_LOGP(SREFRESH, LDEBUG, "REFRESH command sent!\n");
		state->state = SS_REFRESH_TRANSIT;
		/* fallthrough */
	case SS_REFRESH_TRANSIT:
		/* Do nothing, wait for the TERMINAL RESPONSE (see above) */
		SS_LOGP(SREFRESH, LDEBUG, "waiting until file changes are transmitted...:\n");
		break;
	}
}
