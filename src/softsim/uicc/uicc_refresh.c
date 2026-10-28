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
#include "context.h"
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
