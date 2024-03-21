/*
 * Copyright (c) 2024 Onomondo ApS. All rights reserved.
 *
 * SPDX-License-Identifier: GPL-3.0-only
 *
 * Author: Philipp Maier
 *
 * This module provides tha API to communicate with SoftSIM. The APDU input and
 * output is communicated via ss_apdu structs.
 */

#include <assert.h>
#include <stdint.h>
#include <string.h>
#include <onomondo/softsim/softsim.h>
#include <onomondo/softsim/log.h>
#include <onomondo/softsim/utils.h>
#include "access.h"
#include "fs.h"
#include "fs_utils.h"
#include "sw.h"
#include "command.h"
#include "uicc_lchan.h"
#include "context.h"
#include "apdu.h"
#include "uicc_ins.h"
#include "proactive.h"

/*! Create a new softsim context.
 *  \returns allocated softsim context. */
struct ss_context *ss_new_ctx(void)
{
	struct ss_context *ctx;
	uint8_t *fs_chg_filelist;

	ctx = SS_ALLOC(struct ss_context);
	if (ctx == NULL) {
		return NULL;
	}
	fs_chg_filelist = SS_ALLOC(uint8_t[SS_FS_CHG_BUF_SIZE]);

	if (fs_chg_filelist == NULL) {
		SS_FREE(ctx);
		return NULL;
	}

	/* Note: filling the entire context struct with zeros at the beginning
	 * is important since the softsim code relies on the fact that in the
	 * begining all context state and state in its sub structs is in a
	 * defined state (all-zero). */
	memset(ctx, 0, sizeof(*ctx));

	ctx->fs_chg_filelist = fs_chg_filelist;
	/* Set length indicator; the rest may stay uninitialized */
	ctx->fs_chg_filelist[0] = 0;
	ctx->is_suspended = 0;
	return ctx;
}

/*! Create a new softsim context that is recording into the file list of
 *  another context given in @p fs_chg_filelist.
 *  \returns allocated softsim context. */
struct ss_context *ss_new_reporting_ctx(uint8_t *fs_chg_filelist)
{
	struct ss_context *ctx;
	ctx = SS_ALLOC(struct ss_context);
	if (ctx == NULL)
		return NULL;

	/* Zeroing as in ss_new_ctx */
	memset(ctx, 0, sizeof(*ctx));

	ctx->fs_chg_is_borrowed = true;

	ctx->fs_chg_filelist = fs_chg_filelist;
	if (fs_chg_filelist != NULL)
		ctx->fs_chg_record = true;

	return ctx;
}

/*! Free a new softsim context. */
void ss_free_ctx(struct ss_context *ctx)
{
	/* Clear all proactive sim related state (cat) */
	ss_uicc_sms_rx_clear(ctx);
	ss_uicc_sms_tx_clear(ctx);

	ss_uicc_lchan_free(ctx);

	if (!ctx->fs_chg_is_borrowed)
		SS_FREE(ctx->fs_chg_filelist);

	SS_FREE(ctx);
}

/*! Reset the UICC state.
 *  \param[inout] ctx softsim context. */
void ss_reset(struct ss_context *ctx)
{
	SS_LOGP(SLCHAN, LDEBUG, "------------------------------- reset -------------------------------\n");

	/* Reset lchan(s) */
	ss_uicc_lchan_reset(ctx);

	/* Clear all proactive sim related state (cat) */
	/* NOTE: we clear the cat_sms_state before the memset since this struct
	 * may hold a linked list, which needs to be freed first. After that it
	 * is safe to wipe out everythig with zeros. */
	ss_uicc_sms_rx_clear(ctx);
	ss_uicc_sms_tx_clear(ctx);
	memset(&ctx->proactive, 0, sizeof(ctx->proactive));

	return;
}

/*! Poll the UICC to process proactive SIM tasks.
 *  \param[inout] ctx softsim context. */
void ss_poll(struct ss_context *ctx)
{
	if (ctx->proactive.enabled)
		ss_proactive_poll(ctx);
	return;
}

/*! Get an ATR (without resetting the UICC state).
 *  \param[inout] ctx softsim context.
 *  \param[out] atr_buf user provided memory to store the resulting ATR.
 *  \param[in] atr_buf_len maxium length of the user provided memory.
 *  \returns length of the resulting ATR. */
size_t ss_atr(struct ss_context *ctx, uint8_t *atr_buf, size_t atr_buf_len)
{
	uint8_t tck = 0;
	size_t i;

	uint8_t atr[] = { 0x3B, 0x9F, 0x01, 0x80, 0x1F, 0x87, 0x80, 0x31, 0xE0, 0x73, 0xFE,
			  0x21, 0x00, 0x67, 0x4A, 0x4C, 0x75, 0x30, 0x34, 0x05, 0x4B };

	for (i = 1; i < sizeof(atr); i++) {
		tck ^= atr[i];
	}

	assert(atr_buf_len >= sizeof(atr) + 1);

	memcpy(atr_buf, atr, sizeof(atr));
	atr_buf[sizeof(atr)] = tck;

	return sizeof(atr) + 1;
}

uint8_t ss_is_suspended(struct ss_context *ctx)
{
	if (!ctx)
		return 0;
	return ctx->is_suspended;
}

/* Perform transaction with UICC using an already parsed APDU */
static int apdu_transact(struct ss_context *ctx, struct ss_apdu *apdu)
{
	const struct ss_command *cmd;
	struct ss_list backup_path;
	int rc;
	struct ss_apdu *last_apdu = NULL;

	int processed_length = -1;

	SS_LOGP(SLCHAN, LDEBUG, "------------------------- transaction begins ------------------------\n");

	SS_LOGP(SLCHAN, LDEBUG, "Rx C-APDU %02X-%02X %02X-%02X %02X\n", apdu->hdr.cla, apdu->hdr.ins, apdu->hdr.p1,
		apdu->hdr.p2, apdu->hdr.p3);

	/* TS 102 221 Table 10.3 */
	if (apdu->hdr.cla & 0x0C) {
		/* we don't support secure messaging */
		apdu->sw = SS_SW_ERR_FUNCTION_IN_CLA_NOT_SUPP_SM;
		apdu->lc = 0;
		goto out;
	}

	/* Find an lchan (UICC state) for the incoming APDU */
	apdu->lchan = ss_uicc_lchan_get(ctx, apdu->hdr.cla);
	if (!apdu->lchan) {
		apdu->sw = SS_SW_ERR_FUNCTION_IN_CLA_NOT_SUPP_LCHAN;
		apdu->lc = 0;
		goto out;
	}

	/* Reset the APDU keep flag. This is related to GET RESPONSE. The decision
	 * is made for each individual transaction. */
	apdu->lchan->last_apdu_keep = false;

	/* We do not ask of commands that they keep the path where it was in their
	 * error cases. */
	ss_fs_utils_path_clone(&backup_path, &apdu->lchan->fs_path);

	if (((apdu->hdr.cla & 0x70) == 0x00) && apdu->hdr.ins == TS_102_221_INS_GET_RESPONSE) {
		/* The GET RESPONSE command is of command case 2 (see also command.h) */
		processed_length = 5;
		apdu->lc = 0;

		/* Handle GET RESPONSE command */
		SS_LOGP(SLCHAN, LDEBUG, "handling GET RESPONSE command...\n");
		last_apdu = apdu->lchan->last_apdu;

		/* Check parameters and abort if no response can be returned */
		if (apdu->hdr.p1 != 0 || apdu->hdr.p2 != 0) {
			apdu->sw = SS_SW_ERR_CHECKING_WRONG_P1_P2;
			apdu->le = 0;
			SS_LOGP(SLCHAN, LERROR, "P1 and P2 must be 0x00 -- abort.\n");
			goto out;
		}
		if (!last_apdu) {
			apdu->sw = SS_SW_ERR_CHECKING_NO_PRECISE_DIAG;
			apdu->le = 0;
			SS_LOGP(SLCHAN, LERROR, "no previous APDU in storage, cannot return any response -- abort.\n");
			goto out;
		}
		if (last_apdu->rsp_len == 0) {
			apdu->rsp_len = 0;
			apdu->sw = SS_SW_ERR_CHECKING_WRONG_LENGTH;
			apdu->le = 0;
			SS_LOGP(SLCHAN, LERROR, "last command did not return any response -- abort.\n");
			goto out;
		}

		/* When more data than available is requested, tell the correct
		 * length of the available data */
		if (apdu->hdr.p3 > last_apdu->rsp_len) {
			assert(last_apdu->rsp_len <= 0xff);
			apdu->sw = 0x6c00 | last_apdu->rsp_len;
			/* We must keep the last APDU so that the terminal has a chance to pick
			 * up the data in a second try. */
			apdu->lchan->last_apdu_keep = true;
			apdu->le = 0;
			SS_LOGP(SLCHAN, LERROR, "incorrect response length requested (%u), expecting %lu\n",
				apdu->hdr.p3, last_apdu->rsp_len);
		} else {
			memcpy(apdu->rsp, last_apdu->rsp, last_apdu->rsp_len);
			apdu->rsp_len = last_apdu->rsp_len;
			apdu->sw = SS_SW_NORMAL_ENDING;
		}
	} else {
		/* Match APDU and execute command handler */
		cmd = ss_command_match(apdu);
		if (cmd) {
			/* Verify properties */
			switch (cmd->case_) {
			case SS_COMMAND_CASE_UNDEF:
				SS_LOGP(SLCHAN, LERROR,
					"Command %s found, but not executing for lack of case definition\n", cmd->name);
				apdu->sw = SS_SW_ERR_CHECKING_INS_INVALID;
				goto out;
			case SS_COMMAND_CASE_1:
				processed_length = 4;
				apdu->lc = 0;
				break;
			case SS_COMMAND_CASE_2:
				/* if processed length is reported by the apdu it was parsed exhaustively and that should take presendence */
				if (!apdu->le && !apdu->processed_bytes) {
					processed_length = 4 + 1;
					apdu->le = apdu->hdr.p3;
				}
				apdu->lc = 0;
				break;
			case SS_COMMAND_CASE_3:
			case SS_COMMAND_CASE_4:

				if (apdu->lc < apdu->hdr.p3) {
					/* Abort here, the handler would treat
					 * p3 as Lc and then peek into
					 * uninitialized memory */
					SS_LOGP(SLCHAN, LERROR, "Insufficient data for Case 3/4 command\n");
					apdu->sw = SS_SW_ERR_CHECKING_WRONG_LENGTH;
					apdu->lc = 0;
					goto out;
				}
				/* if processed length is reported by the apdu it was parsed exhaustively and that should take precedence */
				if (!apdu->processed_bytes) {
					apdu->lc = apdu->hdr.p3;
					processed_length = 4 + 1 + apdu->lc;
				}
				break;
			}

			if (apdu->processed_bytes) {
				processed_length = apdu->processed_bytes;
			}
			SS_LOGP(SLCHAN, LDEBUG, "Command %s is APDU CASE %u => lc=%u, le=%u\n", cmd->name, cmd->case_,
				apdu->lc, apdu->le);

			if (apdu->lc)
				SS_LOGP(SLCHAN, LDEBUG, "Rx C-APDU body %s (%u bytes)\n",
					ss_hexdump(apdu->cmd, apdu->lc), apdu->lc);

			apdu->sw = 0;
			rc = cmd->handler(apdu);

			if (apdu->sw == 0) {
				/* If the handler does not set a status word, we will either
				 * use the rc as SW or set a generic one here,
				 * depending on the handler return code */
				if (rc < 0)
					apdu->sw = SS_SW_ERR_CHECKING_NO_PRECISE_DIAG;
				else if (rc == 0)
					apdu->sw = SS_SW_NORMAL_ENDING;
				else
					apdu->sw = rc;
			}
		} else {
			apdu->sw = SS_SW_ERR_CHECKING_INS_INVALID;
		}
	}

out:
	/* Check result and re-populate the status word if necessary */
	if (apdu->lc) {
		/* if the response is successful, and we have response data, signal
		 * the length via SW=61xx */
		if (apdu->sw == SS_SW_NORMAL_ENDING && apdu->rsp_len) {
			assert(apdu->rsp_len <= 0xff);
			apdu->sw = 0x6100 | apdu->rsp_len;
		}
	} else {
		if (apdu->le == 0) {
			SS_LOGP(SLCHAN, LDEBUG, "Returning rsp_len = %zu bytes after le = 0\n", apdu->rsp_len);
		} else if (apdu->le != apdu->rsp_len) {
			SS_LOGP(SLCHAN, LERROR,
				"invalid response data, le (%u) != rsp_len (%lu), changing SW=%04x to SW=%04x (wrong length)\n",
				apdu->le, apdu->rsp_len, apdu->sw, SS_SW_ERR_CHECKING_WRONG_LENGTH);
			apdu->sw = SS_SW_ERR_CHECKING_WRONG_LENGTH;
			apdu->rsp_len = 0;
		}
	}

	/* Add length of proactive sim data */
	if (ctx->proactive.enabled && apdu->sw == 0x9000 && ctx->proactive.data_len)
		apdu->sw = 0x9100 | ctx->proactive.data_len;

	if (apdu->rsp_len) {
		SS_LOGP(SLCHAN, LDEBUG, "Tx R-APDU SW=%04x %s (%lu bytes)\n", apdu->sw,
			ss_hexdump(apdu->rsp, apdu->rsp_len), apdu->rsp_len);
	} else {
		SS_LOGP(SLCHAN, LDEBUG, "Tx R-APDU SW=%04x\n", apdu->sw);
	}

	if (!ss_sw_is_successful(apdu->sw)
	    /* If the command just fails with "wrong length", it usually didn't change the path */
	    && (apdu->sw >> 8) != 0x6c) {
		SS_LOGP(SLCHAN, LINFO, "Unsuccessful response %04x, restoring backup path.\n", apdu->sw);
		assert(apdu->sw >> 8 != 0x61);
		/* We could apply various levels of smart here:
		 *
		 * - Leave the fs_path alone if it's still on the same file.
		 * - Start restoring at the point where they diverge,and only restore the
		 *   parts that diverged.
		 *
		 * But in the end, this only happens in the error case for which
		 * computation time barely matters.
		 */
		ss_path_reset(&apdu->lchan->fs_path);
		rc = ss_fs_utils_path_select(&apdu->lchan->fs_path, &backup_path);
		if (rc < 0) {
			SS_LOGP(SLCHAN, LERROR, "Failed to restore path.\n");
			/* Not taking any further actions -- the SW is already unsuccessful (with
			 * the original error, which is likely more helpful). The fs_path may now
			 * be in an empty state, which would usually indicate the absence of an
			 * MF, in which case it will fail future access checks (unless the card
			 * was really reset into personalization mode, which is currently not
			 * implemented). */
		}
		if (!ss_list_empty(&apdu->lchan->fs_path))
			ss_access_populate(apdu->lchan);
	}
	ss_path_reset(&backup_path);

	if (apdu->lchan)
		ss_uicc_lchan_dump(apdu->lchan);
	if (ctx->fs_chg_record) {
		SS_LOGP(SLCHAN, LDEBUG, "file changes since last refresh:\n");
		if (ctx->fs_chg_filelist[0] != 0x00)
			ss_fs_chg_dump(ctx->fs_chg_filelist, 1, SLCHAN, LDEBUG);
		else
			SS_LOGP(SLCHAN, LDEBUG, " (none)\n");
	}
	SS_LOGP(SPROACT, LDEBUG, "proactive sim: %s\n", ctx->proactive.enabled ? "active" : "inactive");

	SS_LOGP(SLCHAN, LDEBUG, "------------------------- transaction ended -------------------------\n");
	return processed_length;
}

/*! Perform transaction with UICC.
 *  \param[inout] ctx softsim context.
 *  \param[out] response_buf user provided memory to store the resulting response APDU (at least 2+256 bytes).
 *  \param[in] response_buf_len maxium length of the resulting response APDU.
 *  \param[in] request_buf user provided memory with request APDU.
 *  \param[inout] request_len length of the request APDU.
 *  \returns length of the resulting response APDU. */
size_t ss_transact(struct ss_context *ctx, uint8_t *response_buf, size_t response_buf_len, uint8_t *request_buf,
		   size_t *request_len)
{
	/*! Note: The request_len parameter may indicate a request length
	 *  longer than 5+255 bytes. At return, command_len indicates the true
	 *  number of bytes consumed by the command (which is "all of them"
	 *  in case the command was not known) */

	struct ss_apdu *apdu;
	size_t response_len = 0;
	int processed_length;
	size_t _request_len = *request_len;

	/* A valid APDU must have a length of at least 5 bytes, any shorter
	 * APDU counts as invalid and must not be processed any further. */
	if (_request_len < 5) {
		SS_LOGP(SIFACE, LERROR, "ignoring short APDU: %s\n", ss_hexdump(request_buf, _request_len));
		response_buf[response_len++] = SS_SW_ERR_CHECKING_WRONG_LENGTH >> 8;
		response_buf[response_len++] = SS_SW_ERR_CHECKING_WRONG_LENGTH & 0xff;
		return 2;
	}

	/* A card response can consume up to 255 bytes, it must be ensured that
	 * the response buffer is large enough. */
	assert(response_buf_len >= sizeof(apdu->rsp) + sizeof(apdu->sw));

	/* Limit the request length to the maximum length of an APDU. It is
	 * legal to call this function with a request lengths far longer than
	 * a valid APDU would be. This may be the case when the actual length
	 * of the request is not yet known and the APDUs come in a concatenated
	 * list without delimiters or length information. */
	if (_request_len > sizeof(apdu->cmd) + sizeof(apdu->hdr)) {
		SS_LOGP(SIFACE, LINFO, "request exceeds maximum length %lu > %lu, will truncate.\n", _request_len,
			sizeof(apdu->cmd) + sizeof(apdu->hdr));
		_request_len = sizeof(apdu->cmd) + sizeof(apdu->hdr);
	}

	apdu = ss_apdu_new(ctx);

	/* Parse APDU */
	memcpy(&apdu->hdr, request_buf, sizeof(apdu->hdr));
	memcpy(apdu->cmd, request_buf + sizeof(apdu->hdr), _request_len - sizeof(apdu->hdr));

	/* Note: We cannot determine the apdu->le and apdu->lc fields yet since
	 * those depend on extra knowledge about the command itsself. We will
	 * populate those fields in apdu_transact() when the exact command is
	 * known. */

	/* only way to tell handler how many bytes are at most valid */
	apdu->lc = _request_len - sizeof(apdu->hdr);

	/* Process APDU (softsim) */
	processed_length = apdu_transact(ctx, apdu);
	if (ss_sw_is_successful(apdu->sw)) {
		if (processed_length != _request_len) {
			/* This is not necessarily an error -- on the remote file handling side,
			 * it's pretty much to be expected. */
			SS_LOGP(SIFACE, LINFO, "Processed %d bytes, but request was %zu\n", processed_length,
				*request_len);
		}
		/* The case switch should have caught that already; ensure things fail hard
		 * if we accessed uninitialized memory */
		assert(processed_length <= _request_len);
	}

	/* Return the actual request length back to the caller. */
	if (processed_length >= 0)
		*request_len = processed_length;

	if (apdu->lc == 0) {
		/* no command data present (Case 2), we can return a response */
		memcpy(response_buf, apdu->rsp, apdu->rsp_len);
		response_len = apdu->rsp_len;
	}
	response_buf[response_len++] = apdu->sw >> 8;
	response_buf[response_len++] = apdu->sw & 0xff;

	ss_apdu_toss(apdu);

	return response_len;
}

/*! Perform transaction with UICC on application layer
 *  The APDU is parsed exhaustively and a response is returned i.e. GET RESPONSE is issued automatically
 *  Extended APDU format is supported in this interface
 *  \param[inout] ctx softsim context.
 *  \param[out] response_buf user provided memory to store the resulting response APDU (at least 2+256 bytes).
 *  \param[in] response_buf_len maximum length of the resulting response APDU.
 *  \param[in] request_buf user provided memory with request APDU.
 *  \param[in] request_len length of the request APDU, must not be longer than 5+265 bytes.
 *  \returns length of the resulting response APDU. */
size_t ss_application_apdu_transact(struct ss_context *ctx, uint8_t *response_buf, size_t response_buf_len,
				    uint8_t *request_buf, size_t *request_len)
{
	struct ss_apdu *apdu;
	struct ss_apdu *apdu_orig;
	size_t response_len = 0;
	size_t _request_len = *request_len;
	uint16_t le = 0;

	if (_request_len < 5) {
		SS_LOGP(SIFACE, LERROR, "ignoring short APDU: %s\n", ss_hexdump(request_buf, _request_len));
		response_buf[response_len++] = SS_SW_ERR_CHECKING_WRONG_LENGTH >> 8;
		response_buf[response_len++] = SS_SW_ERR_CHECKING_WRONG_LENGTH & 0xff;
		return 2;
	}

	/* A card response can consume up to 256 bytes, it must be ensured that
	* the response buffer is large enough. */
	assert(response_buf_len >= sizeof(apdu->rsp) + sizeof(apdu->sw));

	if (_request_len > sizeof(apdu->cmd) + sizeof(apdu->hdr)) {
		SS_LOGP(SIFACE, LINFO, "request exceeds maximum length %zu > %zu, will truncate.\n", _request_len,
			sizeof(apdu->cmd) + sizeof(apdu->hdr));
		_request_len = sizeof(apdu->cmd) + sizeof(apdu->hdr);
	}

	apdu = ss_apdu_new(ctx);

	/* note that this parsing assumes that the buffer is a single apdu */
	ss_apdu_parse_exhaustive(apdu, request_buf, _request_len);

	SS_LOGP(SAPDU, LINFO, "Lc: %02X, Le: %04X (%d)\n", apdu->lc, apdu->le, apdu->le);

	do {
		le = apdu->le;
		/* Process APDU (SoftSIM) */
		apdu_transact(ctx, apdu);

		SS_LOGP(SAPDU, LDEBUG, "rsp-len: %zu, sw: %04X \n", apdu->rsp_len, apdu->sw);

		if (apdu->lc == 0) {
			/* no command data present (case 2), we can return a response */
			if (le == apdu->rsp_len) {
				memcpy(response_buf, apdu->rsp, apdu->rsp_len);
				response_len = apdu->rsp_len;
				break;
			}
		}

		/* Wrong length Le */
		if ((apdu->sw >> 8) == 0x6c) {
			SS_LOGP(SAPDU, LINFO, "Requesting correct data len, le=%d\n", apdu->sw & 0xff);
			/* Keep original APDU so we can re-issue it */
			apdu_orig = apdu;

			apdu = ss_apdu_new(ctx);
			apdu->le = apdu_orig->sw & 0xff;
			memcpy(&apdu->hdr, &apdu_orig->hdr, sizeof(apdu->hdr));
			apdu->hdr.p3 = apdu->le;

			memcpy(apdu->cmd, apdu_orig->cmd, sizeof(apdu->cmd));

			ss_apdu_toss(apdu_orig);
		} else if (((apdu->sw >> 8) == 0x61)) {
			/* Response bytes still available - issue a GET cmd in this case */
			SS_LOGP(SAPDU, LINFO, "GET AVAILABLE DATA, le=%d\n", apdu->sw & 0xff);
			apdu_orig = apdu;
			apdu = ss_apdu_new(ctx);

			apdu->le = apdu_orig->sw & 0xff;
			apdu->sw = 0x00;
			apdu->hdr.ins = TS_102_221_INS_GET_RESPONSE;
			apdu->hdr.cla = 0;
			apdu->hdr.p3 = apdu->le;

			ss_apdu_toss(apdu_orig);
		} else {
			SS_LOGP(SAPDU, LDEBUG, "Transaction completed\n");
			break;
		}

	} while (1);

	response_buf[response_len++] = apdu->sw >> 8;
	response_buf[response_len++] = apdu->sw & 0xff;

	ss_apdu_toss(apdu);

	return response_len;
}
