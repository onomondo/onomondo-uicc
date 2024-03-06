/*
 * Copyright (c) 2024 Onomondo ApS. All rights reserved.
 * 
 * SPDX-License-Identifier: GPL-3.0-only 
 */

#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <errno.h>
#include <onomondo/softsim/log.h>
#include <onomondo/softsim/utils.h>
#include "sw.h"
#include "command.h"
#include "uicc_cat.h"
#include "uicc_sms_tx.h"
#include "uicc_ins.h"
#include "uicc_lchan.h"
#include "apdu.h"
#include "context.h"
#include "btlv.h"
#include "ctlv.h"
#include "tlv8.h"
#include "sms.h"
#include "uicc_sms_tx.h"

/* Check if the TERMINAL PROFILE supports sending of short messages */
static bool check_cat_support(struct ss_context *ctx)
{
	/* See also ETSI TS 102 223, section 5.2
	   and/or ETSI TS 131 111 section 5.2 */

	/* SMS-PP data download */
	if (!ss_proactive_term_prof_bit(ctx, 1, 2))
		return false;

	/* Bit = 1 if SMS-PP data download is supported */
	if (!ss_proactive_term_prof_bit(ctx, 1, 5))
		return false;

	/* Proactive UICC: SEND SHORT MESSAGE */
	if (!ss_proactive_term_prof_bit(ctx, 4, 2))
		return false;

	return true;
}

static void clear_state(struct ss_uicc_sms_tx_state *state)
{
	struct ss_uicc_sms_tx_sm *sm;
	struct ss_uicc_sms_tx_sm *sm_pre;

	if (!ss_list_initialized(&state->sm))
		goto leave;

	SS_LIST_FOR_EACH_SAVE(&state->sm, sm, sm_pre, struct ss_uicc_sms_tx_sm, list) {
		ss_list_remove(&sm->list);
		SS_FREE(sm);
	}

leave:
	memset(state, 0, sizeof(*state));
	ss_list_init(&state->sm);
}

/*! Clear CAT SMS state, needs to be executed once on startup.
 *  \param[inout] ctx softsim context. */
void ss_uicc_sms_tx_clear(struct ss_context *ctx)
{
	struct ss_uicc_sms_tx_state *state = &ctx->proactive.sms_tx_state;
	clear_state(state);
}

/* Encode a single short message TPDU */
int encode_sm(uint8_t *sm_enc, size_t sm_enc_len, const struct ss_sm_hdr *sm_hdr, const uint8_t *ud_hdr,
	      size_t ud_hdr_len, const uint8_t *tp_ud, size_t tp_ud_len, bool recalc_tp_udl)
{
	int rc;
	size_t bytes_used = 0;
	uint8_t *tp_udl = NULL;
	uint8_t tp_dcs;
	struct ss_sm_hdr _sm_hdr;
	struct ss_sm_hdr *sm_hdr_copy = &_sm_hdr;

	/* Note: the data for ud_hdr must not contain the length field at its
	 * beginning. The length is prepended automatically by this function. */

	/* Note: the parameter tp_ud can also be tp_cd in case an SMS-COMMAND
	 * message is sent. */

	/* In cases where the tp_udl value in the header struct is not
	 * populated we will fill in this value automatically with a calculated
	 * result. This currently works only for messages that use the
	 * "Data coding/message class" with 8 bit data message coding.
	 * See also: 3GPP TS 23.038, section 4. */

	/* The SM header may be subject to change, so we create a local copy to
	 * avoid side effects. */
	memcpy(sm_hdr_copy, sm_hdr, sizeof(*sm_hdr_copy));

	switch (sm_hdr_copy->tp_mti) {
	case SMS_MTI_DELIVER_REPORT:
		tp_udl = &sm_hdr_copy->u.sms_deliver.tp_udl;
		tp_dcs = sm_hdr_copy->u.sms_deliver.tp_dcs;
		break;
	case SMS_MTI_SUBMIT:
		tp_udl = &sm_hdr_copy->u.sms_submit.tp_udl;
		tp_dcs = sm_hdr_copy->u.sms_submit.tp_dcs;
		break;
	case SMS_MTI_COMMAND:
		tp_udl = &sm_hdr_copy->u.sms_command.tp_cdl;
		tp_dcs = 0xff; /* not applicable */
		break;
	default:
		SS_LOGP(SSMS, LERROR, "failed to encode incompatible SMS-TPDU (tp-mti=%02x)\n",
			sm_hdr_copy->tp_mti & 3);
		return -EINVAL;
	}
	if ((tp_ud_len || ud_hdr_len) && (*tp_udl == 0 || recalc_tp_udl)) {
		if ((tp_dcs & 0xF4) != 0xF4) {
			SS_LOGP(SSMS, LERROR,
				"failed to encode message with incompatible data coding scheme (tp-dcs=%02x)\n",
				tp_dcs);
			return -EINVAL;
		}
		/* A user data header needs one byte length field + the actual
		 * header data. */
		if (ud_hdr && ud_hdr_len)
			*tp_udl = (uint8_t)(1 + ud_hdr_len);

		/* Add the length of the actual user data (this only works for
		 * 8 bit encoding, see error message above) */
		if (tp_ud && tp_ud_len)
			*tp_udl += (uint8_t)tp_ud_len;

		SS_LOGP(SSMS, LINFO, "using calculated value for tp_udl=%u (8 bit encoding)\n", *tp_udl);
	}

	/* Ensure that the User Data Header Indicator is set in case a user
	 * data header is present */
	if (ud_hdr && ud_hdr_len > 0) {
		switch (sm_hdr_copy->tp_mti) {
		case SMS_MTI_DELIVER_REPORT:
			sm_hdr_copy->u.sms_deliver.tp_udhi = true;
			break;
		case SMS_MTI_SUBMIT:
			sm_hdr_copy->u.sms_submit.tp_udhi = true;
			break;
		case SMS_MTI_COMMAND:
			sm_hdr_copy->u.sms_command.tp_udhi = true;
			break;
		default:
			SS_LOGP(SSMS, LERROR, "failed to encode incompatible SMS-TPDU (tp-mti=%02x)\n",
				sm_hdr_copy->tp_mti & 3);
			return -EINVAL;
		}
	}

	/* Encode header */
	rc = ss_sms_hdr_encode(sm_enc, sm_enc_len, sm_hdr_copy);
	if (rc < 0) {
		SS_LOGP(SSMS, LERROR, "failed to encode SMS-TPDU header.\n");
		return -EINVAL;
	}
	sm_enc_len -= rc;
	sm_enc += rc;
	bytes_used += rc;

	/* Copy user data header (if present) */
	if (ud_hdr && ud_hdr_len > 0) {
		if (sm_enc_len < ud_hdr_len + 1) {
			SS_LOGP(SSMS, LERROR, "failed to encode SMS-TPDU, no space to fit user data header\n");
			return -EINVAL;
		}

		if (ud_hdr_len > 254) {
			SS_LOGP(SSMS, LERROR, "failed to encode SMS-TPDU, data header too large\n");
			return -EINVAL;
		}

		/* Prepend user data header length */
		sm_enc[0] = (uint8_t)ud_hdr_len;
		sm_enc_len -= 1;
		sm_enc += 1;
		bytes_used += 1;

		/* Copy user data header data */
		memcpy(sm_enc, ud_hdr, ud_hdr_len);
		sm_enc_len -= ud_hdr_len;
		sm_enc += ud_hdr_len;
		bytes_used += ud_hdr_len;
	}

	/* Copy user data (if present) */
	if (tp_ud && tp_ud_len > 0) {
		if (sm_enc_len < tp_ud_len) {
			SS_LOGP(SSMS, LERROR, "failed to encode SMS-TPDU, no space to fit user data\n");
			return -EINVAL;
		}
		memcpy(sm_enc, tp_ud, tp_ud_len);
		sm_enc_len -= tp_ud_len;
		sm_enc += tp_ud_len;
		bytes_used += tp_ud_len;
	}

	return bytes_used;
}

static int sms_tx_single(struct ss_uicc_sms_tx_state *state, const struct ss_sm_hdr *sm_hdr, const uint8_t *ud_hdr,
			 size_t ud_hdr_len, const uint8_t *tp_ud, size_t tp_ud_len, sms_result_cb sms_result_cb,
			 bool last_msg, uint8_t msg_id, bool recalc_tp_udl)
{
	struct ss_uicc_sms_tx_sm *sm;
	int rc;

	/* Initialize queue in case it hasn't been initialized yet */
	if (!ss_list_initialized(&state->sm))
		clear_state(state);

	/* Encode and Enqueue SMS TPDU */
	sm = SS_ALLOC(struct ss_uicc_sms_tx_sm);
	rc = encode_sm(sm->msg, sizeof(sm->msg), sm_hdr, ud_hdr, ud_hdr_len, tp_ud, tp_ud_len, recalc_tp_udl);
	if (rc < 0) {
		SS_FREE(sm);
		SS_LOGP(SSMS, LERROR, "error encoding SMS-TPDU - tossed!\n");
		return -EINVAL;
	}
	sm->msg_len = rc;
	sm->sms_result_cb = sms_result_cb;
	sm->last_msg = last_msg;
	sm->msg_id = msg_id;
	SS_LOGP(SSMS, LINFO, "enqueueing SMS-TPDU: %s\n", ss_hexdump(sm->msg, sm->msg_len));
	ss_list_put(&state->sm, &sm->list);

	return 0;
}

/* Calculate the number of message parts that will be needed */
static uint8_t calc_message_parts(size_t ud_hdr_len, size_t tp_ud_len)
{
	size_t total_len;
	size_t result;

	total_len = ud_hdr_len + tp_ud_len;

	/* 5 byte (concat_sm_descr IE) + 1 byte user data header length field
	 * will be subtracted from the overall useful bytes of the SM
	 * (SMS_MAX_SIZE) */

	result = total_len / (SMS_MAX_SIZE - 6);
	if (total_len % (SMS_MAX_SIZE - 6))
		result++;

	if (result > 0xff) {
		SS_LOGP(SSMS, LERROR, "message too large!\n");
		return 0;
	}

	return (uint8_t)result;
}

/* Remove all messages with a specified message id from the queue. This is
 * usually done to remove already scheduled parts of a concatenated SM from
 * the queue in case there is an error while generating and enqueing the
 * partial messages. */
void cancel_sm(struct ss_uicc_sms_tx_state *state, uint8_t msg_id)
{
	struct ss_uicc_sms_tx_sm *sm;
	struct ss_uicc_sms_tx_sm *sm_pre;

	if (!ss_list_initialized(&state->sm))
		return;

	SS_LIST_FOR_EACH_SAVE(&state->sm, sm, sm_pre, struct ss_uicc_sms_tx_sm, list) {
		if (sm->msg_id == msg_id) {
			SS_LOGP(SSMS, LINFO, "canceling pending SMS-TPDU: %s\n", ss_hexdump(sm->msg, sm->msg_len));
			ss_list_remove(&sm->list);
			SS_FREE(sm);
		}
	}
}

/*! Send an SM.
 *  \param[inout] ctx softsim context.
 *  \param[inout] sm_hdr user provided memory with SMS TPDU header struct.
 *  \param[in] ud_hdr user provided memory with user data header (encoded).
 *  \param[in] ud_hdr_len user data header length.
 *  \param[in] tp_ud user provided memory with user data.
 *  \param[in] tp_ud_len user data length.
 *  \param[in] ms_rsult_cb callback to inform caller about the outcome.
 *  \returns ISO7816 SW or 0 on success. */
int ss_uicc_sms_tx(struct ss_context *ctx, struct ss_sm_hdr *sm_hdr, uint8_t *ud_hdr, size_t ud_hdr_len, uint8_t *tp_ud,
		   size_t tp_ud_len, sms_result_cb sms_result_cb)
{
	struct ss_uicc_sms_tx_state *state = &ctx->proactive.sms_tx_state;

	uint8_t concat_sm_descr[5];
	uint8_t msg_parts;
	uint8_t i;
	uint8_t ud_hdr_buf[SMS_MAX_SIZE];
	size_t ud_hdr_buf_len;
	int rc;
	size_t tp_ud_len_window;
	uint8_t *tp_ud_ptr;

	state->msg_id++;

	/* Check if user data and user data header will fit in a single SM. */
	if (ud_hdr_len + 1 + tp_ud_len <= SMS_MAX_SIZE) {
		rc = sms_tx_single(state, sm_hdr, ud_hdr, ud_hdr_len, tp_ud, tp_ud_len, sms_result_cb, true,
				   state->msg_id, false);

		/* Give the SMS a chance to go out immediately */
		ss_uicc_sms_tx_poll(ctx);
		return rc;
	}

	/* Split up, encode and enqueue the message */
	msg_parts = calc_message_parts(ud_hdr_len, tp_ud_len);
	concat_sm_descr[0] = TS_23_040_IEI_CONCAT_SMS;
	concat_sm_descr[1] = 0x03;
	concat_sm_descr[2] = state->msg_id;
	concat_sm_descr[3] = msg_parts;
	tp_ud_ptr = tp_ud;
	SS_LOGP(SSMS, LINFO, "user data too large for a single SM, splitting into %u separate SMs, message id is: %u\n",
		msg_parts, state->msg_id);
	for (i = 1; i <= msg_parts; i++) {
		concat_sm_descr[4] = i;

		/* Copy the user data header with concat SM descriptor IE */
		memcpy(ud_hdr_buf, concat_sm_descr, sizeof(concat_sm_descr));
		ud_hdr_buf_len = sizeof(concat_sm_descr);

		/* Copy the user data header part that the caller has
		 * specified, but only in the first message. */
		if (ud_hdr && ud_hdr_len > 0) {
			memcpy(ud_hdr_buf + ud_hdr_buf_len, ud_hdr, ud_hdr_len);
			ud_hdr_buf_len += ud_hdr_len;
			ud_hdr_len = 0;
			ud_hdr = NULL;
		}

		/* Calculate window size. This will be the user data header
		 * length (including its length byte) minus the maximum useful
		 * byte size of an SM in all cases ecept for the last message,
		 * where the remainder of the message is sent. */
		if (i == msg_parts)
			tp_ud_len_window = tp_ud_len - (tp_ud_ptr - tp_ud);
		else
			tp_ud_len_window = SMS_MAX_SIZE - ud_hdr_buf_len - 1;

		/* Enqueue message and point tp_ud_ptr to the beginning of the
		 * user data window that is transmitted with the next turn. */
		rc = sms_tx_single(state, sm_hdr, ud_hdr_buf, ud_hdr_buf_len, tp_ud_ptr, tp_ud_len_window,
				   sms_result_cb, (i == msg_parts), state->msg_id, true);
		if (rc < 0) {
			SS_LOGP(SSMS, LERROR, "unable to send part %u/%u of message %u!\n", i, msg_parts,
				state->msg_id);
			cancel_sm(state, state->msg_id);
			return -EINVAL;
		}

		tp_ud_ptr += tp_ud_len_window;
	}

	/* Give the SMS a chance to go out immediately */
	ss_uicc_sms_tx_poll(ctx);

	return 0;
}

/* Handle terminal response */
static void term_response_cb(struct ss_context *ctx, uint8_t *resp_data, uint8_t resp_data_len)
{
	int rc;
	rc = ss_proactive_get_rc(resp_data, resp_data_len, SSMS);

	if (ctx->proactive.sms_tx_state.sms_result_cb) {
		/* Note: When sending was successful we only report the success
		 * back to the caller when the last message is done. Contrary
		 * to that, errors are reported back immediately. */
		if (rc == 0 && ctx->proactive.sms_tx_state.last_msg)
			ctx->proactive.sms_tx_state.sms_result_cb(ctx, 0);
		else if (rc != 0)
			ctx->proactive.sms_tx_state.sms_result_cb(ctx, -EINVAL);
	}

	ctx->proactive.sms_tx_state.sms_result_cb = NULL;
	ctx->proactive.sms_tx_state.pending = false;
	ctx->proactive.sms_tx_state.last_msg = false;

	/* Give any additional queued SMSs a chance to go out */
	ss_uicc_sms_tx_poll(ctx);
}

/* Pick pending SM from queue */
static struct ss_uicc_sms_tx_sm *pick_sm(struct ss_uicc_sms_tx_state *state)
{
	struct ss_uicc_sms_tx_sm *sm;

	if (!ss_list_initialized(&state->sm))
		return NULL;
	if (ss_list_empty(&state->sm))
		return NULL;

	sm = SS_LIST_GET(state->sm.next, struct ss_uicc_sms_tx_sm, list);
	SS_LOGP(SSMS, LINFO, "dequeueing SMS-TPDU: %s\n", ss_hexdump(sm->msg, sm->msg_len));
	ss_list_remove(&sm->list);

	return sm;
}

void ss_uicc_sms_tx_poll(struct ss_context *ctx)
{
	struct ss_uicc_sms_tx_sm *sm;
	uint8_t cmd_sms[] = { 0x80 | TS_101_220_IEI_CMD_DETAILS, 0x03, 0x01, TS_102_223_TOC_SEND_SHORT_MESSAGE, 0x00,
			      /* Device identities: From UICC to network is the only combination allowed
		 * for Send Short Message per TS 102 223 V4.4.0 Section 10 */
			      0x80 | TS_101_220_IEI_DEV_ID, 0x02, 0x81, 0x83, 0x80 | TS_101_220_IEI_SMS_TPDU };
	/* 2 for length; at most 2 bytes as SMS are limited in length */
	uint8_t cmd[sizeof(cmd_sms) + 2 + sizeof(sm->msg)];
	uint8_t *cmd_ptr = cmd;
	int rc;

	if (ctx->proactive.sms_tx_state.pending) {
		SS_LOGP(SSMS, LINFO, "pending SM not yet sent, skipping...\n");
		return;
	}

	if (!ss_proactive_rts(ctx)) {
		SS_LOGP(SSMS, LINFO, "another proactive command is still pending, skipping...\n");
		return;
	}

	sm = pick_sm(&ctx->proactive.sms_tx_state);
	if (sm) {
		memcpy(cmd_ptr, cmd_sms, sizeof(cmd_sms));
		cmd_ptr += sizeof(cmd_sms);
		assert(sm->msg_len <= 255);
		if (sm->msg_len > 127) {
			*cmd_ptr = 0x81;
			cmd_ptr++;
			*cmd_ptr = sm->msg_len;
			cmd_ptr++;
		} else {
			*cmd_ptr = (uint8_t)sm->msg_len;
			cmd_ptr++;
		}
		memcpy(cmd_ptr, sm->msg, sm->msg_len);
		cmd_ptr += sm->msg_len;

		SS_LOGP(SSMS, LINFO, "sending CAT command with SMS-TPDU: %s\n", ss_hexdump(cmd, cmd_ptr - cmd));

		if (check_cat_support(ctx)) {
			rc = ss_proactive_put(ctx, term_response_cb, cmd, cmd_ptr - cmd);
		} else {
			SS_LOGP(SSMS, LERROR,
				"cannot send, TERMINAL PROFILE does not support sending of short messages!\n");
			rc = -EINVAL;
		}

		if (rc < 0) {
			SS_LOGP(SSMS, LERROR, "error sending CAT command - SMS-TPDU tossed!\n");
			if (sm->sms_result_cb)
				sm->sms_result_cb(ctx, -EINVAL);
			ctx->proactive.sms_tx_state.sms_result_cb = NULL;
		} else {
			ctx->proactive.sms_tx_state.sms_result_cb = sm->sms_result_cb;
			ctx->proactive.sms_tx_state.pending = true;
			ctx->proactive.sms_tx_state.last_msg = sm->last_msg;
		}
		SS_FREE(sm);
	}
}
