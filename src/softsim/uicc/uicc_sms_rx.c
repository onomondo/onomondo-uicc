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
#include "uicc_sms_rx.h"
#include "uicc_remote_cmd.h"
#include "uicc_ins.h"
#include "uicc_lchan.h"
#include "apdu.h"
#include "context.h"
#include "btlv.h"
#include "tlv8.h"
#include "sms.h"

/* Information element identifier for command packets, as used in TS 23.048
 * V5.9.0 Seciton 6.2 */
#define IEI_CPI 0x70

/* Concatenation cap, overridable at build time. TS 23.040 section 9.2.3.24.1
 * allows up to 255 parts; each buffered part costs sizeof(struct
 * ss_uicc_sms_rx_sm) of heap and the reassembled message up to 140 bytes per
 * part, so a port on a small heap should lower this to what its remote-
 * management traffic actually needs. */
#ifndef SS_SMS_RX_MAX_PARTS
#define SS_SMS_RX_MAX_PARTS 255
#endif

static void clear_state(struct ss_uicc_sms_rx_state *state)
{
	struct ss_uicc_sms_rx_sm *sm;
	struct ss_uicc_sms_rx_sm *sm_pre;

	/* When the number of message parts is set to zero, there is no
	 * multi part SMS reception in progress, wich means we can simply
	 * wipe of all state with zeros. There will be no SMS message in
	 * the list that could leak memory. */
	if (state->msg_parts == 0)
		goto leave;

	SS_LIST_FOR_EACH_SAVE(&state->sm, sm, sm_pre, struct ss_uicc_sms_rx_sm, list) {
		ss_list_remove(&sm->list);
		SS_FREE(sm);
	}

leave:
	memset(state, 0, sizeof(*state));
	ss_list_init(&state->sm);
}

/*! Clear CAT SMS state, needs to be executed once on startup.
 *  \param[inout] ctx softsim context. */
void ss_uicc_sms_rx_clear(struct ss_context *ctx)
{
	struct ss_uicc_sms_rx_state *state = &ctx->proactive.sms_rx_state;
	clear_state(state);
}

/* Get an SM part we have received before from the SM list. */
static struct ss_uicc_sms_rx_sm *get_sm_part(struct ss_uicc_sms_rx_state *state, uint8_t msg_part_no)
{
	struct ss_uicc_sms_rx_sm *sm;
	SS_LIST_FOR_EACH(&state->sm, sm, struct ss_uicc_sms_rx_sm, list) {
		if (sm->msg_part_no == msg_part_no)
			return sm;
	}

	return NULL;
}

/* Put an SM part into SM list for later processing. */
static int put_sm_part(struct ss_uicc_sms_rx_state *state, struct ss_uicc_sms_rx_sm *sm)
{
	struct ss_uicc_sms_rx_sm *sm_i;

	/* Ignore duplicates */
	SS_LIST_FOR_EACH(&state->sm, sm_i, struct ss_uicc_sms_rx_sm, list) {
		if (sm_i->msg_part_no == sm->msg_part_no) {
			SS_LOGP(SSMS, LERROR, "ignoring duplicate part %u/%u of message %u\n", sm->msg_part_no,
				state->msg_parts, sm->msg_id);
			return -EINVAL;
		}
	}

	ss_list_put(&state->sm, &sm->list);
	return 0;
}

/* Collect and when complete concatenate all SM parts to one large SM.
 *
 * On success (return 0), *out_result is set to the reassembled message once
 * the last outstanding part has arrived, and is left NULL while parts are
 * still outstanding. A non-zero return is the SW to report for a part that
 * was rejected outright; *out_result is left NULL in that case too, and any
 * state buffered so far for the message is freed. */
static int concat_sm(struct ss_uicc_sms_rx_state *state, uint8_t *tp_ud, size_t tp_ud_len,
		     struct tlv8_ie *concat_sm_desc_ie, struct ss_list *ud_hdr_dec, struct ss_buf **out_result)
{
	struct ss_uicc_sms_rx_sm *sm;
	uint8_t i;
	size_t result_len = 0;
	struct ss_buf *result;
	uint8_t *result_ptr;
	int rc;
	uint8_t msg_id = concat_sm_desc_ie->value->data[0];
	uint8_t msg_parts = concat_sm_desc_ie->value->data[1];
	uint8_t msg_part_no = concat_sm_desc_ie->value->data[2];

	*out_result = NULL;

	SS_LOGP(SSMS, LERROR, "receiving part %u/%u of message %u: %s\n", msg_part_no, msg_parts, msg_id,
		ss_hexdump(tp_ud, tp_ud_len));

	/* TS 23.040 section 9.2.3.24.1: when the part count is zero, or the
	 * sequence number is zero or exceeds the part count, ignore the IE and
	 * handle the SM as a single short message. */
	if (msg_parts == 0 || msg_part_no == 0 || msg_part_no > msg_parts) {
		SS_LOGP(SSMS, LERROR, "ignoring invalid concatenation IE (part %u/%u), handling as single SM\n",
			msg_part_no, msg_parts);

		/* Mirror handle_single_sm()'s gate: a "single SM" is only a
		 * command packet, and thus only worth handing to handle_sm(),
		 * if its UDH actually carries the CPI IE. TS 23.048 section 6.3
		 * puts no requirement on the order of UDH elements (its own
		 * Table 7 example has the concatenation IE before CPI), so
		 * this looks the IE up by tag rather than checking position 0. */
		if (!ss_tlv8_get_ie(ud_hdr_dec, IEI_CPI)) {
			SS_LOGP(SSMS, LDEBUG, "received sms TP-UD with no CPI IE: %s\n", ss_hexdump(tp_ud, tp_ud_len));
			return -1;
		}

		result = ss_buf_try_alloc(tp_ud_len);
		if (!result) {
			SS_LOGP(SSMS, LERROR, "no memory to copy message (%zu bytes) handled as single SM.\n",
				tp_ud_len);
			return SS_SW_ERR_WRONG_PARAM_ENOMEM;
		}
		memcpy(result->data, tp_ud, tp_ud_len);
		*out_result = result;
		return 0;
	}

	/* Refuse messages the part budget cannot hold: every buffered part
	 * costs heap, so an over-long concatenation from the wire must not be
	 * collected at all. */
	if (msg_parts > SS_SMS_RX_MAX_PARTS) {
		SS_LOGP(SSMS, LERROR, "message %u reports %u parts, refusing to buffer more than %u.\n", msg_id,
			msg_parts, SS_SMS_RX_MAX_PARTS);
		clear_state(state);
		return SS_SW_ERR_WRONG_PARAM_INCORRECT_DATA;
	}

	/* Clear state when a new message is detected */
	if (state->msg_id != msg_id) {
		SS_LOGP(SSMS, LERROR, "message %u is a new message, clearing state.\n", msg_id);
		clear_state(state);
		state->msg_id = msg_id;
		state->msg_parts = msg_parts;
	}

	/* Only part 1 of a concatenated SM carries the CPI IE (TS 23.048). If
	 * it is missing there, this concatenation is not a command packet we
	 * can process, so reject it now rather than buffering parts for a
	 * message that could never complete into anything handle_sm accepts. */
	if (msg_part_no == 1) {
		if (!ss_tlv8_get_ie(ud_hdr_dec, IEI_CPI)) {
			SS_LOGP(SSMS, LDEBUG, "part 1 of message %u has no CPI IE, not a command packet\n", msg_id);
			clear_state(state);
			return SS_SW_ERR_WRONG_PARAM_INCORRECT_DATA;
		}
	}

	/* Make sure that each message reports the same number of message
	 * parts */
	if (msg_parts != state->msg_parts) {
		SS_LOGP(SSMS, LERROR,
			"message part %u of message %u reports invalid number of message parts expected %u, got %u\n",
			msg_part_no, msg_id, state->msg_parts, msg_parts);
		clear_state(state);
		return SS_SW_ERR_WRONG_PARAM_INCORRECT_DATA;
	}

	/* NOTE: In reality, the message cannot be longer than 140 octets,
	 * so we won't see the following error message unless there are
	 * serios software problems elsewhere. */
	if (tp_ud_len > sizeof(sm->tp_ud)) {
		SS_LOGP(SSMS, LERROR,
			"receiving part %u/%u of message %u exceeds size of a normal SMS, expected < %zu octets, got %zu octets.\n",
			msg_part_no, msg_parts, msg_id, sizeof(sm->tp_ud), tp_ud_len);
		return SS_SW_ERR_WRONG_PARAM_INCORRECT_DATA;
	}

	/* Store message in list */
	sm = SS_ALLOC(struct ss_uicc_sms_rx_sm);
	if (!sm) {
		SS_LOGP(SSMS, LERROR, "no memory to buffer part %u/%u of message %u, dropping message.\n", msg_part_no,
			msg_parts, msg_id);
		clear_state(state);
		return SS_SW_ERR_WRONG_PARAM_ENOMEM;
	}
	memcpy(sm->tp_ud, tp_ud, tp_ud_len);
	sm->tp_ud_len = tp_ud_len;
	sm->msg_part_no = msg_part_no;
	sm->msg_id = msg_id;
	rc = put_sm_part(state, sm);
	if (rc < 0) {
		/* Duplicate part: harmless, ignore it and keep waiting for the
		 * parts still missing. */
		SS_FREE(sm);
		return 0;
	}

	/* Check if we got the complete message */
	for (i = 0; i < msg_parts; i++) {
		sm = get_sm_part(state, i + 1);
		if (!sm) {
			SS_LOGP(SSMS, LDEBUG, "message %u is not complete yet, still waiting for message part %u/%u.\n",
				msg_id, msg_parts, i + 1);
			return 0;
		}

		result_len += sm->tp_ud_len;
	}

	/* Concatenate message */
	result = ss_buf_try_alloc(result_len);
	if (!result) {
		SS_LOGP(SSMS, LERROR, "no memory to reassemble message %u (%zu bytes), dropping message.\n", msg_id,
			result_len);
		clear_state(state);
		return SS_SW_ERR_WRONG_PARAM_ENOMEM;
	}
	result_ptr = result->data;
	for (i = 0; i < msg_parts; i++) {
		sm = get_sm_part(state, i + 1);
		if (!sm)
			assert(false);
		if (sm->msg_id != msg_id)
			assert(false);
		memcpy(result_ptr, sm->tp_ud, sm->tp_ud_len);
		result_ptr += sm->tp_ud_len;
	}

	SS_LOGP(SSMS, LDEBUG, "message %u complete: %s\n", msg_id, ss_hexdump(result->data, result->len));
	clear_state(state);
	*out_result = result;
	return 0;
}

/* Process the tp_ud data of a command packet (IEI_CPI) we have received from
 * either a single SM or multiple concatenated delivered SMs. The caller is
 * responsible for confirming the CPI IE was present before calling this.
 *
 * The response arguments behave like those of @ref ss_uicc_sms_rx.
 * */
static int handle_sm(struct ss_context *ctx, struct ss_sm_hdr *sm_hdr, uint8_t *tp_ud, size_t tp_ud_len,
		     size_t *response_len, uint8_t response[*response_len])
{
#ifdef CONFIG_DISABLE_OTA
	(void)ctx;
	(void)sm_hdr;
	(void)response_len;
	(void)response;

	SS_LOGP(SSMS, LDEBUG, "received sms command packet but OTA is compiled out:%s\n", ss_hexdump(tp_ud, tp_ud_len));
	return -1;
#else
	int rc;
	struct ss_buf *sms_response = NULL;

	assert(sm_hdr->tp_mti == SMS_MTI_DELIVER);

	rc = ss_uicc_remote_cmd_receive(tp_ud_len, tp_ud, response_len, response, &sms_response, ctx->fs_chg_filelist);

	if (sms_response != NULL) {
		struct ss_sm_hdr response_hdr;
		memset(&response_hdr, 0, sizeof(response_hdr));

		response_hdr.tp_mti = SMS_MTI_SUBMIT;
		response_hdr.u.sms_submit.tp_da.extension = true;
		memcpy(&response_hdr.u.sms_submit.tp_da, &sm_hdr->u.sms_deliver.tp_oa, sizeof(struct ss_sms_addr));
		/* TP-Protocol-Identifier: unsure */
		response_hdr.u.sms_submit.tp_pid = 127;
		/* data coding scheme: 8-bit data */
		response_hdr.u.sms_submit.tp_dcs = 246;
		/* UDHI gets set automatically when encode_sm gets its hands on it */

		ss_uicc_sms_tx(ctx, &response_hdr,
			       /* The response is a single blob with both UDH and UD, which makes
                * sense there as that's part of what gets integrity protected, but as
			        * sms_tx needs to fragment it, we're dissecting the message for it */
			       &sms_response->data[1], sms_response->data[0],
			       &sms_response->data[1 + sms_response->data[0]],
			       sms_response->len - 1 - sms_response->data[0],
			       /* Couldn't do anything else than debug logging */
			       NULL);
		SS_LOGP(SSMS, LDEBUG, "Enqueued SMS in response to command\n");
		ss_buf_free(sms_response);
	}

	return rc;
#endif // CONFIG_DISABLE_OTA
}

/* Check a single (non-concatenated) SM for the CPI IE and, if present, hand
 * it to handle_sm().
 *
 * The response arguments behave like those of @ref ss_uicc_sms_rx. */
static int handle_single_sm(struct ss_context *ctx, struct ss_sm_hdr *sm_hdr, struct ss_list *ud_hdr_dec,
			    uint8_t *tp_ud, size_t tp_ud_len, size_t *response_len, uint8_t response[*response_len])
{
	if (!ss_tlv8_get_ie(ud_hdr_dec, IEI_CPI)) {
		SS_LOGP(SSMS, LDEBUG, "received sms TP-UD with no CPI IE: %s\n", ss_hexdump(tp_ud, tp_ud_len));
		return -1;
	}

	return handle_sm(ctx, sm_hdr, tp_ud, tp_ud_len, response_len, response);
}

/*! Receive an SM.
 *  \param[inout] ctx softsim context.
 *  \param[in] data encoded SM.
 *  \param[inout] response_len Pointer to what is initially the maximum size of
 *      response; changed to the filled size on 0 (successul) returns.
 *  \param[out] response Buffer in which a response to the envelope command in
 *      which the SMS-PP download arrived.
 *  \returns ISO7816 SW or 0 on success. */
int ss_uicc_sms_rx(struct ss_context *ctx, struct ss_buf *sms_tpdu, size_t *response_len,
		   uint8_t response[*response_len])
{
	struct ss_uicc_sms_rx_state *state = &ctx->proactive.sms_rx_state;

	int rc = 0;
	struct ss_sm_hdr sm_hdr;
	int sm_hdr_len;

	uint8_t *tp_ud;
	size_t tp_ud_len;

	uint8_t *ud_hdr = NULL;
	size_t ud_hdr_len = 0;

	struct ss_list *ud_hdr_dec = NULL;
	struct tlv8_ie *concat_sm_desc_ie = NULL;
	struct ss_buf *concat_sm_buf;

	sm_hdr_len = ss_sms_hdr_decode(&sm_hdr, sms_tpdu->data, sms_tpdu->len);
	if (sm_hdr_len < 0) {
		SS_LOGP(SSMS, LERROR, "failed to decode SMS TPDU header.\n");
		*response_len = 0;
		goto leave;
	}
	assert(sm_hdr_len <= sms_tpdu->len);

	switch (sm_hdr.tp_mti) {
	case SMS_MTI_DELIVER:
		tp_ud = sms_tpdu->data + sm_hdr_len;
		tp_ud_len = sms_tpdu->len - sm_hdr_len;
		if (sm_hdr.u.sms_deliver.tp_udhi) {
			if (tp_ud[0] + 1 <= tp_ud_len) {
				ud_hdr = tp_ud + 1;
				ud_hdr_len = tp_ud[0];

				SS_LOGP(SSMS, LDEBUG, "received sms TP-UD header: %s\n",
					ss_hexdump(ud_hdr, ud_hdr_len));
				ud_hdr_dec = ss_tlv8_decode(ud_hdr, ud_hdr_len);
				if (!ud_hdr_dec) {
					SS_LOGP(SSMS, LERROR, "failed to decode user data header, invalid TLV data\n");
					*response_len = 0;
					goto leave;
				}
				ss_tlv8_dump(ud_hdr_dec, 2, SSMS, LDEBUG);

				/* Advance pointers to actual user data */
				tp_ud_len -= 1 + tp_ud[0];
				tp_ud += 1 + tp_ud[0];

				/* Part of a concatencated SM received, collect partial messages */
				concat_sm_desc_ie = ss_tlv8_get_ie_minlen(ud_hdr_dec, TS_23_040_IEI_CONCAT_SMS, 3);
				if (concat_sm_desc_ie) {
					rc = concat_sm(state, tp_ud, tp_ud_len, concat_sm_desc_ie, ud_hdr_dec,
						       &concat_sm_buf);
					if (rc != 0) {
						*response_len = 0;
					} else if (concat_sm_buf) {
						rc = handle_sm(ctx, &sm_hdr, concat_sm_buf->data, concat_sm_buf->len,
							       response_len, response);
						ss_buf_free(concat_sm_buf);
						if (rc < 0)
							*response_len = 0;
					} else {
						/* Part accepted and buffered, message still incomplete:
						 * no response data of our own to report yet. */
						*response_len = 0;
					}
				}

			} else {
				SS_LOGP(SSMS, LERROR,
					"failed to decode user data header, length field exceeds TP-UD length\n");
				rc = SS_SW_ERR_WRONG_PARAM_INCORRECT_DATA;
				*response_len = 0;
				goto leave;
			}
		}

		/* Normal SM received, forward directly */
		if (!concat_sm_desc_ie) {
			SS_LOGP(SSMS, LDEBUG, "received sms TP-UD: %s\n", ss_hexdump(tp_ud, tp_ud_len));
			rc = handle_single_sm(ctx, &sm_hdr, ud_hdr_dec, tp_ud, tp_ud_len, response_len, response);
			if (rc < 0)
				*response_len = 0;
		}
		break;
	default:
		SS_LOGP(SSMS, LINFO, "Unspported SMS message type (%u) received -- ignored!\n", sm_hdr.tp_mti & 0x03);
		*response_len = 0;
		break;
	}

leave:
	ss_tlv8_free(ud_hdr_dec);
	return rc;
}
