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

#define SMS_RX_MAX_REASSEMBLIES 4
#define SMS_RX_MAX_REASSEMBLED_LEN (SMS_MAX_SIZE * 255)

struct ss_uicc_sms_rx_sm {
	struct ss_list list;
	uint8_t msg_part_no;
	uint8_t tp_ud[SMS_MAX_SIZE];
	size_t tp_ud_len;
};

struct ss_uicc_sms_rx_reassembly {
	struct ss_list list;
	struct ss_list sm;
	struct ss_sms_addr tp_oa;
	uint8_t tp_pid;
	uint8_t tp_dcs;
	bool concat_ref_16bit;
	uint16_t concat_ref;
	uint8_t msg_parts;
	uint8_t msg_parts_received;
	size_t tp_ud_len;
	bool ud_hdr_set;
	uint8_t ud_hdr[SMS_MAX_SIZE];
	size_t ud_hdr_len;
};

struct sms_rx_udh_info {
	bool concat_present;
	bool concat_ref_16bit;
	uint16_t concat_ref;
	uint8_t msg_parts;
	uint8_t msg_part_no;
	uint8_t ud_hdr[SMS_MAX_SIZE];
	size_t ud_hdr_len;
};

static void init_state_if_needed(struct ss_uicc_sms_rx_state *state)
{
	if (!ss_list_initialized(&state->reassemblies))
		ss_list_init(&state->reassemblies);
}

static void free_reassembly(struct ss_uicc_sms_rx_reassembly *reassembly)
{
	struct ss_uicc_sms_rx_sm *sm;
	struct ss_uicc_sms_rx_sm *sm_pre;

	if (ss_list_initialized(&reassembly->sm)) {
		SS_LIST_FOR_EACH_SAVE(&reassembly->sm, sm, sm_pre, struct ss_uicc_sms_rx_sm, list) {
			ss_list_remove(&sm->list);
			SS_FREE(sm);
		}
	}

	memset(reassembly, 0, sizeof(*reassembly));
	SS_FREE(reassembly);
}

static void clear_state(struct ss_uicc_sms_rx_state *state)
{
	struct ss_uicc_sms_rx_reassembly *reassembly;
	struct ss_uicc_sms_rx_reassembly *reassembly_pre;

	if (ss_list_initialized(&state->reassemblies)) {
		SS_LIST_FOR_EACH_SAVE(&state->reassemblies, reassembly, reassembly_pre,
				      struct ss_uicc_sms_rx_reassembly, list) {
			ss_list_remove(&reassembly->list);
			free_reassembly(reassembly);
		}
	}

	memset(state, 0, sizeof(*state));
	ss_list_init(&state->reassemblies);
}

/*! Clear CAT SMS state, needs to be executed once on startup.
 *  \param[inout] ctx softsim context. */
void ss_uicc_sms_rx_clear(struct ss_context *ctx)
{
	struct ss_uicc_sms_rx_state *state = &ctx->proactive.sms_rx_state;
	clear_state(state);
}

static bool sms_addr_equal(const struct ss_sms_addr *a, const struct ss_sms_addr *b)
{
	return a->extension == b->extension && a->type_of_number == b->type_of_number &&
	       a->numbering_plan == b->numbering_plan && strcmp(a->digits, b->digits) == 0;
}

static bool reassembly_matches(const struct ss_uicc_sms_rx_reassembly *reassembly, const struct ss_sm_hdr *sm_hdr,
			       const struct sms_rx_udh_info *udh_info)
{
	const struct ss_sms_deliver *sms_deliver = &sm_hdr->u.sms_deliver;

	return sms_addr_equal(&reassembly->tp_oa, &sms_deliver->tp_oa) &&
	       reassembly->tp_pid == sms_deliver->tp_pid && reassembly->tp_dcs == sms_deliver->tp_dcs &&
	       reassembly->concat_ref_16bit == udh_info->concat_ref_16bit &&
	       reassembly->concat_ref == udh_info->concat_ref && reassembly->msg_parts == udh_info->msg_parts;
}

static struct ss_uicc_sms_rx_reassembly *find_reassembly(struct ss_uicc_sms_rx_state *state,
							 const struct ss_sm_hdr *sm_hdr,
							 const struct sms_rx_udh_info *udh_info)
{
	struct ss_uicc_sms_rx_reassembly *reassembly;

	init_state_if_needed(state);
	SS_LIST_FOR_EACH(&state->reassemblies, reassembly, struct ss_uicc_sms_rx_reassembly, list) {
		if (reassembly_matches(reassembly, sm_hdr, udh_info))
			return reassembly;
	}

	return NULL;
}

static struct ss_uicc_sms_rx_sm *get_sm_part(struct ss_uicc_sms_rx_reassembly *reassembly, uint8_t msg_part_no)
{
	struct ss_uicc_sms_rx_sm *sm;
	SS_LIST_FOR_EACH(&reassembly->sm, sm, struct ss_uicc_sms_rx_sm, list) {
		if (sm->msg_part_no == msg_part_no)
			return sm;
	}

	return NULL;
}

static void remove_reassembly(struct ss_uicc_sms_rx_state *state, struct ss_uicc_sms_rx_reassembly *reassembly)
{
	ss_list_remove(&reassembly->list);
	assert(state->reassembly_count > 0);
	state->reassembly_count--;
	free_reassembly(reassembly);
}

static void evict_oldest_reassembly(struct ss_uicc_sms_rx_state *state)
{
	struct ss_uicc_sms_rx_reassembly *reassembly;

	if (ss_list_empty(&state->reassemblies))
		return;

	reassembly = SS_LIST_GET(state->reassemblies.next, struct ss_uicc_sms_rx_reassembly, list);
	SS_LOGP(SSMS, LERROR, "evicting incomplete concatenated SM ref=%u (%u-bit), received %u/%u parts\n",
		reassembly->concat_ref, reassembly->concat_ref_16bit ? 16 : 8, reassembly->msg_parts_received,
		reassembly->msg_parts);
	remove_reassembly(state, reassembly);
}

static struct ss_uicc_sms_rx_reassembly *new_reassembly(struct ss_uicc_sms_rx_state *state,
							const struct ss_sm_hdr *sm_hdr,
							const struct sms_rx_udh_info *udh_info)
{
	struct ss_uicc_sms_rx_reassembly *reassembly;
	const struct ss_sms_deliver *sms_deliver = &sm_hdr->u.sms_deliver;

	init_state_if_needed(state);
	if (state->reassembly_count >= SMS_RX_MAX_REASSEMBLIES)
		evict_oldest_reassembly(state);

	reassembly = SS_ALLOC(struct ss_uicc_sms_rx_reassembly);
	if (!reassembly)
		return NULL;

	memset(reassembly, 0, sizeof(*reassembly));
	ss_list_init(&reassembly->sm);
	memcpy(&reassembly->tp_oa, &sms_deliver->tp_oa, sizeof(reassembly->tp_oa));
	reassembly->tp_pid = sms_deliver->tp_pid;
	reassembly->tp_dcs = sms_deliver->tp_dcs;
	reassembly->concat_ref_16bit = udh_info->concat_ref_16bit;
	reassembly->concat_ref = udh_info->concat_ref;
	reassembly->msg_parts = udh_info->msg_parts;

	ss_list_put(&state->reassemblies, &reassembly->list);
	state->reassembly_count++;

	return reassembly;
}

static int parse_ud_hdr(struct sms_rx_udh_info *udh_info, const uint8_t *ud_hdr, size_t ud_hdr_len)
{
	size_t pos = 0;

	memset(udh_info, 0, sizeof(*udh_info));
	while (pos < ud_hdr_len) {
		uint8_t iei;
		uint8_t ie_len;
		const uint8_t *ie_value;

		if (ud_hdr_len - pos < 2) {
			SS_LOGP(SSMS, LERROR, "failed to decode user data header, truncated IE header\n");
			return SS_SW_ERR_WRONG_PARAM_INCORRECT_DATA;
		}

		iei = ud_hdr[pos];
		ie_len = ud_hdr[pos + 1];
		if (ie_len > ud_hdr_len - pos - 2) {
			SS_LOGP(SSMS, LERROR, "failed to decode user data header, IE length exceeds UDHL\n");
			return SS_SW_ERR_WRONG_PARAM_INCORRECT_DATA;
		}
		ie_value = &ud_hdr[pos + 2];

		if (iei == TS_23_040_IEI_CONCAT_SMS || iei == TS_23_040_IEI_CONCAT_SMS_REF) {
			if (udh_info->concat_present) {
				SS_LOGP(SSMS, LERROR, "failed to decode user data header, multiple concat IEs\n");
				return SS_SW_ERR_WRONG_PARAM_INCORRECT_DATA;
			}
			if (iei == TS_23_040_IEI_CONCAT_SMS) {
				if (ie_len != 3) {
					SS_LOGP(SSMS, LERROR,
						"failed to decode 8-bit concat IE, expected len=3, got %u\n",
						ie_len);
					return SS_SW_ERR_WRONG_PARAM_INCORRECT_DATA;
				}
				udh_info->concat_ref_16bit = false;
				udh_info->concat_ref = ie_value[0];
				udh_info->msg_parts = ie_value[1];
				udh_info->msg_part_no = ie_value[2];
			} else {
				if (ie_len != 4) {
					SS_LOGP(SSMS, LERROR,
						"failed to decode 16-bit concat IE, expected len=4, got %u\n",
						ie_len);
					return SS_SW_ERR_WRONG_PARAM_INCORRECT_DATA;
				}
				udh_info->concat_ref_16bit = true;
				udh_info->concat_ref = ((uint16_t)ie_value[0] << 8) | ie_value[1];
				udh_info->msg_parts = ie_value[2];
				udh_info->msg_part_no = ie_value[3];
			}

			if (udh_info->msg_parts == 0 || udh_info->msg_part_no == 0 ||
			    udh_info->msg_part_no > udh_info->msg_parts) {
				SS_LOGP(SSMS, LERROR,
					"invalid concat IE ref=%u (%u-bit), part=%u/%u\n",
					udh_info->concat_ref, udh_info->concat_ref_16bit ? 16 : 8,
					udh_info->msg_part_no, udh_info->msg_parts);
				return SS_SW_ERR_WRONG_PARAM_INCORRECT_DATA;
			}

			udh_info->concat_present = true;
		} else {
			if (udh_info->ud_hdr_len + 2 + ie_len > sizeof(udh_info->ud_hdr)) {
				SS_LOGP(SSMS, LERROR, "failed to preserve user data header, UDH too large\n");
				return SS_SW_ERR_WRONG_PARAM_INCORRECT_DATA;
			}
			udh_info->ud_hdr[udh_info->ud_hdr_len++] = iei;
			udh_info->ud_hdr[udh_info->ud_hdr_len++] = ie_len;
			memcpy(&udh_info->ud_hdr[udh_info->ud_hdr_len], ie_value, ie_len);
			udh_info->ud_hdr_len += ie_len;
		}

		pos += 2 + ie_len;
	}

	return 0;
}

static int decode_ud_hdr(struct ss_list **ud_hdr_dec, const uint8_t *ud_hdr, size_t ud_hdr_len)
{
	*ud_hdr_dec = NULL;
	if (ud_hdr_len == 0)
		return 0;

	*ud_hdr_dec = ss_tlv8_decode(ud_hdr, ud_hdr_len);
	if (!*ud_hdr_dec) {
		SS_LOGP(SSMS, LERROR, "failed to decode user data header, invalid TLV data\n");
		return SS_SW_ERR_WRONG_PARAM_INCORRECT_DATA;
	}
	ss_tlv8_dump(*ud_hdr_dec, 2, SSMS, LDEBUG);

	return 0;
}

static int store_reassembly_ud_hdr(struct ss_uicc_sms_rx_reassembly *reassembly,
				   const struct sms_rx_udh_info *udh_info)
{
	if (udh_info->ud_hdr_len == 0)
		return 0;

	if (!reassembly->ud_hdr_set) {
		memcpy(reassembly->ud_hdr, udh_info->ud_hdr, udh_info->ud_hdr_len);
		reassembly->ud_hdr_len = udh_info->ud_hdr_len;
		reassembly->ud_hdr_set = true;
		return 0;
	}

	if (reassembly->ud_hdr_len != udh_info->ud_hdr_len ||
	    memcmp(reassembly->ud_hdr, udh_info->ud_hdr, udh_info->ud_hdr_len) != 0) {
		SS_LOGP(SSMS, LERROR, "conflicting non-concat UDH in concatenated SM ref=%u\n",
			reassembly->concat_ref);
		return SS_SW_ERR_WRONG_PARAM_INCORRECT_DATA;
	}

	return 0;
}

static int put_sm_part(struct ss_uicc_sms_rx_reassembly *reassembly, uint8_t msg_part_no, const uint8_t *tp_ud,
		       size_t tp_ud_len, bool *complete)
{
	struct ss_uicc_sms_rx_sm *sm;

	*complete = false;
	if (tp_ud_len > SMS_MAX_SIZE) {
		SS_LOGP(SSMS, LERROR,
			"receiving part %u/%u of message ref=%u exceeds SMS TP-UD size, got %zu octets\n",
			msg_part_no, reassembly->msg_parts, reassembly->concat_ref, tp_ud_len);
		return SS_SW_ERR_WRONG_PARAM_INCORRECT_DATA;
	}

	sm = get_sm_part(reassembly, msg_part_no);
	if (sm) {
		if (sm->tp_ud_len == tp_ud_len && memcmp(sm->tp_ud, tp_ud, tp_ud_len) == 0) {
			SS_LOGP(SSMS, LDEBUG, "ignoring duplicate part %u/%u of message ref=%u\n",
				msg_part_no, reassembly->msg_parts, reassembly->concat_ref);
			return 0;
		}

		SS_LOGP(SSMS, LERROR, "conflicting duplicate part %u/%u of message ref=%u\n", msg_part_no,
			reassembly->msg_parts, reassembly->concat_ref);
		return SS_SW_ERR_WRONG_PARAM_INCORRECT_DATA;
	}

	if (reassembly->tp_ud_len + tp_ud_len > SMS_RX_MAX_REASSEMBLED_LEN) {
		SS_LOGP(SSMS, LERROR, "concatenated SM ref=%u exceeds maximum reassembled length\n",
			reassembly->concat_ref);
		return SS_SW_ERR_WRONG_PARAM_INCORRECT_DATA;
	}

	sm = SS_ALLOC(struct ss_uicc_sms_rx_sm);
	if (!sm)
		return SS_SW_ERR_WRONG_PARAM_ENOMEM;

	memset(sm, 0, sizeof(*sm));
	sm->msg_part_no = msg_part_no;
	memcpy(sm->tp_ud, tp_ud, tp_ud_len);
	sm->tp_ud_len = tp_ud_len;
	ss_list_put(&reassembly->sm, &sm->list);
	reassembly->msg_parts_received++;
	reassembly->tp_ud_len += tp_ud_len;

	*complete = reassembly->msg_parts_received == reassembly->msg_parts;
	return 0;
}

static struct ss_buf *reassemble_sm(struct ss_uicc_sms_rx_reassembly *reassembly)
{
	uint8_t i;
	uint8_t *result_ptr;
	struct ss_buf *result;

	result = ss_buf_alloc(reassembly->tp_ud_len);
	result_ptr = result->data;

	for (i = 1; i <= reassembly->msg_parts; i++) {
		struct ss_uicc_sms_rx_sm *sm = get_sm_part(reassembly, i);
		assert(sm);
		memcpy(result_ptr, sm->tp_ud, sm->tp_ud_len);
		result_ptr += sm->tp_ud_len;
	}

	SS_LOGP(SSMS, LDEBUG, "message ref=%u complete: %s\n", reassembly->concat_ref,
		ss_hexdump(result->data, result->len));
	return result;
}

/* Process the tp_ud data we have received from either single SM or multiple
 * concatenated delivered SMs
 *
 * The response arguments behave like those of @ref ss_uicc_sms_rx.
 * */
static int handle_sm(struct ss_context *ctx, struct ss_sm_hdr *sm_hdr, struct ss_list *ud_hdr_dec, uint8_t *tp_ud,
		     size_t tp_ud_len, size_t *response_len, uint8_t response[*response_len])
{
	int rc = 0;
	assert(sm_hdr->tp_mti == SMS_MTI_DELIVER);

	struct tlv8_ie *cpi_ie = NULL;
	if (ud_hdr_dec) {
		cpi_ie = ss_tlv8_get_ie(ud_hdr_dec, IEI_CPI);
	}

	if (cpi_ie) {
		struct ss_buf *sms_response = NULL;
		rc = ss_uicc_remote_cmd_receive(tp_ud_len, tp_ud, response_len, response, &sms_response,
						ctx->fs_chg_filelist);

		if (sms_response != NULL) {
			struct ss_sm_hdr response_hdr;
			memset(&response_hdr, 0, sizeof(response_hdr));

			response_hdr.tp_mti = SMS_MTI_SUBMIT;
			response_hdr.u.sms_submit.tp_da.extension = true;
			memcpy(&response_hdr.u.sms_submit.tp_da, &sm_hdr->u.sms_deliver.tp_oa,
			       sizeof(struct ss_sms_addr));
			response_hdr.u.sms_submit.tp_pid = 127;
			response_hdr.u.sms_submit.tp_dcs = 246;

			ss_uicc_sms_tx(ctx, &response_hdr, &sms_response->data[1], sms_response->data[0],
				       &sms_response->data[1 + sms_response->data[0]],
				       sms_response->len - 1 - sms_response->data[0], NULL);
			SS_LOGP(SSMS, LDEBUG, "Enqueued SMS in response to command\n");
			ss_buf_free(sms_response);
		}
	} else {
		SS_LOGP(SSMS, LDEBUG, "received sms TP-UD with no CPI IE (0x70) in UDH: %s\n",
			ss_hexdump(tp_ud, tp_ud_len));
		*response_len = 0;
	}

	return rc;
}

static int process_concat_sm(struct ss_context *ctx, struct ss_uicc_sms_rx_state *state, struct ss_sm_hdr *sm_hdr,
			     const struct sms_rx_udh_info *udh_info, uint8_t *tp_ud, size_t tp_ud_len,
			     size_t *response_len, uint8_t response[*response_len])
{
	struct ss_uicc_sms_rx_reassembly *reassembly;
	struct ss_buf *concat_sm_buf = NULL;
	struct ss_list *ud_hdr_dec = NULL;
	bool complete;
	int rc;

	reassembly = find_reassembly(state, sm_hdr, udh_info);
	if (!reassembly) {
		reassembly = new_reassembly(state, sm_hdr, udh_info);
		if (!reassembly) {
			*response_len = 0;
			return SS_SW_ERR_WRONG_PARAM_ENOMEM;
		}
	}

	rc = store_reassembly_ud_hdr(reassembly, udh_info);
	if (rc != 0) {
		remove_reassembly(state, reassembly);
		*response_len = 0;
		return rc;
	}

	SS_LOGP(SSMS, LDEBUG, "receiving part %u/%u of message ref=%u (%u-bit): %s\n", udh_info->msg_part_no,
		udh_info->msg_parts, udh_info->concat_ref, udh_info->concat_ref_16bit ? 16 : 8,
		ss_hexdump(tp_ud, tp_ud_len));

	rc = put_sm_part(reassembly, udh_info->msg_part_no, tp_ud, tp_ud_len, &complete);
	if (rc != 0) {
		remove_reassembly(state, reassembly);
		*response_len = 0;
		return rc;
	}

	if (!complete) {
		SS_LOGP(SSMS, LDEBUG, "message ref=%u is not complete yet, received %u/%u parts.\n",
			reassembly->concat_ref, reassembly->msg_parts_received, reassembly->msg_parts);
		*response_len = 0;
		return 0;
	}

	concat_sm_buf = reassemble_sm(reassembly);
	rc = decode_ud_hdr(&ud_hdr_dec, reassembly->ud_hdr, reassembly->ud_hdr_len);
	if (rc == 0)
		rc = handle_sm(ctx, sm_hdr, ud_hdr_dec, concat_sm_buf->data, concat_sm_buf->len, response_len, response);

	if (ud_hdr_dec)
		ss_tlv8_free(ud_hdr_dec);
	ss_buf_free(concat_sm_buf);
	remove_reassembly(state, reassembly);
	if (rc != 0)
		*response_len = 0;

	return rc;
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
	struct sms_rx_udh_info udh_info;
	struct ss_list *ud_hdr_dec = NULL;

	init_state_if_needed(state);
	memset(&udh_info, 0, sizeof(udh_info));
	sm_hdr_len = ss_sms_hdr_decode(&sm_hdr, sms_tpdu->data, sms_tpdu->len);
	if (sm_hdr_len < 0) {
		SS_LOGP(SSMS, LERROR, "failed to decode SMS TPDU header.\n");
		rc = SS_SW_ERR_WRONG_PARAM_INCORRECT_DATA;
		*response_len = 0;
		goto leave;
	}
	assert(sm_hdr_len <= sms_tpdu->len);

	switch (sm_hdr.tp_mti) {
	case SMS_MTI_DELIVER:
		tp_ud = sms_tpdu->data + sm_hdr_len;
		tp_ud_len = sms_tpdu->len - sm_hdr_len;
		if (sm_hdr.u.sms_deliver.tp_udhi) {
			uint8_t ud_hdr_len;
			const uint8_t *ud_hdr;

			if (tp_ud_len == 0 || tp_ud[0] + 1 > tp_ud_len) {
				SS_LOGP(SSMS, LERROR,
					"failed to decode user data header, length field exceeds TP-UD length\n");
				rc = SS_SW_ERR_WRONG_PARAM_INCORRECT_DATA;
				*response_len = 0;
				goto leave;
			}

			ud_hdr_len = tp_ud[0];
			ud_hdr = tp_ud + 1;
			SS_LOGP(SSMS, LDEBUG, "received sms TP-UD header: %s\n", ss_hexdump(ud_hdr, ud_hdr_len));

			rc = parse_ud_hdr(&udh_info, ud_hdr, ud_hdr_len);
			if (rc != 0) {
				*response_len = 0;
				goto leave;
			}

			tp_ud_len -= 1 + ud_hdr_len;
			tp_ud += 1 + ud_hdr_len;
		}

		if (udh_info.concat_present) {
			rc = process_concat_sm(ctx, state, &sm_hdr, &udh_info, tp_ud, tp_ud_len, response_len, response);
			break;
		}

		/* Normal SM received, forward directly */
		SS_LOGP(SSMS, LDEBUG, "received sms TP-UD: %s\n", ss_hexdump(tp_ud, tp_ud_len));
		rc = decode_ud_hdr(&ud_hdr_dec, udh_info.ud_hdr, udh_info.ud_hdr_len);
		if (rc == 0)
			rc = handle_sm(ctx, &sm_hdr, ud_hdr_dec, tp_ud, tp_ud_len, response_len, response);
		if (rc != 0)
			*response_len = 0;
		if (ud_hdr_dec) {
			ss_tlv8_free(ud_hdr_dec);
			ud_hdr_dec = NULL;
		}
		break;
	default:
		SS_LOGP(SSMS, LINFO, "Unspported SMS message type (%u) received -- ignored!\n", sm_hdr.tp_mti & 0x03);
		*response_len = 0;
		break;
	}

leave:
	if (ud_hdr_dec)
		ss_tlv8_free(ud_hdr_dec);
	return rc;
}
