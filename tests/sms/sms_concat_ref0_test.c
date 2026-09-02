/*
 * Copyright (c) 2026 Onomondo ApS. All rights reserved.
 *
 * SPDX-License-Identifier: GPL-3.0-only
 */

/* TS 23.040 section 9.2.3.24.1: the concatenation reference number is a
 * modulo-256 counter with no reserved values, so 0 is a valid msg_id;
 * idleness of the reassembly state is indicated by msg_parts == 0, which a
 * latched message can never carry. This pins that a reference-0 message
 * latches from idle, reassembles and supersedes like any other reference,
 * and that the part-count consistency check still bites within reference 0.
 *
 * TS 23.048 puts the CPI IE only on part 1 of a concatenation, so part 1
 * below carries it and part 2 does not. */

#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <onomondo/softsim/softsim.h>
#include <onomondo/softsim/list.h>
#include <onomondo/softsim/utils.h>
#include "src/softsim/uicc/context.h"
#include "src/softsim/uicc/sw.h"
#include "src/softsim/uicc/uicc_sms_rx.h"

/* Feed one SMS-DELIVER whose user-data header carries a concatenation IE
 * with the given values, optionally preceded by a CPI IE. Returns the
 * ss_uicc_sms_rx() result: 0 when the part was buffered; -1 when the
 * payload was handled as a single SM and rejected for its unknown IEIa
 * 0x00; an SW when a completed reassembly reached handle_sm() and was
 * rejected there. */
static int rx(struct ss_context *ctx, uint8_t id, uint8_t parts, uint8_t seq, bool with_cpi)
{
	uint8_t udh[7];
	size_t udh_len = 0;
	uint8_t tpdu[24];
	size_t tpdu_len = 0;
	uint8_t response[256];
	size_t response_len = sizeof(response);
	struct ss_buf *sb;
	int rc;

	if (with_cpi) {
		udh[udh_len++] = 0x70; /* CPI IE */
		udh[udh_len++] = 0x00; /* CPI IEDLa = 0 */
	}
	udh[udh_len++] = 0x00; /* concatenation IE */
	udh[udh_len++] = 0x03;
	udh[udh_len++] = id;
	udh[udh_len++] = parts;
	udh[udh_len++] = seq;

	tpdu[tpdu_len++] = 0x40; /* SMS-DELIVER, TP-UDHI set */
	tpdu[tpdu_len++] = 0x02; /* TP-OA: 2 digits, national */
	tpdu[tpdu_len++] = 0x81;
	tpdu[tpdu_len++] = 0x21;
	tpdu[tpdu_len++] = 0x7f; /* TP-PID, TP-DCS (8-bit data) */
	tpdu[tpdu_len++] = 0xf6;
	memset(&tpdu[tpdu_len], 0x00, 7); /* TP-SCTS */
	tpdu_len += 7;
	tpdu[tpdu_len++] = (uint8_t)(1 + udh_len + 2); /* TP-UDL */
	tpdu[tpdu_len++] = (uint8_t)udh_len; /* UDHL */
	memcpy(&tpdu[tpdu_len], udh, udh_len);
	tpdu_len += udh_len;
	tpdu[tpdu_len++] = 0x41; /* payload */
	tpdu[tpdu_len++] = 0x42;

	sb = ss_buf_alloc_and_cpy(tpdu, tpdu_len);
	assert(sb);
	rc = ss_uicc_sms_rx(ctx, sb, &response_len, response);
	ss_buf_free(sb);
	return rc;
}

int main(void)
{
	struct ss_context *ctx = ss_new_ctx();
	struct ss_uicc_sms_rx_state *state;

	assert(ctx);
	ss_reset(ctx);
	/* ss_reset() leaves the rx state all-zero (its documented initial
	 * form); init the part list so ss_list_empty() below is meaningful. */
	ss_uicc_sms_rx_clear(ctx);
	state = &ctx->proactive.sms_rx_state;

	/* A reference-0 part arriving on idle state latches the part count
	 * and buffers the part. */
	assert(rx(ctx, 0, 2, 1, true) == 0);
	assert(state->msg_parts == 2 && !ss_list_empty(&state->sm));

	/* The reference-0 message completes and the reassembly is delivered
	 * to handle_sm(), which forwards it to ss_uicc_remote_cmd_receive();
	 * the 4-byte reassembled payload is too short to be a command packet,
	 * same as envelope_test.c's concat_sm_reassembly_test(). */
	assert(rx(ctx, 0, 2, 2, false) == SS_SW_ERR_CHECKING_WRONG_LENGTH);
	assert(state->msg_parts == 0 && ss_list_empty(&state->sm));

	/* Reference 0 latches again after completion. */
	assert(rx(ctx, 0, 2, 1, true) == 0);
	assert(state->msg_parts == 2 && !ss_list_empty(&state->sm));

	/* The part-count consistency check still bites within reference 0:
	 * a part reporting a different total clears state and is rejected. */
	assert(rx(ctx, 0, 3, 1, true) == SS_SW_ERR_WRONG_PARAM_INCORRECT_DATA);
	assert(state->msg_parts == 0 && ss_list_empty(&state->sm));

	/* A nonzero reference still latches... */
	assert(rx(ctx, 5, 2, 1, true) == 0);
	assert(state->msg_id == 5 && state->msg_parts == 2 && !ss_list_empty(&state->sm));

	/* ...and reference 0 supersedes it. */
	assert(rx(ctx, 0, 2, 1, true) == 0);
	assert(state->msg_id == 0 && state->msg_parts == 2 && !ss_list_empty(&state->sm));

	/* The superseding reference-0 message reassembles too. */
	assert(rx(ctx, 0, 2, 2, false) == SS_SW_ERR_CHECKING_WRONG_LENGTH);
	assert(state->msg_parts == 0 && ss_list_empty(&state->sm));

	ss_free_ctx(ctx);
	printf("ok\n");
	return 0;
}
