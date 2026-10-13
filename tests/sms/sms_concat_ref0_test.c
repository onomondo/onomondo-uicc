/*
 * Copyright (c) 2026 Onomondo ApS. All rights reserved.
 *
 * SPDX-License-Identifier: GPL-3.0-only
 */

/* TS 23.040 section 9.2.3.24.1: the reference number is a modulo-256 counter,
 * so reference 0 must latch, reassemble and supersede like any other. */

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

/* Feed one SMS-DELIVER carrying a concatenation IE, optionally preceded by
 * the CPI IE (part 1 only, TS 23.048); returns ss_uicc_sms_rx()'s result. */
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
	/* ss_reset() leaves the part list zeroed; init it for ss_list_empty(). */
	ss_uicc_sms_rx_clear(ctx);
	state = &ctx->proactive.sms_rx_state;

	/* Reference 0 latches from idle and buffers part 1. */
	assert(rx(ctx, 0, 2, 1, true) == 0);
	assert(state->msg_parts == 2 && !ss_list_empty(&state->sm));

	/* Part 2 completes it; the 4-byte payload is too short for a command packet. */
	assert(rx(ctx, 0, 2, 2, false) == SS_SW_ERR_CHECKING_WRONG_LENGTH);
	assert(state->msg_parts == 0 && ss_list_empty(&state->sm));

	/* Reference 0 latches again after completion. */
	assert(rx(ctx, 0, 2, 1, true) == 0);
	assert(state->msg_parts == 2 && !ss_list_empty(&state->sm));

	/* A part reporting a different total still clears state and is rejected. */
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
