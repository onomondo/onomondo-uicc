/*
 * Copyright (c) 2026 Onomondo ApS. All rights reserved.
 *
 * SPDX-License-Identifier: GPL-3.0-only
 */

/* TS 23.040 section 9.2.3.24.1: a concatenation IE whose part count is zero,
 * or whose sequence number is zero or exceeds the part count, shall be
 * ignored and the SM handled as a single short message. This pins that a
 * malformed IE neither creates reassembly state nor drops the message, and
 * that a well-formed two-part message still reassembles.
 *
 * TS 23.048 puts the CPI IE only on part 1 of a concatenation (see also
 * envelope_test.c's concat_sm_reassembly_test(), which pins the same "CPI
 * IE, then concat IE" ordering on part 1 only), so part 1 of the
 * well-formed message below carries it and part 2 does not. */

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

	/* Malformed IEs: handled as a single SM (rc -1 from the unknown-IEIa
	 * handler proves the payload got there), no reassembly state created. */
	assert(rx(ctx, 7, 0, 1, false) == -1); /* part count 0 */
	assert(state->msg_parts == 0 && ss_list_empty(&state->sm));
	assert(rx(ctx, 7, 2, 0, false) == -1); /* sequence number 0 */
	assert(state->msg_parts == 0 && ss_list_empty(&state->sm));
	assert(rx(ctx, 7, 2, 3, false) == -1); /* sequence number > part count */
	assert(state->msg_parts == 0 && ss_list_empty(&state->sm));

	/* A well-formed two-part message still buffers and reassembles. Only
	 * part 1 carries the CPI IE (TS 23.048). */
	assert(rx(ctx, 9, 2, 1, true) == 0); /* buffered, waiting for part 2 */
	assert(state->msg_parts == 2 && !ss_list_empty(&state->sm));
	/* Complete: reassembly delivered to handle_sm(), which forwards it to
	 * ss_uicc_remote_cmd_receive(); the 4-byte reassembled payload is too
	 * short to be a command packet, same as envelope_test.c's
	 * concat_sm_reassembly_test(). */
	assert(rx(ctx, 9, 2, 2, false) == SS_SW_ERR_CHECKING_WRONG_LENGTH);
	assert(state->msg_parts == 0 && ss_list_empty(&state->sm));

	ss_free_ctx(ctx);
	printf("ok\n");
	return 0;
}
