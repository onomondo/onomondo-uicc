/*
 * Copyright (c) 2026 Onomondo ApS. All rights reserved.
 *
 * SPDX-License-Identifier: GPL-3.0-only
 */

/* TS 23.040 section 9.2.3.24.1: a concatenation IE whose part count is zero,
 * or whose sequence number is zero or exceeds the part count, shall be
 * ignored and the SM handled as a single short message. This pins that a
 * malformed IE neither creates reassembly state nor drops the message, and
 * that a well-formed two-part message still reassembles. */

#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <onomondo/softsim/softsim.h>
#include <onomondo/softsim/list.h>
#include <onomondo/softsim/utils.h>
#include "src/softsim/uicc/context.h"
#include "src/softsim/uicc/uicc_sms_rx.h"

/* Feed one SMS-DELIVER whose user-data header carries a concatenation IE
 * with the given values. Returns the ss_uicc_sms_rx() result: 0 when the
 * part was buffered, -1 when the payload reached the single/reassembled
 * message handler (which rejects the unknown IEIa 0x00 with -1). */
static int rx(struct ss_context *ctx, uint8_t id, uint8_t parts, uint8_t seq)
{
	const uint8_t tpdu[] = {
		0x40, /* SMS-DELIVER, TP-UDHI set */
		0x02, 0x81, 0x21, /* TP-OA: 2 digits, national */
		0x7f, 0xf6, /* TP-PID, TP-DCS (8-bit data) */
		0x00, 0x00, 0x00, 0x00, 0x00,  0x00, 0x00, /* TP-SCTS */
		0x08, /* TP-UDL */
		0x05, 0x00, 0x03, id,	parts, seq, /* UDH: concatenation IE */
		0x41, 0x42, /* payload */
	};
	uint8_t response[256];
	size_t response_len = sizeof(response);
	struct ss_buf *sb = ss_buf_alloc_and_cpy(tpdu, sizeof(tpdu));
	int rc;

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
	assert(rx(ctx, 7, 0, 1) == -1); /* part count 0 */
	assert(state->msg_parts == 0 && ss_list_empty(&state->sm));
	assert(rx(ctx, 7, 2, 0) == -1); /* sequence number 0 */
	assert(state->msg_parts == 0 && ss_list_empty(&state->sm));
	assert(rx(ctx, 7, 2, 3) == -1); /* sequence number > part count */
	assert(state->msg_parts == 0 && ss_list_empty(&state->sm));

	/* A well-formed two-part message still buffers and reassembles. */
	assert(rx(ctx, 9, 2, 1) == 0); /* buffered, waiting for part 2 */
	assert(state->msg_parts == 2 && !ss_list_empty(&state->sm));
	assert(rx(ctx, 9, 2, 2) == -1); /* complete: reassembly delivered */
	assert(state->msg_parts == 0 && ss_list_empty(&state->sm));

	ss_free_ctx(ctx);
	printf("ok\n");
	return 0;
}
