/*
 * Copyright (c) 2026 Onomondo ApS. All rights reserved.
 *
 * SPDX-License-Identifier: GPL-3.0-only
 */

/* TS 23.040 section 9.2.3.24.1: the concatenation reference number is a
 * modulo-256 counter with no reserved values, so 0 is a valid msg_id;
 * idleness of the reassembly state is indicated by msg_parts == 0, which a
 * latched message can never carry. This pins that a reference-0 message
 * latches from idle, reassembles, supersedes and is superseded like any
 * other reference. */

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

	/* A reference-0 part arriving on idle state latches the part count
	 * and buffers the part. */
	assert(rx(ctx, 0, 2, 1) == 0);
	assert(state->msg_parts == 2 && !ss_list_empty(&state->sm));

	/* The reference-0 message completes: reassembly delivered, state
	 * cleared. */
	assert(rx(ctx, 0, 2, 2) == -1);
	assert(state->msg_parts == 0 && ss_list_empty(&state->sm));

	/* A stray re-delivered part of the completed message re-latches
	 * cleanly, like a stray part of any other reference. */
	assert(rx(ctx, 0, 2, 2) == 0);
	assert(state->msg_parts == 2 && !ss_list_empty(&state->sm));

	/* The part-count consistency check still bites within reference 0:
	 * a part reporting a different total clears state and is dropped. */
	assert(rx(ctx, 0, 3, 1) == 0);
	assert(state->msg_parts == 0 && ss_list_empty(&state->sm));

	/* Reference 0 reused for a new message (modulo-256 counter). */
	assert(rx(ctx, 0, 3, 1) == 0);
	assert(state->msg_id == 0 && state->msg_parts == 3 && !ss_list_empty(&state->sm));

	/* A new nonzero reference supersedes the in-progress reference 0... */
	assert(rx(ctx, 5, 2, 1) == 0);
	assert(state->msg_id == 5 && state->msg_parts == 2 && !ss_list_empty(&state->sm));

	/* ...and reference 0 supersedes an in-progress nonzero reference. */
	assert(rx(ctx, 0, 2, 1) == 0);
	assert(state->msg_id == 0 && state->msg_parts == 2 && !ss_list_empty(&state->sm));

	/* The superseding reference-0 message is fully functional. */
	assert(rx(ctx, 0, 2, 2) == -1);
	assert(state->msg_parts == 0 && ss_list_empty(&state->sm));

	ss_free_ctx(ctx);
	printf("ok\n");
	return 0;
}
