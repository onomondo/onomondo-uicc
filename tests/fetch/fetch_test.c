/*
 * Copyright (c) 2026 Onomondo ApS. All rights reserved.
 *
 * SPDX-License-Identifier: GPL-3.0-only
 */

#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <onomondo/softsim/softsim.h>
#include <onomondo/softsim/utils.h>
#include "src/softsim/uicc/context.h"
#include "src/softsim/uicc/proactive.h"
extern uint32_t ss_log_mask;

/* A FETCH with the wrong Le gets '6C XX' with the correct length and the proactive command stays pending
 * (ETSI TS 102 221, section 7.3.1.1.5.1): a terminal that re-issues the FETCH with P3 = XX still receives it. */

/* fn: ss_transact for a raw T=0 TPDU, ss_application_apdu_transact to include the 61xx/6Cxx handling */
static uint16_t xfer(size_t (*fn)(struct ss_context *, uint8_t *, size_t, uint8_t *, size_t *), struct ss_context *ctx,
		     const char *hex, uint8_t *resp, size_t *resp_len)
{
	uint8_t cmd[300];
	size_t cmd_len = ss_binary_from_hexstr(cmd, sizeof(cmd), hex);

	*resp_len = fn(ctx, resp, 300, cmd, &cmd_len);
	assert(*resp_len >= 2);
	return (uint16_t)((resp[*resp_len - 2] << 8) | resp[*resp_len - 1]);
}

/* A REFRESH (File Change Notification, EF.FPLMN) as the card would queue it */
static void queue_refresh(struct ss_context *ctx)
{
	uint8_t body[32];
	size_t body_len = ss_binary_from_hexstr(body, sizeof(body), "8103010101820281829207013f007fff6f7b");
	int rc = ss_proactive_put(ctx, NULL, body, body_len);

	assert(rc == 0);
	assert(ctx->proactive.data_len == 0x14);
}

int main(void)
{
	struct ss_context *ctx;
	uint8_t resp[300];
	size_t resp_len;
	uint16_t sw;

	ss_log_mask = 0;
	ctx = ss_new_ctx();
	ss_reset(ctx);

	sw = xfer(ss_transact, ctx, "8010000014ffffffffffffffffffffffffffffffffffffffff", resp, &resp_len);
	assert(sw == 0x9000);

	queue_refresh(ctx);
	sw = xfer(ss_transact, ctx, "80f2000c00", resp, &resp_len);
	printf("STATUS: %04x\n", sw);
	assert(sw == 0x9114);

	sw = xfer(ss_transact, ctx, "8012000005", resp, &resp_len);
	printf("FETCH with Le=05: %04x, pending %u bytes\n", sw, ctx->proactive.data_len);
	assert(sw == 0x6c14 && ctx->proactive.data_len == 0x14);

	sw = xfer(ss_transact, ctx, "8012000000", resp, &resp_len);
	printf("FETCH with Le=00: %04x, pending %u bytes\n", sw, ctx->proactive.data_len);
	assert(sw == 0x6c14 && ctx->proactive.data_len == 0x14);

	sw = xfer(ss_transact, ctx, "8012000014", resp, &resp_len);
	printf("FETCH with Le=14: %s %04x\n", ss_hexdump(resp, resp_len - 2), sw);
	assert(sw == 0x9000 && resp_len == 0x14 + 2 && ctx->proactive.data_len == 0);

	sw = xfer(ss_transact, ctx, "801400000c810301010182028281830100", resp, &resp_len);
	printf("TERMINAL RESPONSE: %04x\n", sw);
	assert(sw == 0x9000);

	/* Nothing pending: FETCH answers 9000 with an empty body, whatever Le */
	sw = xfer(ss_transact, ctx, "8012000005", resp, &resp_len);
	printf("FETCH with nothing pending: %04x, %zu data bytes\n", sw, resp_len - 2);
	assert(sw == 0x9000 && resp_len == 2);

	/* The transport layer re-issues the FETCH with the length it was told */
	queue_refresh(ctx);
	sw = xfer(ss_application_apdu_transact, ctx, "8012000005", resp, &resp_len);
	printf("FETCH with Le=05 via the transport layer: %s %04x\n", ss_hexdump(resp, resp_len - 2), sw);
	assert(sw == 0x9000 && resp_len == 0x14 + 2);

	ss_free_ctx(ctx);
	return 0;
}
