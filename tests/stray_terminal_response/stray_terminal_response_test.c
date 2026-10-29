/*
 * Copyright (c) 2026 Onomondo ApS. All rights reserved.
 *
 * SPDX-License-Identifier: GPL-3.0-only
 */

#include <assert.h>
#include <stdio.h>
#include <onomondo/softsim/softsim.h>
#include <onomondo/softsim/utils.h>
#include "src/softsim/uicc/context.h"
#include "src/softsim/uicc/proactive.h"
extern uint32_t ss_log_mask;

/* A TERMINAL RESPONSE answers a fetched command (ETSI TS 102 223, 6.8): one with nothing pending, or sent
 * before the FETCH, is ignored and the pending command stays announced. */

#define TERMINAL_RESPONSE "801400000c810301010182028281830100"

static unsigned int term_resp_calls;

static void count_term_resp(struct ss_context *ctx, uint8_t *resp_data, uint8_t resp_data_len)
{
	term_resp_calls++;
}

static uint16_t xfer(struct ss_context *ctx, const char *hex, uint8_t *resp, size_t *resp_len)
{
	uint8_t cmd[300];
	size_t cmd_len = ss_binary_from_hexstr(cmd, sizeof(cmd), hex);

	*resp_len = ss_transact(ctx, resp, 300, cmd, &cmd_len);
	assert(*resp_len >= 2);
	return (uint16_t)((resp[*resp_len - 2] << 8) | resp[*resp_len - 1]);
}

int main(void)
{
	struct ss_context *ctx;
	uint8_t body[32], resp[300];
	size_t body_len, resp_len;
	char fetch[16];
	uint16_t sw;
	int rc;

	ss_log_mask = 0;
	ctx = ss_new_ctx();
	ss_reset(ctx);

	sw = xfer(ctx, "8010000014ffffffffffffffffffffffffffffffffffffffff", resp, &resp_len);
	assert(sw == 0x9000);

	sw = xfer(ctx, TERMINAL_RESPONSE, resp, &resp_len);
	printf("TERMINAL RESPONSE with nothing pending: %04x\n", sw);
	assert(sw == 0x9000);

	/* A REFRESH (File Change Notification, EF.FPLMN) announced but not fetched yet */
	body_len = ss_binary_from_hexstr(body, sizeof(body), "8103010101820281829207013f007fff6f7b");
	rc = ss_proactive_put(ctx, count_term_resp, body, body_len);
	assert(rc == 0);
	sw = xfer(ctx, "80f2000c00", resp, &resp_len);
	printf("STATUS: %04x\n", sw);
	assert(sw == 0x9114);

	sw = xfer(ctx, TERMINAL_RESPONSE, resp, &resp_len);
	printf("TERMINAL RESPONSE before the FETCH: %04x, callback calls: %u\n", sw, term_resp_calls);
	assert(sw == 0x9114 && term_resp_calls == 0);
	sw = xfer(ctx, "80f2000c00", resp, &resp_len);
	printf("STATUS: %04x\n", sw);
	assert(sw == 0x9114);

	snprintf(fetch, sizeof(fetch), "80120000%02x", sw & 0xff);
	sw = xfer(ctx, fetch, resp, &resp_len);
	printf("FETCH: %s %04x\n", ss_hexdump(resp, resp_len - 2), sw);
	assert(sw == 0x9000 && resp_len == 0x14 + 2);

	sw = xfer(ctx, TERMINAL_RESPONSE, resp, &resp_len);
	printf("TERMINAL RESPONSE after the FETCH: %04x, callback calls: %u\n", sw, term_resp_calls);
	assert(sw == 0x9000 && term_resp_calls == 1);

	ss_free_ctx(ctx);
	return 0;
}
