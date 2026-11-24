/*
 * Copyright (c) 2026 Onomondo ApS. All rights reserved.
 *
 * SPDX-License-Identifier: GPL-3.0-only
 */

#include <assert.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <onomondo/softsim/softsim.h>
#include <onomondo/softsim/utils.h>

/* allow test to silence noisy logs */
extern uint32_t ss_log_mask;

/* GET RESPONSE on the T=0 path. TS 102 221 clause 12.1.1: it must follow the
 * command whose response it fetches, otherwise the card answers 6F00.
 * Read-only: nothing here writes to files/. */
#define SELECT_MF_FCP "00a40004023f00"
#define STATUS_NO_DATA "80f2000c00"
#define STATUS_LCHAN_1 "81f2000c00"

static uint8_t resp[300];
static size_t resp_len;

static uint16_t transact(struct ss_context *ctx, const char *hex)
{
	uint8_t cmd[300];
	size_t cmd_len = ss_binary_from_hexstr(cmd, sizeof(cmd), hex);

	resp_len = ss_transact(ctx, resp, sizeof(resp), cmd, &cmd_len);
	assert(resp_len >= 2);
	return (uint16_t)((resp[resp_len - 2] << 8) | resp[resp_len - 1]);
}

static bool has_bytes(const uint8_t *buf, size_t len, const uint8_t *pat, size_t n)
{
	for (size_t i = 0; i + n <= len; i++) {
		if (memcmp(buf + i, pat, n) == 0)
			return true;
	}
	return false;
}

static uint16_t get_response(struct ss_context *ctx, uint8_t p3)
{
	char hex[11];

	snprintf(hex, sizeof(hex), "00c00000%02x", p3);
	return transact(ctx, hex);
}

int main(void)
{
	static const uint8_t mf_id[] = { 0x83, 0x02, 0x3f, 0x00 };
	struct ss_context *ctx;
	uint16_t sw;
	uint8_t xx;

	ss_log_mask = 0;
	ctx = ss_new_ctx();
	ss_reset(ctx);
	ss_log_mask = 0;

	sw = get_response(ctx, 0);
	printf("a) GET RESPONSE after reset: %04x\n", sw);
	assert(sw == 0x6f00);

	sw = transact(ctx, SELECT_MF_FCP);
	printf("b) SELECT MF: %04x\n", sw);
	assert((sw >> 8) == 0x61);
	xx = sw & 0xff;
	sw = get_response(ctx, xx + 1);
	printf("b) GET RESPONSE, P3 too long: %04x\n", sw);
	assert(sw == (0x6c00 | xx));
	sw = get_response(ctx, xx);
	printf("b) GET RESPONSE: %04x, %zu bytes\n", sw, resp_len - 2);
	assert(sw == 0x9000 && resp_len - 2 == xx);
	assert(has_bytes(resp, resp_len - 2, mf_id, sizeof(mf_id)));

	sw = get_response(ctx, xx);
	printf("c) GET RESPONSE repeated: %04x\n", sw);
	assert(sw == 0x6f00);

	sw = transact(ctx, STATUS_NO_DATA);
	assert(sw == 0x9000);
	sw = get_response(ctx, 0);
	printf("d) GET RESPONSE after STATUS without data: %04x\n", sw);
	assert(sw == 0x6f00);

	sw = transact(ctx, SELECT_MF_FCP);
	assert((sw >> 8) == 0x61);
	xx = sw & 0xff;
	sw = transact(ctx, STATUS_NO_DATA);
	assert(sw == 0x9000);
	sw = get_response(ctx, xx);
	printf("e) GET RESPONSE after an intervening command: %04x\n", sw);
	assert(sw == 0x6f00);

	sw = transact(ctx, SELECT_MF_FCP);
	assert((sw >> 8) == 0x61);
	xx = sw & 0xff;
	sw = get_response(ctx, xx + 1);
	assert(sw == (0x6c00 | xx));
	sw = transact(ctx, STATUS_NO_DATA);
	assert(sw == 0x9000);
	sw = get_response(ctx, xx);
	printf("f) GET RESPONSE after 6Cxx and an intervening command: %04x\n", sw);
	assert(sw == 0x6f00);

	sw = transact(ctx, SELECT_MF_FCP);
	assert((sw >> 8) == 0x61);
	xx = sw & 0xff;
	sw = transact(ctx, STATUS_LCHAN_1);
	assert(sw == 0x6881);
	sw = get_response(ctx, xx);
	printf("g) GET RESPONSE after a command on a closed lchan: %04x\n", sw);
	assert(sw == 0x6f00);

	ss_free_ctx(ctx);
	return 0;
}
