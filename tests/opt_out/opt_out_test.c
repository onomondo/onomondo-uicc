/*
 * Copyright (c) 2026 Onomondo ApS. All rights reserved.
 *
 * SPDX-License-Identifier: GPL-3.0-only
 */

/* Built with CONFIG_DISABLE_SMS: the card stays a working card with CAT alive,
 * and an SMS-PP DOWNLOAD ends in 6F00, one of the answers TS 31.111 clause
 * 7.1.1.1 maps to an RP-ACK. */

#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <onomondo/softsim/softsim.h>
#include <onomondo/softsim/utils.h>

static uint16_t transact_hex(struct ss_context *ctx, const char *hex)
{
	uint8_t cmd[300];
	uint8_t rsp[300];
	size_t cmd_len = ss_binary_from_hexstr(cmd, sizeof(cmd), hex);
	size_t rsp_len = ss_application_apdu_transact(ctx, rsp, sizeof(rsp), cmd, &cmd_len);

	assert(rsp_len >= 2);
	return (rsp[rsp_len - 2] << 8) | rsp[rsp_len - 1];
}

int main(void)
{
	uint16_t sw;
	struct ss_context *ctx = ss_new_ctx();

	assert(ctx);
	ss_reset(ctx);

	/* SELECT MF: the gated build is still a card */
	assert(transact_hex(ctx, "00a40004023f00") == 0x9000);

	/* TERMINAL PROFILE: CAT is still there */
	assert(transact_hex(ctx, "8010000014ffffffffffffffffffffffffffffffffffffffff") == 0x9000);

	/* OTA command packet in an SMS-PP DOWNLOAD (the envelope suite's) */
	sw = transact_hex(ctx, "80c200005b"
			       "d15982028381860510426587f98b4c60039121437ff662408011"
			       "9342803d02700000381516393232b00011d5cbcbd7ad00edcae5"
			       "fb251618e04ed8502924dbad65b15be802a9d9e28267110d433c"
			       "06103268db6a2a9d618fe8ab74");
	assert(sw == 0x6f00);

	ss_free_ctx(ctx);
	printf("ok\n");
	return 0;
}
