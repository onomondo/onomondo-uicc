/*
 * Copyright (c) 2026 Onomondo ApS. All rights reserved.
 *
 * SPDX-License-Identifier: GPL-3.0-only
 */

/* Built only with CONFIG_DISABLE_PROACTIVE: the CAT commands are compiled
 * out, so the card must answer their instruction codes with 6D00
 * ("instruction code not supported", TS 102 221 section 10.2.1.1). */

#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <onomondo/softsim/softsim.h>

static uint16_t transact_sw(struct ss_context *ctx, const uint8_t *req, size_t req_len)
{
	uint8_t rsp[258];
	uint8_t cmd[8];
	size_t rsp_len;

	assert(req_len <= sizeof(cmd));
	memcpy(cmd, req, req_len);
	rsp_len = ss_transact(ctx, rsp, sizeof(rsp), cmd, &req_len);
	assert(rsp_len >= 2);
	return (rsp[rsp_len - 2] << 8) | rsp[rsp_len - 1];
}

int main(void)
{
	const uint8_t term_profile[] = { 0x80, 0x10, 0x00, 0x00, 0x00 };
	const uint8_t fetch[] = { 0x80, 0x12, 0x00, 0x00, 0x00 };
	const uint8_t envelope[] = { 0x80, 0xc2, 0x00, 0x00, 0x00 };

	struct ss_context *ctx = ss_new_ctx();
	assert(ctx);
	ss_reset(ctx);

	assert(transact_sw(ctx, term_profile, sizeof(term_profile)) == 0x6d00);
	assert(transact_sw(ctx, fetch, sizeof(fetch)) == 0x6d00);
	assert(transact_sw(ctx, envelope, sizeof(envelope)) == 0x6d00);

	ss_free_ctx(ctx);
	printf("ok\n");
	return 0;
}
