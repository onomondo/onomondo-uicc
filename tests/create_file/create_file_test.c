/*
 * Copyright (c) 2026 Onomondo ApS. All rights reserved.
 *
 * SPDX-License-Identifier: GPL-3.0-only
 */

#include <assert.h>
#include <stdint.h>
#include <onomondo/softsim/softsim.h>
#include <onomondo/softsim/utils.h>

/* allow test to silence noisy logs */
extern uint32_t ss_log_mask;

/* Transparent EF 2F70 under the MF, 4 bytes, no SFI (22 bytes). */
#define FCP "8202412183022f708a01058b032f0610800200048800"

static uint16_t transact(struct ss_context *ctx, const char *hex)
{
	uint8_t cmd[300];
	uint8_t rsp[300];
	size_t cmd_len = ss_binary_from_hexstr(cmd, sizeof(cmd), hex);
	size_t rsp_len = ss_application_apdu_transact(ctx, rsp, sizeof(rsp), cmd, &cmd_len);

	assert(rsp_len >= 2);
	return (uint16_t)((rsp[rsp_len - 2] << 8) | rsp[rsp_len - 1]);
}

/* CREATE FILE checks the template before access, so no ADM is needed: padding inside it is
 * refused with 6A80, and the same template without padding reaches the access check (69xx). */
int main(void)
{
	struct ss_context *ctx;

	ss_log_mask = 0;
	ctx = ss_new_ctx();
	ss_reset(ctx);
	ss_log_mask = 0;

	assert(transact(ctx, "00e000001a6218" FCP "ffff") == 0x6a80);
	assert(transact(ctx, "00e00000186216" FCP) >> 8 == 0x69);

	ss_free_ctx(ctx);
	return 0;
}
