/*
 * Copyright (c) 2024 Onomondo ApS. All rights reserved.
 *
 * SPDX-License-Identifier: GPL-3.0-only
 */

#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <onomondo/softsim/softsim.h>
#include <onomondo/softsim/utils.h>

/* allow test to silence noisy logs when comparing output */
extern uint32_t ss_log_mask;

static uint16_t transact(struct ss_context *ctx, const char *hex, size_t *out_len)
{
	uint8_t cmd[256];
	uint8_t resp[300];
	size_t cmd_len = ss_binary_from_hexstr(cmd, sizeof(cmd), hex);
	size_t resp_len = ss_application_apdu_transact(ctx, resp, sizeof(resp), cmd, &cmd_len);
	if (out_len)
		*out_len = resp_len;
	if (resp_len >= 2)
		return (uint16_t)((resp[resp_len - 2] << 8) | resp[resp_len - 1]);
	return 0;
}

int main(void)
{
	struct ss_context *ctx;
	uint16_t sw;

	ss_log_mask = 0;
	ctx = ss_new_ctx();
	ss_reset(ctx);
	ss_log_mask = 0;

	/* VERIFY PIN with Lc=0 via 5-byte APDU (p3=0x00).
	 * ss_apdu_parse_exhaustive misclassifies this as Case 2 (Le=256); the
	 * Case 3 handler in apdu_transact must clear apdu->le so the out: check
	 * does not rewrite the correct SW=63Cx to SW=6700. */
	sw = transact(ctx, "0020000100", NULL);
	printf("VERIFY PIN1 remaining tries: %04x\n", sw);
	assert((sw & 0xff00) == 0x6300);

	sw = transact(ctx, "0020008100", NULL);
	printf("VERIFY PIN2 remaining tries: %04x\n", sw);
	assert((sw & 0xff00) == 0x6300);

	ss_free_ctx(ctx);
	return 0;
}
