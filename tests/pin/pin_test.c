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

#define MF_FCP_PS(ps) "62298202782183023f00a5098001f18701008801008a01058b032f060fc60c9001" ps "83010183018183010a"

/* STATUS / SELECT and compare the full FCP (response without SW) */
static void expect_fcp(struct ss_context *ctx, const char *name, const char *hex, const char *exp_fcp)
{
	uint8_t cmd[256], resp[300], exp[300];
	size_t cmd_len = ss_binary_from_hexstr(cmd, sizeof(cmd), hex);
	size_t resp_len = ss_application_apdu_transact(ctx, resp, sizeof(resp), cmd, &cmd_len);
	size_t exp_len = ss_binary_from_hexstr(exp, sizeof(exp), exp_fcp);

	printf("%s: %s\n", name, ss_hexdump(resp, resp_len));
	assert(resp_len == exp_len + 2);
	assert(memcmp(resp, exp, exp_len) == 0);
	assert(resp[resp_len - 2] == 0x90 && resp[resp_len - 1] == 0x00);
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

	/* CHANGE PIN must reset the retry counter on success, the same as
	 * VERIFY PIN: a failed attempt followed by a successful change must
	 * not leave the counter one attempt closer to blocked. PIN1 ships
	 * disabled and CHANGE PIN refuses a disabled PIN, so enable it first. */
	sw = transact(ctx, "002800010831323334ffffffff", NULL);
	printf("ENABLE PIN1: %04x\n", sw);
	assert(sw == 0x9000);

	sw = transact(ctx, "002400011039393939ffffffff34333231ffffffff", NULL);
	printf("CHANGE PIN1 with wrong old PIN: %04x\n", sw);
	assert(sw == 0x63c2);

	sw = transact(ctx, "002400011031323334ffffffff34333231ffffffff", NULL);
	printf("CHANGE PIN1 with correct old PIN: %04x\n", sw);
	assert(sw == 0x9000);

	sw = transact(ctx, "0020000100", NULL);
	printf("VERIFY PIN1 remaining tries after CHANGE PIN: %04x\n", sw);
	assert(sw == 0x63c3);

	/* The PIN status template (C6) follows the PIN state: patched in place
	 * on the already selected MF, and generated fresh on a new SELECT. */
	expect_fcp(ctx, "STATUS MF, PIN1 enabled", "80f2000001", MF_FCP_PS("a0"));
	expect_fcp(ctx, "SELECT MF, PIN1 enabled", "00a40004023f00", MF_FCP_PS("a0"));

	sw = transact(ctx, "002600010834333231ffffffff", NULL); /* DISABLE with the changed PIN "4321" */
	printf("DISABLE PIN1: %04x\n", sw);
	assert(sw == 0x9000);

	expect_fcp(ctx, "STATUS MF, PIN1 disabled", "80f2000001", MF_FCP_PS("20"));

	ss_free_ctx(ctx);

	return 0;
}
