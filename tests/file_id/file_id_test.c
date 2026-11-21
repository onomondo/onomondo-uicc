/*
 * Copyright (c) 2026 Onomondo ApS. All rights reserved.
 *
 * SPDX-License-Identifier: GPL-3.0-only
 *
 * CREATE FILE with a file ID that is not 2 bytes long: TS 102 222 V17.1.0 Tables 3 and 4 code it
 * as exactly 2 bytes, so the card answers '6A80' (Table 6) and stores nothing.
 */

#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <onomondo/softsim/softsim.h>
#include <onomondo/softsim/utils.h>

/* allow test to silence noisy logs when comparing output */
extern uint32_t ss_log_mask;

/* Send one APDU, print "<name>: <response>" and require its status word. */
static void step(struct ss_context *ctx, const char *name, const char *hex, uint16_t sw_exp)
{
	uint8_t cmd[300];
	uint8_t rsp[300];
	size_t cmd_len = ss_binary_from_hexstr(cmd, sizeof(cmd), hex);
	size_t rsp_len = ss_application_apdu_transact(ctx, rsp, sizeof(rsp), cmd, &cmd_len);

	printf("%s: %s\n", name, ss_hexdump(rsp, rsp_len));
	fflush(stdout); /* keep the trail when the assert fires */
	assert(rsp_len >= 2 && ((rsp[rsp_len - 2] << 8) | rsp[rsp_len - 1]) == sw_exp);
}

int main(void)
{
	struct ss_context *ctx;

	ss_log_mask = 0;
	ctx = ss_new_ctx();
	ss_reset(ctx);
	ss_log_mask = 0;

	/* The shipped MF has no access rule for CREATE FILE: as ADM1, give the MF (EF.ARR record 15)
	 * ADM1 for every DF access mode. */
	step(ctx, "verify ADM1", "0020000a0831323334ffffffff", 0x9000);
	step(ctx, "select EF.ARR", "00a4000c022f06", 0x9000);
	step(ctx, "update the MF's rule",
	     "00dc0f0428"
	     "80017fa40683010a950108ffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
	     0x9000);
	step(ctx, "select MF", "00a4000c023f00", 0x9000);

	step(ctx, "create DF, 4-byte file ID, DF name",
	     "00e000001b6219"
	     "82027821830400007f238405a0000000aa8a01058b032f060f",
	     0x6a80);
	step(ctx, "create EF, 4-byte file ID",
	     "00e000001a6218"
	     "82024121830400002f778a01058b032f0610800200048800",
	     0x6a80);
	step(ctx, "select 7F23: not created", "00a4000c027f23", 0x6a82);
	step(ctx, "select 2F77: not created", "00a4000c022f77", 0x6a82);

	step(ctx, "create DF 7F21, DF name", "00e000001962178202782183027f218405a0000000aa8a01058b032f060f", 0x9000);
	step(ctx, "select MF", "00a4000c023f00", 0x9000);
	step(ctx, "select it by DF name", "00a4040405a0000000aa", 0x9000);

	ss_free_ctx(ctx);
	return 0;
}
