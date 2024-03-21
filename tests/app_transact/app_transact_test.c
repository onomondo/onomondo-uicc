/*
 * Copyright (c) 2024 Onomondo ApS. All rights reserved.
 *
 * SPDX-License-Identifier: GPL-3.0-only
 */

#include <assert.h>
#include <errno.h>

#include <onomondo/softsim/log.h>
#include <onomondo/softsim/softsim.h>
#include <onomondo/softsim/utils.h>

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
const char *apdus[] = {
	"80f20000000168",
	"00a408040000022fe20168",
	"00b000000a",
	"00a408040000022f000168",
	"00b2010426",
	"00a408040000022f050168",
	"00b000000a",
	"00a408040000022f080168",
	"00b0000005",
	"80100000223301e842119c00078400001f2060000043c000000000400040000000000800801730",
	"00a408040000047f666fd20168",
	"00a40404000010a0000000871002ffffffff89070900000168",
	"00a408040000047fff6f070168",
	"00a408040000047fff6f380168",
	"00b000000f",
	"00a408040000047fff6fe30168",
	"00b0000012",
	"00a408040000047fff6fe40168",
	"00b2010436",
	"00a408040000047fff6f730168",
	"00b000000e",
	"00a408040000047fff6f7e0168",
	"00b000000b",
	"00a408040000047fff6f090168",
	"00b0000021",
	"00a408040000047fff6f310168",
	"00b0000001",
	"00a408040000047fff6f780168",
	"00b0000002",
	"00a408040000047fff6f7b0168",
	"00b000000c",
	"00a408040000047fff6f420168",
	"00b2010434",
	"00b2020433",
	"00a408040000087fff7f665f404f400168",
	"00a408040000087fff7f665f404f410168",
	"00a408040000087fff7f665f404f420168",
	"00a408040000087fff7f665f404f430168",
	"00a408040000087fff7f665f304f340168",
	"80f2010c",
	"00a408040000047fff6fe40168",
	"00dc010436a0348001078120ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff8204ffffffff8304ffffffff8401ff",
	"00a408040000022fe20001"
};

int main(void)
{
	struct ss_context *ctx;

	ctx = ss_new_ctx();
	ss_reset(ctx);

	// buffers and house keeping
	size_t cmd_len = 0, resp_len = 0;
	uint8_t resp[300] = { 0 };
	uint8_t cmd[256] = { 0 };
	size_t apdus_cnt = SS_ARRAY_SIZE(apdus);
	const char *cmd_string = NULL;

	for (size_t i = 0; i < apdus_cnt; i++) {
		cmd_string = apdus[i];

		cmd_len = ss_binary_from_hexstr(cmd, sizeof(cmd), cmd_string);
		resp_len = sizeof(resp);

		SS_LOGP(SAPDU, LINFO, ">>> Card APDU request %s >>>\n ", ss_hexdump(cmd, cmd_len));

		resp_len = ss_application_apdu_transact(ctx, resp, sizeof(resp), cmd, &cmd_len);

		SS_LOGP(SAPDU, LINFO, "<<< Card APDU response %s <<< \n\n\n ", ss_hexdump(resp, resp_len));
	}
	ss_free_ctx(ctx);

	return 0;
}
