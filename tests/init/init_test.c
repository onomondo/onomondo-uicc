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

/* init_test: Basic application APDU exchange smoke test
 *
 * This test runs a set of APDUs used during a modem / UICC
 * initialization: selects (MF, ADF and EFs), reads (records/binaries),
 * terminal profile downloads, and status commands. It is included to validate
 * the SIMs behavior during initialization sequences of an actual modem. */

const char *apdus[] = {
	"00a4000c023f00",
	"00a40804022f0500",
    // "00b000000a",
	"801000002337e9ffe3119c001fa500001fe260000043cb00000000400040000000080080011010",
	"00a40804022f0800",
    // "00b0000005",
	"00a40804022f0600",
    // "00b2010428",
	"00a40004022f0000",
    // "00b2010426",
    // "00b2020426",
    "00a4040410a0000000871002ffffffff8907090000",
    "00200001",
    "002c0001",
    "00200081",
    "002c0081",
    "00a40804022f0e00",
    // "00b000000a",
    "00a40804047fff6f0500",
    // "00b000000a",
    "80f2000032",
    "00a40804047fff6fad00",
    // "00b0000004",
    "00a40804047fff6f3800",
    // "00b000000f",
    "00a40804047fff6f0700",
    // "00b0000009",
    "00a40804047fff6f7800",
    // "00b0000002",
    "00a40804047fff6f3100",
    // "00b0000001",
    "00a40804047fff6fe300",
    // "00b0000012",
    "00a40804047fff6f7e00",
    // "00b000000b",
    "00a40804047fff6f7300",
    // "00b000000e",
    "00a40804047fff6f0900",
    // "00b0000021",
    "00a40804047fff6fe400",
    // "00b2010436",
    "00a40804047fff6f7b00",
    // "00b000000c",
    "80f2010c",
    "00a40804047fff6fe800",
    "80f2000032",
    /* perform authentication */
};

int main(void)
{
	struct ss_context *ctx;

	ctx = ss_new_ctx();
	ss_reset(ctx);

	size_t cmd_len = 0;
    size_t resp_len = 0;
	uint8_t resp[300] = { 0 };
	uint8_t cmd[256] = { 0 };
	size_t apdus_cnt = SS_ARRAY_SIZE(apdus);
	const char *cmd_string = NULL;

	for (size_t i = 0; i < apdus_cnt; i++) {
		cmd_string = apdus[i];
		cmd_len = ss_binary_from_hexstr(cmd, sizeof(cmd), cmd_string);
		resp_len = sizeof(resp);

	    printf(">>> Card APDU request %s >>>\n", ss_hexdump(cmd, cmd_len));

		resp_len = ss_application_apdu_transact(ctx, resp, sizeof(resp), cmd, &cmd_len);

	    printf("<<< Card APDU response %s <<<\n", ss_hexdump(resp, resp_len));
	}
    
	ss_free_ctx(ctx);

	return 0;
}
