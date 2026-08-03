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
	"00a4000c023f00", "00a40804022f0500",
	// "00b000000a",
	"801000002237e9ffe3119c001fa500001fe260000043cb00000000400040000000080080011010", "00a40804022f0800",
	// "00b0000005",
	"00a40804022f0600",
	// "00b2010428",
	"00a40004022f0000",
	// "00b2010426",
	// "00b2020426",
	"00a4040410a0000000871002ffffffff8907090000", "00200001", "002c0001", "00200081", "002c0081",
	"00a40804022f0e00",
	// "00b000000a",
	"00a40804047fff6f0500",
	// "00b000000a",
	"80f2000032", "00a40804047fff6fad00",
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
	"80f2010c", "00a40804047fff6fe800", "80f2000032",
	/* perform authentication */
};

/* An unknown class must be answered 6e00, an unknown instruction 6d00.
 * TS 102 221 clause 10.2.1.5.0; TS 31.122 clause 6.7.2.1 steps r) and t). */
static void unknown_class_test(struct ss_context *ctx)
{
	const struct {
		uint8_t apdu[5];
		uint16_t sw;
	} cases[] = {
		{ { 0x30, 0xc0, 0x00, 0x00, 0x00 }, 0x6e00 }, /* class '30' */
		{ { 0xa0, 0xf2, 0x00, 0x00, 0x00 }, 0x6e00 }, /* GSM class 'A0' */
		{ { 0x00, 0x6f, 0x00, 0x00, 0x00 }, 0x6d00 }, /* known class, unknown INS */
	};
	uint8_t resp[300];

	for (size_t i = 0; i < SS_ARRAY_SIZE(cases); i++) {
		uint8_t cmd[sizeof(cases[i].apdu)];
		size_t cmd_len = sizeof(cmd);
		size_t resp_len;

		memcpy(cmd, cases[i].apdu, sizeof(cmd));
		memset(resp, 0, sizeof(resp));
		resp_len = ss_transact(ctx, resp, sizeof(resp), cmd, &cmd_len);

		assert(resp_len == 2);
		assert(((resp[0] << 8) | resp[1]) == cases[i].sw);
	}
}

/* ss_transact() requires the full 5-byte header; every shorter prefix
 * answers 6700. */
static void transact_short_apdu_test(struct ss_context *ctx)
{
	/* 5 bytes of a plausible SELECT; only the first `len` are handed over. */
	uint8_t cmd[] = { 0x00, 0xa4, 0x00, 0x0c, 0x02 };
	uint8_t resp[300];

	for (size_t len = 0; len < sizeof(cmd); len++) {
		size_t cmd_len = len;
		size_t resp_len;

		memset(resp, 0, sizeof(resp));
		resp_len = ss_transact(ctx, resp, sizeof(resp), cmd, &cmd_len);

		/* SS_SW_ERR_CHECKING_WRONG_LENGTH, big endian */
		assert(resp_len == 2);
		assert(resp[0] == 0x67 && resp[1] == 0x00);
	}
}

/* Both CLA rejections answer before a logical channel is resolved, so the APDU
 * has no holder and must be freed rather than parked. First APDU, no auth. */
static void transact_unresolved_lchan_test(struct ss_context *ctx)
{
	/* CLA 0x0c sets the secure-messaging bits; CLA 0x01 leaves them clear and
	 * names logical channel 1, so each reaches a different rejection. */
	struct {
		uint8_t cla;
		uint8_t sw2;
	} cases[] = {
		{ 0x0c, 0x82 }, /* SS_SW_ERR_FUNCTION_IN_CLA_NOT_SUPP_SM */
		{ 0x01, 0x81 }, /* SS_SW_ERR_FUNCTION_IN_CLA_NOT_SUPP_LCHAN */
	};
	uint8_t resp[300];

	for (size_t i = 0; i < SS_ARRAY_SIZE(cases); i++) {
		uint8_t cmd[] = { cases[i].cla, 0xa4, 0x00, 0x0c, 0x02 };
		size_t cmd_len = sizeof(cmd);
		size_t resp_len;

		memset(resp, 0, sizeof(resp));
		resp_len = ss_transact(ctx, resp, sizeof(resp), cmd, &cmd_len);

		assert(resp_len == 2);
		assert(resp[0] == 0x68 && resp[1] == cases[i].sw2);
	}
}

int main(void)
{
	struct ss_context *ctx;

	ctx = ss_new_ctx();
	ss_reset(ctx);

	unknown_class_test(ctx);
	ss_reset(ctx);

	transact_short_apdu_test(ctx);
	ss_reset(ctx);

	transact_unresolved_lchan_test(ctx);
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
