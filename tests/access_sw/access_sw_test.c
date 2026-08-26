/*
 * Copyright (c) 2026 Onomondo ApS. All rights reserved.
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

/* EF.LOCI (6F7E, transparent, 11 bytes) and EF.EST (6FE4, one record of 54
 * bytes) both gate READ and UPDATE on PIN1, which the checked-in profile
 * ships disabled. The test enables PIN1 without verifying it, so every
 * access check below must fail -- with 6982, security status not satisfied,
 * and SEARCH RECORD must not return matches. Enabling PIN1 writes the PIN
 * state, so the test runs on a private copy of files/. */
#define SELECT_ADF "00a4000c027ff0"
#define SELECT_LOCI "00a4000c026f7e"
#define SELECT_EST "00a4000c026fe4"
#define ENABLE_PIN1 "002800010831323334ffffffff"
#define VERIFY_PIN1 "002000010831323334ffffffff"
#define LOCI_DATA "ffffffffffffffffffffff"
#define REC_DATA                                   \
	"ffffffffffffffffffffffffffffffffffffffff" \
	"ffffffffffffffffffffffffffffffffffffffff" \
	"ffffffffffffffffffffffffffff"

static uint16_t transact(struct ss_context *ctx, const char *hex)
{
	uint8_t cmd[300];
	uint8_t resp[400];
	size_t cmd_len = ss_binary_from_hexstr(cmd, sizeof(cmd), hex);
	size_t resp_len = ss_application_apdu_transact(ctx, resp, sizeof(resp), cmd, &cmd_len);
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

	sw = transact(ctx, SELECT_ADF);
	printf("SELECT ADF.USIM: %04x\n", sw);
	assert(sw == 0x9000);

	sw = transact(ctx, SELECT_LOCI);
	printf("SELECT EF.LOCI: %04x\n", sw);
	assert(sw == 0x9000);

	/* Disabled PIN1 satisfies the access condition. */
	sw = transact(ctx, "00b000000b");
	printf("READ BINARY with PIN1 disabled: %04x\n", sw);
	assert(sw == 0x9000);

	sw = transact(ctx, ENABLE_PIN1);
	printf("ENABLE PIN1: %04x\n", sw);
	assert(sw == 0x9000);

	sw = transact(ctx, "00b000000b");
	printf("READ BINARY without PIN1: %04x\n", sw);
	assert(sw == 0x6982);

	sw = transact(ctx, "00d600000b" LOCI_DATA);
	printf("UPDATE BINARY without PIN1: %04x\n", sw);
	assert(sw == 0x6982);

	sw = transact(ctx, SELECT_EST);
	printf("SELECT EF.EST: %04x\n", sw);
	assert(sw == 0x9000);

	sw = transact(ctx, "00b2010436");
	printf("READ RECORD without PIN1: %04x\n", sw);
	assert(sw == 0x6982);

	sw = transact(ctx, "00dc010436" REC_DATA);
	printf("UPDATE RECORD without PIN1: %04x\n", sw);
	assert(sw == 0x6982);

	/* SEARCH RECORD never checked the READ condition at all: it returned
	 * the match result with 9000. */
	sw = transact(ctx, "00a2010401ff");
	printf("SEARCH RECORD without PIN1: %04x\n", sw);
	assert(sw == 0x6982);

	/* A verified PIN1 satisfies the condition again. */
	sw = transact(ctx, VERIFY_PIN1);
	printf("VERIFY PIN1: %04x\n", sw);
	assert(sw == 0x9000);

	sw = transact(ctx, "00b2010436");
	printf("READ RECORD with PIN1 verified: %04x\n", sw);
	assert(sw == 0x9000);

	sw = transact(ctx, SELECT_LOCI);
	printf("SELECT EF.LOCI again: %04x\n", sw);
	assert(sw == 0x9000);

	sw = transact(ctx, "00b000000b");
	printf("READ BINARY with PIN1 verified: %04x\n", sw);
	assert(sw == 0x9000);

	ss_free_ctx(ctx);
	return 0;
}
