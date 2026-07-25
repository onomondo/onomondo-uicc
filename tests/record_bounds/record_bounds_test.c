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

/* EF.EST (6FE4) under ADF.USIM: one record of 54 bytes, and its access rule
 * (EF.ARR record 4) gates both READ and UPDATE on PIN1, which the checked-in
 * profile ships disabled -- so the access check passes and the record-number
 * bounds check is what decides. Every out-of-range operation below is
 * rejected, so the test writes nothing and leaves files/ untouched. */
#define SELECT_ADF "00a4000c027ff0"
#define SELECT_EST "00a4000c026fe4"
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

	sw = transact(ctx, SELECT_EST);
	printf("SELECT EF.EST: %04x\n", sw);
	assert(sw == 0x9000);

	/* The last record stays reachable: the check rejects
	 * "> number_of_records", not ">=". */
	sw = transact(ctx, "00b2010436");
	printf("READ RECORD 1 of 1: %04x\n", sw);
	assert(sw == 0x9000);

	/* One past the last record. Previously the read reached the storage
	 * layer and failed there, reporting 6a84 "not enough memory". */
	sw = transact(ctx, "00b2020436");
	printf("READ RECORD 2 of 1: %04x\n", sw);
	assert(sw == 0x6a83);

	/* The data-integrity case: previously this appended a second record at
	 * end-of-file -- doubling the content file -- and returned 9000. */
	sw = transact(ctx, "00dc020436" REC_DATA);
	printf("UPDATE RECORD 2 of 1: %04x\n", sw);
	assert(sw == 0x6a83);

	/* SEARCH RECORD takes its starting record from P1 just as unchecked. */
	sw = transact(ctx, "00a2020401ff");
	printf("SEARCH RECORD from 2 of 1: %04x\n", sw);
	assert(sw == 0x6a83);

	/* ...and an in-range search must not be caught by that new check. */
	sw = transact(ctx, "00a2010401ff");
	printf("SEARCH RECORD from 1 of 1: %s\n", sw == 0x6a83 ? "wrongly rejected" : "accepted");
	assert(sw != 0x6a83);

	ss_free_ctx(ctx);
	return 0;
}
