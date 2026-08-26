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

/* A file command with a DF or ADF selected must answer 6986, command not
 * allowed, no EF selected -- not 6981, which is for an EF whose structure
 * does not fit the command. Read-only: nothing here writes to files/. */
#define SELECT_MF "00a4000c023f00"
#define SELECT_ADF "00a4000c027ff0"
#define SELECT_ICCID "00a4000c022fe2"

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

	/* The MF is current after a reset. */
	sw = transact(ctx, "00b0000001");
	printf("READ BINARY with the MF selected: %04x\n", sw);
	assert(sw == 0x6986);

	sw = transact(ctx, "00b2010401");
	printf("READ RECORD with the MF selected: %04x\n", sw);
	assert(sw == 0x6986);

	sw = transact(ctx, SELECT_ADF);
	printf("SELECT ADF.USIM: %04x\n", sw);
	assert(sw == 0x9000);

	sw = transact(ctx, "00b0000001");
	printf("READ BINARY with the ADF selected: %04x\n", sw);
	assert(sw == 0x6986);

	/* An EF whose structure does not fit the command keeps 6981. */
	sw = transact(ctx, SELECT_MF);
	printf("SELECT MF: %04x\n", sw);
	assert(sw == 0x9000);

	sw = transact(ctx, SELECT_ICCID);
	printf("SELECT EF.ICCID: %04x\n", sw);
	assert(sw == 0x9000);

	sw = transact(ctx, "00b2010401");
	printf("READ RECORD on a transparent EF: %04x\n", sw);
	assert(sw == 0x6981);

	sw = transact(ctx, "00b000000a");
	printf("READ BINARY with an EF selected: %04x\n", sw);
	assert(sw == 0x9000);

	ss_free_ctx(ctx);
	return 0;
}
