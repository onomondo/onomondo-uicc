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

/* EF.DIR (2F00) under the MF: linear fixed, 2 records of 38 bytes, readable
 * without any PIN. Record 1 holds the application template, record 2 is pure
 * padding, so the payload tells apart which record the pointer names.
 * EF.EPSNSC (6FE4) under ADF.USIM: 1 record of 54 bytes, READ and UPDATE
 * behind PIN1, which the checked-in profile ships disabled. Every command
 * with write intent below is rejected before the storage layer, so the test
 * runs read-only against the checked-in files/ tree. */
#define SELECT_DIR "00a4000c022f00"
#define SELECT_ADF "00a4000c027ff0"
#define SELECT_EPSNSC "00a4000c026fe4"
#define DIR_REC1 "61194f10a0000000871002ffffffff890709000050055553696d31ffffffffffffffffffffff"
#define DIR_REC2                                   \
	"ffffffffffffffffffffffffffffffffffffffff" \
	"ffffffffffffffffffffffffffffffffffff"
#define EPSNSC_REC                                 \
	"ffffffffffffffffffffffffffffffffffffffff" \
	"ffffffffffffffffffffffffffffffffffffffff" \
	"ffffffffffffffffffffffffffff"

static uint16_t transact(struct ss_context *ctx, const char *label, const char *hex, char *data_out)
{
	uint8_t cmd[300];
	uint8_t resp[400];
	size_t i;
	uint16_t sw = 0;
	size_t cmd_len = ss_binary_from_hexstr(cmd, sizeof(cmd), hex);
	size_t resp_len = ss_application_apdu_transact(ctx, resp, sizeof(resp), cmd, &cmd_len);

	data_out[0] = '\0';
	if (resp_len >= 2) {
		sw = (uint16_t)((resp[resp_len - 2] << 8) | resp[resp_len - 1]);
		for (i = 0; i < resp_len - 2; i++)
			sprintf(&data_out[i * 2], "%02x", resp[i]);
	}
	printf("%s: sw=%04x data=%s\n", label, sw, data_out);
	return sw;
}

int main(void)
{
	struct ss_context *ctx;
	char data[801];
	uint16_t sw;

	ss_log_mask = 0;
	ctx = ss_new_ctx();
	ss_reset(ctx);
	ss_log_mask = 0;

	sw = transact(ctx, "SELECT EF.DIR", SELECT_DIR, data);
	assert(sw == 0x9000);

	/* Table 11.11 of TS 102 221: in absolute/current mode P1 = '00' names
	 * the record the pointer holds. A SELECT leaves the pointer unset, so
	 * there is no such record yet. Previously both commands forwarded
	 * record 0 to the storage layer and reported 6a84. */
	sw = transact(ctx, "READ RECORD current, pointer unset", "00b2000426", data);
	assert(sw == 0x6a83);
	sw = transact(ctx, "SEARCH RECORD from current, pointer unset", "00a200040161", data);
	assert(sw == 0x6a83);

	/* The rejected commands must not have set the pointer: NEXT from an
	 * unset pointer reads record 1. */
	sw = transact(ctx, "READ RECORD next (1)", "00b2000226", data);
	assert(sw == 0x9000 && strcmp(data, DIR_REC1) == 0);

	sw = transact(ctx, "READ RECORD current (1)", "00b2000426", data);
	assert(sw == 0x9000 && strcmp(data, DIR_REC1) == 0);

	/* Move the pointer to record 2; the current record must follow. */
	sw = transact(ctx, "READ RECORD next (2)", "00b2000226", data);
	assert(sw == 0x9000 && strcmp(data, DIR_REC2) == 0);
	sw = transact(ctx, "READ RECORD current (2)", "00b2000426", data);
	assert(sw == 0x9000 && strcmp(data, DIR_REC2) == 0);

	/* A simple forward search with P1 = '00' begins at the current record:
	 * from record 2 the pattern (only in record 1) is not found, from
	 * record 1 it is. */
	sw = transact(ctx, "SEARCH RECORD from current", "00a200040161", data);
	assert(sw == 0x9000 && data[0] == '\0');
	sw = transact(ctx, "SEARCH RECORD from record 1", "00a201040161", data);
	assert(sw == 0x9000 && strcmp(data, "01") == 0);

	/* A SELECT makes the pointer undefined again (TS 102 221 clause
	 * 11.1.1.1). */
	sw = transact(ctx, "SELECT ADF.USIM", SELECT_ADF, data);
	assert(sw == 0x9000);
	sw = transact(ctx, "SELECT EF.EPSNSC", SELECT_EPSNSC, data);
	assert(sw == 0x9000);

	sw = transact(ctx, "READ RECORD current after SELECT", "00b2000436", data);
	assert(sw == 0x6a83);

	/* Previously the write intent reached the storage layer. */
	sw = transact(ctx, "UPDATE RECORD current, pointer unset", "00dc000436" EPSNSC_REC, data);
	assert(sw == 0x6a83);

	ss_free_ctx(ctx);
	return 0;
}
