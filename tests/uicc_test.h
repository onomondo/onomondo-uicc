/*
 * Copyright (c) 2026 Onomondo ApS. All rights reserved.
 *
 * SPDX-License-Identifier: GPL-3.0-only
 *
 * Shared helpers for tests that drive APDUs through the command dispatcher.
 */

#pragma once

#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include <onomondo/softsim/softsim.h>
#include <onomondo/softsim/utils.h>

/* Lets a test silence the logs so stdout stays comparable to its .ok file. */
extern uint32_t ss_log_mask;

/* Response body without SW, filled in by the helpers below. */
struct ut_rsp {
	uint8_t data[300];
	size_t len;
};

static struct ut_rsp ut_rsp;

static uint16_t ut_run(struct ss_context *ctx, const char *hex, int raw)
{
	uint8_t cmd[256];
	uint8_t resp[sizeof(ut_rsp.data)];
	size_t cmd_len = ss_binary_from_hexstr(cmd, sizeof(cmd), hex);
	size_t resp_len;

	if (raw)
		resp_len = ss_transact(ctx, resp, sizeof(resp), cmd, &cmd_len);
	else
		resp_len = ss_application_apdu_transact(ctx, resp, sizeof(resp), cmd, &cmd_len);

	if (resp_len < 2) {
		ut_rsp.len = 0;
		return 0;
	}

	ut_rsp.len = resp_len - 2;
	memcpy(ut_rsp.data, resp, ut_rsp.len);
	return (uint16_t)((resp[resp_len - 2] << 8) | resp[resp_len - 1]);
}

/* Application level: the 61xx/6Cxx exchange is driven internally. */
static uint16_t ut_apdu(struct ss_context *ctx, const char *hex)
{
	return ut_run(ctx, hex, 0);
}

/* Single transaction, so 61xx/6Cxx procedure bytes stay visible to the test. */
static uint16_t ut_apdu_raw(struct ss_context *ctx, const char *hex)
{
	return ut_run(ctx, hex, 1);
}

/* Print "<name>: <sw>" and require the status word to be sw_exp. */
static void ut_step(struct ss_context *ctx, const char *name, const char *hex, uint16_t sw_exp)
{
	uint16_t sw = ut_apdu(ctx, hex);

	printf("%s: %04x\n", name, sw);
	fflush(stdout);
	assert(sw == sw_exp);
}

/* As ut_step(), and require the response body to equal exp_data (hex, may be
 * NULL to only print it). */
static void ut_step_data(struct ss_context *ctx, const char *name, const char *hex, uint16_t sw_exp,
			 const char *exp_data)
{
	uint16_t sw = ut_apdu(ctx, hex);

	printf("%s: %04x %s\n", name, sw, ss_hexdump(ut_rsp.data, ut_rsp.len));
	fflush(stdout);
	assert(sw == sw_exp);

	if (exp_data) {
		uint8_t exp[sizeof(ut_rsp.data)];
		size_t exp_len = ss_binary_from_hexstr(exp, sizeof(exp), exp_data);

		assert(ut_rsp.len == exp_len);
		assert(memcmp(ut_rsp.data, exp, exp_len) == 0);
	}
}
