/*
 * Copyright (c) 2024 Onomondo ApS. All rights reserved.
 *
 * SPDX-License-Identifier: GPL-3.0-only
 */

#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include <onomondo/softsim/softsim.h>
#include <onomondo/softsim/utils.h>

extern uint32_t ss_log_mask;

/* Large enough to carry an extended Case-3/4 APDU with Lc up to 65535. */
static uint8_t cmd_buf[5 + 65535];

static uint16_t transact_buf(struct ss_context *ctx, uint8_t *cmd, size_t cmd_len)
{
	uint8_t resp[300];
	size_t resp_len = ss_application_apdu_transact(ctx, resp, sizeof(resp), cmd, &cmd_len);
	assert(resp_len >= 2);
	return (uint16_t)((resp[resp_len - 2] << 8) | resp[resp_len - 1]);
}

static uint16_t transact_hex(struct ss_context *ctx, const char *hex)
{
	size_t cmd_len = ss_binary_from_hexstr(cmd_buf, sizeof(cmd_buf), hex);
	return transact_buf(ctx, cmd_buf, cmd_len);
}

int main(void)
{
	struct ss_context *ctx;
	uint16_t sw;

	ss_log_mask = 0;
	ctx = ss_new_ctx();
	ss_reset(ctx);
	ss_log_mask = 0;

	/* Extended Case-2 READ BINARY with Le=257 must be rejected with SW=6700. */
	sw = transact_hex(ctx, "00b00000000101");
	printf("extended Le=257: %04x\n", sw);
	assert(sw == 0x6700);

	/* Extended Case-2 READ BINARY with Le=65535 (encoded as 00 00 00) must
	 * be rejected with SW=6700. */
	sw = transact_hex(ctx, "00b00000000000");
	printf("extended Le=65535: %04x\n", sw);
	assert(sw == 0x6700);

	/* Extended Case-3 UPDATE BINARY with Lc=257 must be rejected with
	 * SW=6700 without crashing. This validates the parser-side memcpy
	 * guard at apdu.c: without it, the 257-byte data field overflows
	 * apdu->cmd[256] before the dispatcher ever runs. */
	memset(cmd_buf, 0, sizeof(cmd_buf));
	cmd_buf[0] = 0x00;
	cmd_buf[1] = 0xd6;
	cmd_buf[2] = 0x00;
	cmd_buf[3] = 0x00;
	cmd_buf[4] = 0x00;
	cmd_buf[5] = 0x01;
	cmd_buf[6] = 0x01;
	sw = transact_buf(ctx, cmd_buf, 4 + 3 + 257);
	printf("extended Lc=257: %04x\n", sw);
	assert(sw == 0x6700);

	/* Extended Case-4 UPDATE BINARY with Lc=257 AND Le=257 must be
	 * rejected. Exercises both halves of the `lc > 256 || le > 256`
	 * guard in a single APDU. */
	memset(cmd_buf, 0, sizeof(cmd_buf));
	cmd_buf[0] = 0x00;
	cmd_buf[1] = 0xd6;
	cmd_buf[2] = 0x00;
	cmd_buf[3] = 0x00;
	cmd_buf[4] = 0x00;
	cmd_buf[5] = 0x01;
	cmd_buf[6] = 0x01;
	/* cmd_buf[7..263] = 0 (data, 257 bytes) */
	cmd_buf[264] = 0x01;
	cmd_buf[265] = 0x01;
	sw = transact_buf(ctx, cmd_buf, 4 + 3 + 257 + 2);
	printf("extended Case-4 Lc=257 Le=257: %04x\n", sw);
	assert(sw == 0x6700);

	/* Extended Case-2 STATUS with Le=257 must be rejected. Confirms
	 * the dispatcher guard fires regardless of which command is
	 * invoked, not just READ BINARY. */
	sw = transact_hex(ctx, "80f20000000101");
	printf("extended STATUS Le=257: %04x\n", sw);
	assert(sw == 0x6700);

	/* Extended Case-4 SELECT (file 2FE2) with Le=257 must be rejected.
	 * Same dispatcher universality check on a Case-4 short-Lc command. */
	sw = transact_hex(ctx, "00a408040000022fe20101");
	printf("extended SELECT Le=257: %04x\n", sw);
	assert(sw == 0x6700);

	/* After-rejection sanity: a rejected APDU must not poison subsequent
	 * traffic on the same context. Send a known-rejected extended APDU,
	 * then a short STATUS, and verify STATUS is not blocked by the guard. */
	sw = transact_hex(ctx, "00b00000000101");
	assert(sw == 0x6700);
	sw = transact_hex(ctx, "80f20000");
	printf("STATUS after rejection: %04x\n", sw);
	assert(sw != 0x6700);

	/* Positive control: short Case-2 with Le=256 (encoded as 0x00) must
	 * NOT trip the > 256 guard. The handler may return any non-6700 SW
	 * depending on selection state; we only care that the central guard
	 * does not fire on the boundary value. */
	sw = transact_hex(ctx, "00b0000000");
	printf("short Le=256: %04x\n", sw);
	assert(sw != 0x6700);

	/* Positive control: short Case-3 with Lc=255 (max short) must NOT
	 * trip the > 256 guard. */
	memset(cmd_buf, 0, sizeof(cmd_buf));
	cmd_buf[0] = 0x00;
	cmd_buf[1] = 0xd6;
	cmd_buf[2] = 0x00;
	cmd_buf[3] = 0x00;
	cmd_buf[4] = 0xff;
	/* cmd_buf[5..259] = 0 (data, 255 bytes) */
	sw = transact_buf(ctx, cmd_buf, 5 + 255);
	printf("short Case-3 Lc=255: %04x\n", sw);
	assert(sw != 0x6700);

	/* Positive control: Case-1 APDU (header only, no Lc/Le). Must not
	 * trip the guard. */
	sw = transact_hex(ctx, "80f20000");
	printf("Case-1 STATUS: %04x\n", sw);
	assert(sw != 0x6700);

	ss_free_ctx(ctx);
	return 0;
}
