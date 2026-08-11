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

/* the enlarged size of the private copy of EF.ICCID (3f00/2fe2) */
#define FILE_LEN 300

static uint16_t transact(struct ss_context *ctx, const char *hex, size_t *out_len)
{
	uint8_t cmd[256];
	uint8_t resp[300];
	size_t cmd_len = ss_binary_from_hexstr(cmd, sizeof(cmd), hex);
	size_t resp_len = ss_application_apdu_transact(ctx, resp, sizeof(resp), cmd, &cmd_len);
	if (out_len)
		*out_len = resp_len;
	if (resp_len >= 2)
		return (uint16_t)((resp[resp_len - 2] << 8) | resp[resp_len - 1]);
	return 0;
}

int main(void)
{
	struct ss_context *ctx;
	uint16_t sw;
	FILE *f;
	int i;

	/* Grow this test's private copy of EF.ICCID (transparent) to FILE_LEN
	 * bytes. The storage backend takes the file length from the on-disk
	 * hex file, so the FCP declared size does not matter here. */
	f = fopen("files/3f00/2fe2", "w");
	assert(f);
	for (i = 0; i < FILE_LEN; i++)
		fputs("ff", f);
	fclose(f);

	ss_log_mask = 0;
	ctx = ss_new_ctx();
	ss_reset(ctx);
	ss_log_mask = 0;

	size_t len;

	sw = transact(ctx, "00a40804022fe200", NULL);
	printf("SELECT EF.ICCID: %04x\n", sw);
	assert(sw == 0x9000);

	/* On a too-large Le the handler answers '6C' with the short Le for the
	 * reissued command in SW2, where '00' encodes 256 (ISO/IEC 7816-4
	 * clauses 5.4.5 and 5.3.2). ss_application_apdu_transact reissues
	 * internally, so what is observable here is the reissued read: the
	 * response must carry every available byte (up to 256) plus the
	 * status word. '6CFF' instead of '6C00' would drop a byte. */

	/* 44 bytes past offset 256, short Le '00' (256) -> 6C2C -> 44 bytes */
	sw = transact(ctx, "00b0010000", &len);
	printf("READ BINARY offset 256, 44 available: len=%u sw=%04x\n", (unsigned int)len, sw);
	assert(sw == 0x9000 && len == 44 + 2);

	/* exactly 256 bytes past offset 44, extended Le 512 -> 6C00 -> 256 bytes */
	sw = transact(ctx, "00b0002c000200", &len);
	printf("READ BINARY offset 44, 256 available: len=%u sw=%04x\n", (unsigned int)len, sw);
	assert(sw == 0x9000 && len == 256 + 2);

	/* 300 bytes past offset 0, extended Le 512 -> 6C00 -> 256 bytes, the
	 * most one short APDU can carry */
	sw = transact(ctx, "00b00000000200", &len);
	printf("READ BINARY offset 0, 300 available: len=%u sw=%04x\n", (unsigned int)len, sw);
	assert(sw == 0x9000 && len == 256 + 2);

	ss_free_ctx(ctx);
	return 0;
}
