/*
 * Copyright (c) 2026 Onomondo ApS. All rights reserved.
 *
 * SPDX-License-Identifier: GPL-3.0-only
 */

/* atr_test: decode the ATR and check each declared capability against the code
 * or the file tree that has to implement it.
 *
 * The ATR is a promise to the terminal. Nothing else in the tree reads it back,
 * so without this the bytes are held in place only by a comment. Bit layouts are
 * ISO/IEC 7816-4:2005 Tables 85-88; interface bytes are ISO/IEC 7816-3 section 8.
 *
 * Changing a byte here changes TCK and is visible to every terminal, so a
 * deliberate change updates this test and runs the conformance gate. */

#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <onomondo/softsim/softsim.h>
#include <onomondo/softsim/utils.h>

#include "src/softsim/uicc/apdu.h"

/* Offsets into the ATR. TS is byte 0; the historical bytes start after TA3. */
#define ATR_TS 0
#define ATR_T0 1
#define ATR_TA1 2
#define ATR_TD1 3
#define ATR_TD2 4
#define ATR_TA3 5
#define ATR_HIST 6

#define HIST_CATEGORY 0
#define HIST_CARD_SERVICE 2 /* value of tag 3, after '31' */
#define HIST_CAP_SELECTION 4 /* card capabilities byte 1, after '73' */
#define HIST_CAP_CODING 5
#define HIST_CAP_CHAINING 6

static void atr_structure_test(const uint8_t *atr, size_t len)
{
	uint8_t tck = 0;
	size_t i;

	assert(atr[ATR_TS] == 0x3b); /* direct convention */

	/* T0 low nibble is the historical byte count; TCK follows them. */
	assert((atr[ATR_T0] & 0x0f) == 15);
	assert(len == ATR_HIST + 15 + 1);

	/* TD1 names T=0, TD2 names T=15, which is what makes TCK mandatory
	 * (ISO/IEC 7816-3 section 8.2.5). TCK covers T0 onwards. */
	assert((atr[ATR_TD1] & 0x0f) == 0);
	assert((atr[ATR_TD2] & 0x0f) == 15);
	for (i = 1; i < len - 1; i++)
		tck ^= atr[i];
	assert(tck == atr[len - 1]);

	/* TS 31.122 section 8.2.2: the low 6 bits of TA3 shall be one of
	 * '03', '06' or '07' -- at least two consecutive voltage classes. */
	{
		uint8_t classes = atr[ATR_TA3] & 0x3f;

		assert(classes == 0x03 || classes == 0x06 || classes == 0x07);
	}
}

/* Each declared capability against the thing that implements it. */
static void atr_claims_match_implementation_test(struct ss_context *ctx, const uint8_t *atr)
{
	const uint8_t *hist = &atr[ATR_HIST];
	uint8_t card_service = hist[HIST_CARD_SERVICE];
	uint8_t selection = hist[HIST_CAP_SELECTION];
	uint8_t coding = hist[HIST_CAP_CODING];
	uint8_t chaining = hist[HIST_CAP_CHAINING];
	uint8_t resp[300];
	uint8_t cmd[16];
	size_t cmd_len, resp_len;

	assert(hist[HIST_CATEGORY] == 0x80); /* compact-TLV */
	assert(hist[1] == 0x31); /* tag 3, length 1 */
	assert(hist[3] == 0x73); /* tag 7, length 3 */

	/* Card service data, Table 85. b1 = 0 says "card with MF", and the MF is
	 * selectable, which ss_fs_init() also relies on. */
	assert((card_service & 0x01) == 0);
	cmd_len = ss_binary_from_hexstr(cmd, sizeof(cmd), "00a4000c023f00");
	resp_len = ss_transact(ctx, resp, sizeof(resp), cmd, &cmd_len);
	assert(resp_len == 2 && resp[0] == 0x90 && resp[1] == 0x00);

	/* b4b3b2: '100' would be READ BINARY, '000' is READ RECORD(S). EF.DIR
	 * (2f00) is linear fixed in files/, so '000' is the accurate claim. */
	assert((card_service & 0x1c) == 0x00);
	{
		FILE *f = fopen("./files/3f00/2f00.def", "r");
		char def[128] = { 0 };
		size_t read_len;

		assert(f); /* ctest sets WORKING_DIRECTORY to the project root */
		read_len = fread(def, 1, sizeof(def) - 1, f);
		assert(read_len > 0);
		fclose(f);
		/* FCP tag 82, length 5, first descriptor byte 0x42:
		 * b3b2b1 = 010 = linear fixed. */
		assert(strstr(def, "820542") != NULL);
	}

	/* Selection methods, Table 86: by file identifier (b5) is exercised by the
	 * SELECT above; b1 = 0 correctly declines record-identifier addressing. */
	assert((selection & 0x10) != 0);
	assert((selection & 0x01) == 0);

	/* Data coding, Table 87: b8 = 0 says no EFs of TLV structure, and the data
	 * unit is 2 quartets, i.e. one byte -- which is what the binary offset in
	 * calc_read_write_offset() counts in. */
	assert((coding & 0x80) == 0);
	assert((coding & 0x0f) == 0x01);

	/* Third software function table, Table 88. */
	assert((chaining & 0x80) == 0); /* no command chaining */

	/* b7 = 0: no extended Lc/Le. The buffers this interface fills are 256
	 * bytes, so an extended length could not be honoured. */
	assert((chaining & 0x40) == 0);
	{
		struct ss_apdu probe;

		assert(sizeof(probe.cmd) == 256);
		assert(sizeof(probe.rsp) == 256);
	}

	/* b5b4 = 00: no logical channel assignment. b3b2b1 = 000: one channel.
	 * MANAGE CHANNEL and any non-zero channel number are refused. */
	assert((chaining & 0x18) == 0);
	assert((chaining & 0x07) == 0);
	{
		/* CLA 01 addresses logical channel 1 */
		cmd_len = ss_binary_from_hexstr(cmd, sizeof(cmd), "01a4000c023f00");
		resp_len = ss_transact(ctx, resp, sizeof(resp), cmd, &cmd_len);
		assert(resp_len == 2 && resp[0] == 0x68 && resp[1] == 0x81);

		/* MANAGE CHANNEL, open */
		cmd_len = ss_binary_from_hexstr(cmd, sizeof(cmd), "0070000001");
		resp_len = ss_transact(ctx, resp, sizeof(resp), cmd, &cmd_len);
		assert(resp_len == 2 && resp[0] == 0x68 && resp[1] == 0x81);
	}
}

/* ss_atr() must refuse a buffer it does not fit rather than overrun it, and the
 * refusal has to hold under NDEBUG. */
static void atr_short_buffer_test(struct ss_context *ctx)
{
	uint8_t full[64];
	size_t len = ss_atr(ctx, full, sizeof(full));
	size_t written;
	size_t i;

	assert(len > 0);

	for (i = 0; i < len; i++) {
		/* sized to exactly what is offered, so a write past it is an
		 * ASan report rather than a scribble on a roomy stack array */
		uint8_t *tight = malloc(i ? i : 1);

		assert(tight);
		memset(tight, 0xa5, i ? i : 1);
		/* the call stays outside the assert: NDEBUG drops the whole
		 * expression, and this run has to reach ss_atr() to mean anything */
		written = ss_atr(ctx, tight, i);
		assert(written == 0);
		/* nothing was written */
		assert(tight[0] == 0xa5);
		free(tight);
	}

	written = ss_atr(ctx, full, len);
	assert(written == len);
}

int main(void)
{
	struct ss_context *ctx;
	uint8_t atr[64];
	size_t len;

	ctx = ss_new_ctx();
	ss_reset(ctx);

	len = ss_atr(ctx, atr, sizeof(atr));
	assert(len > 0);

	atr_structure_test(atr, len);
	ss_reset(ctx);
	atr_claims_match_implementation_test(ctx, atr);
	ss_reset(ctx);
	atr_short_buffer_test(ctx);

	ss_free_ctx(ctx);

	printf("atr_test: %zu-byte ATR, all declared capabilities matched\n", len);
	return 0;
}
