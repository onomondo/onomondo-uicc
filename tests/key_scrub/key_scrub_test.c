/*
 * Copyright (c) 2026 Onomondo ApS. All rights reserved.
 *
 * SPDX-License-Identifier: GPL-3.0-only
 */

/* K and OP/OPc must not reach the allocator in the clear. free() is wrapped
 * rather than polling a later malloc(), so the result cannot depend on when the
 * allocator reuses a chunk. */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <malloc.h>
#include <onomondo/softsim/softsim.h>
#include <onomondo/softsim/utils.h>

extern uint32_t ss_log_mask;

#define KEY_LEN 16

/* Both forms: storage.c stages the file as hex text, so scrubbing only the
 * decoded copy still releases the key. Hex needles are the file's own bytes. */
static struct needle {
	const char *what;
	uint8_t bytes[2 * KEY_LEN];
	size_t len;
} needles[] = {
	{ "K" },
	{ "OP/OPc" },
	{ "K as hex text" },
	{ "OP/OPc as hex text" },
};

static int armed;
static int hits;

void __real_free(void *ptr);

static int contains(const uint8_t *haystack, size_t len, const uint8_t *needle, size_t needle_len)
{
	for (size_t i = 0; i + needle_len <= len; i++)
		if (!memcmp(haystack + i, needle, needle_len))
			return 1;
	return 0;
}

void __wrap_free(void *ptr)
{
	if (armed && ptr) {
		size_t len = malloc_usable_size(ptr);

		for (size_t i = 0; i < sizeof(needles) / sizeof(needles[0]); i++) {
			if (contains(ptr, len, needles[i].bytes, needles[i].len)) {
				printf("FAIL: a %zu byte block released to the allocator still holds %s\n", len,
				       needles[i].what);
				hits++;
			}
		}
	}
	__real_free(ptr);
}

/* 16 identical bytes would match every scrubbed block. */
static int degenerate(const uint8_t *needle)
{
	for (size_t i = 1; i < KEY_LEN; i++)
		if (needle[i] != needle[0])
			return 0;
	return 1;
}

/* Needles come from the profile, so a changed key cannot make this vacuous. */
static int load_needles(void)
{
	struct ss_buf *raw;
	char hex[4 * KEY_LEN + 1];
	FILE *f = fopen("files/3f00/a001", "r");

	if (!f || !fgets(hex, sizeof(hex), f)) {
		printf("cannot read files/3f00/a001\n");
		return -1;
	}
	fclose(f);

	raw = ss_buf_from_hexstr(hex);
	if (!raw || raw->len < 2 * KEY_LEN) {
		printf("key data file too short\n");
		return -1;
	}
	memcpy(needles[0].bytes, raw->data, KEY_LEN);
	needles[0].len = KEY_LEN;
	memcpy(needles[1].bytes, raw->data + KEY_LEN, KEY_LEN);
	needles[1].len = KEY_LEN;
	ss_buf_free(raw);

	memcpy(needles[2].bytes, hex, 2 * KEY_LEN);
	needles[2].len = 2 * KEY_LEN;
	memcpy(needles[3].bytes, hex + 2 * KEY_LEN, 2 * KEY_LEN);
	needles[3].len = 2 * KEY_LEN;

	if (degenerate(needles[0].bytes) || degenerate(needles[1].bytes)) {
		printf("profile key material is not usable as a needle (K %02x.., OP/OPc %02x..)\n",
		       needles[0].bytes[0], needles[1].bytes[0]);
		return -1;
	}
	return 0;
}

int main(void)
{
	struct ss_context *ctx;
	uint8_t cmd[64], resp[300];
	size_t cmd_len, resp_len;
	uint16_t sw;

	if (load_needles() < 0)
		return 1;

	ss_log_mask = 0;
	ctx = ss_new_ctx();
	ss_reset(ctx);
	ss_log_mask = 0;

	/* GSM context: only RAND needed, no valid AUTN. RAND must differ from K,
	 * or the needle matches the command itself. */
	cmd_len = ss_binary_from_hexstr(cmd, sizeof(cmd), "008800801110a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5");
	armed = 1;
	resp_len = ss_application_apdu_transact(ctx, resp, sizeof(resp), cmd, &cmd_len);
	armed = 0;

	sw = resp_len >= 2 ? (uint16_t)((resp[resp_len - 2] << 8) | resp[resp_len - 1]) : 0;
	if (sw != 0x9000) {
		printf("FAIL: AUTHENTICATE answered %04x, expected 9000 -- key load not exercised\n", sw);
		return 1;
	}

	ss_free_ctx(ctx);

	if (hits)
		return 1;
	printf("No key material reached the allocator in the clear\n");
	return 0;
}
