/*
 * Copyright (c) 2026 Onomondo ApS. All rights reserved.
 *
 * SPDX-License-Identifier: GPL-3.0-only
 */

/* The Milenage SEQ state lives in one file (3f00/a002: 32 x 8-byte SEQ
 * values, 8-byte delta last). File systems written before the collapse carry
 * one file per value (a100..a11f + a120, sharing a100.def); get_seq_data()
 * migrates such a tree on the first AUTHENTICATE. This test rewrites the
 * fixture into the legacy layout, authenticates, and pins: the coalesced
 * a002 (with the accepted SQN in its slot), the untouched legacy files, and
 * the single-slot update on a second AUTHENTICATE. */

#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <onomondo/softsim/softsim.h>
#include <onomondo/softsim/utils.h>
#include "src/softsim/milenage/milenage.h"

extern uint32_t ss_log_mask;

/* Template key material (see utils/files-creation/softsim_fill_files_mf.pysim) */
static const uint8_t K[16] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
			       0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f };
static const uint8_t OPC[16] = { 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
				 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f };

#define LEGACY_DEF "6216820241218302a1008a01058b032f0606800200088800"
#define SLOT_ZERO "0000000000000000"
#define SLOT_FIVE "0000000000000042" /* pre-set bucket, proves coalescing */
#define DELTA_HEX "0000000010000000"

static void write_file(const char *path, const char *content)
{
	FILE *fd = fopen(path, "w");

	assert(fd);
	assert(fputs(content, fd) >= 0);
	fclose(fd);
}

/* Replace the fixture's a002 with the legacy per-slot layout */
static void install_legacy_layout(void)
{
	char path[64];
	int i;

	assert(remove("files/3f00/a002") == 0);
	assert(remove("files/3f00/a002.def") == 0);
	write_file("files/3f00/a100.def", LEGACY_DEF);
	for (i = 0; i < 32; i++) {
		snprintf(path, sizeof(path), "files/3f00/a1%02x", i);
		write_file(path, i == 5 ? SLOT_FIVE : SLOT_ZERO);
	}
	write_file("files/3f00/a120", DELTA_HEX);
}

static void assert_file_content(const char *path, const char *expected)
{
	char content[600] = { 0 };
	FILE *fd = fopen(path, "r");

	assert(fd);
	assert(fread(content, 1, sizeof(content) - 1, fd) == strlen(expected));
	fclose(fd);
	assert(strcmp(content, expected) == 0);
}

/* AUTHENTICATE (3G context) with a freshly generated AUTN for the given
 * 43-bit SEQ and 5-bit IND; returns the status word and stores the response
 * tag (0xDB = success, 0xDC = synchronisation failure) in *tag. */
static uint16_t authenticate(struct ss_context *ctx, uint64_t seq, uint8_t ind, uint8_t *tag)
{
	const uint8_t amf[2] = { 0x80, 0x00 };
	uint8_t rand[16] = { 0xa5, 0xa5, 0xa5, 0xa5, 0xa5, 0xa5, 0xa5, 0xa5,
			     0xa5, 0xa5, 0xa5, 0xa5, 0xa5, 0xa5, 0xa5, 0xa5 };
	uint8_t sqn[6], autn[16], ik[16], ck[16], res[8];
	size_t res_len = sizeof(res);
	uint8_t cmd[64], resp[300];
	size_t cmd_len = 0;
	size_t resp_len;

	/* SQN = SEQ || IND (TS 33.102 C.3.2, IND is the low 5 bits) */
	ss_uint64_store_to_be(autn, (seq << 5) | ind); /* borrow autn as scratch */
	memcpy(sqn, &autn[2], sizeof(sqn));
	milenage_generate(OPC, amf, K, sqn, rand, autn, ik, ck, res, &res_len);

	cmd[cmd_len++] = 0x00;
	cmd[cmd_len++] = 0x88;
	cmd[cmd_len++] = 0x00;
	cmd[cmd_len++] = 0x81; /* 3G security context */
	cmd[cmd_len++] = 0x22;
	cmd[cmd_len++] = sizeof(rand);
	memcpy(&cmd[cmd_len], rand, sizeof(rand));
	cmd_len += sizeof(rand);
	cmd[cmd_len++] = sizeof(autn);
	memcpy(&cmd[cmd_len], autn, sizeof(autn));
	cmd_len += sizeof(autn);

	resp_len = ss_application_apdu_transact(ctx, resp, sizeof(resp), cmd, &cmd_len);
	assert(resp_len >= 3);
	*tag = resp[0];
	return (resp[resp_len - 2] << 8) | resp[resp_len - 1];
}

int main(void)
{
	/* clang-format off */
	static const char expected_first[] =
		SLOT_ZERO "0000000000000050" SLOT_ZERO SLOT_ZERO      /* 0-3 */
		SLOT_ZERO SLOT_FIVE SLOT_ZERO SLOT_ZERO               /* 4-7 */
		SLOT_ZERO SLOT_ZERO SLOT_ZERO SLOT_ZERO SLOT_ZERO SLOT_ZERO SLOT_ZERO SLOT_ZERO
		SLOT_ZERO SLOT_ZERO SLOT_ZERO SLOT_ZERO SLOT_ZERO SLOT_ZERO SLOT_ZERO SLOT_ZERO
		SLOT_ZERO SLOT_ZERO SLOT_ZERO SLOT_ZERO SLOT_ZERO SLOT_ZERO SLOT_ZERO SLOT_ZERO
		DELTA_HEX;
	static const char expected_second[] =
		SLOT_ZERO "0000000000000060" SLOT_ZERO SLOT_ZERO
		SLOT_ZERO SLOT_FIVE SLOT_ZERO SLOT_ZERO
		SLOT_ZERO SLOT_ZERO SLOT_ZERO SLOT_ZERO SLOT_ZERO SLOT_ZERO SLOT_ZERO SLOT_ZERO
		SLOT_ZERO SLOT_ZERO SLOT_ZERO SLOT_ZERO SLOT_ZERO SLOT_ZERO SLOT_ZERO SLOT_ZERO
		SLOT_ZERO SLOT_ZERO SLOT_ZERO SLOT_ZERO SLOT_ZERO SLOT_ZERO SLOT_ZERO SLOT_ZERO
		DELTA_HEX;
	/* clang-format on */
	struct ss_context *ctx;
	uint8_t tag;

	install_legacy_layout();

	ss_log_mask = 0;
	ctx = ss_new_ctx();
	assert(ctx);
	ss_reset(ctx);

	/* First AUTHENTICATE on the legacy tree: SEQ 0x50 into IND 1 is fresh
	 * (above every bucket, within delta of the highest, 0x42). It must
	 * succeed AND leave the tree migrated. */
	assert(authenticate(ctx, 0x50, 1, &tag) == 0x9000);
	assert(tag == 0xDB);
	assert_file_content("files/3f00/a002", expected_first);

	/* The legacy files are left in place, contents untouched. */
	assert_file_content("files/3f00/a105", SLOT_FIVE);
	assert_file_content("files/3f00/a101", SLOT_ZERO);
	assert_file_content("files/3f00/a120", DELTA_HEX);

	/* Second AUTHENTICATE persists through a002 (single-slot update). */
	assert(authenticate(ctx, 0x60, 1, &tag) == 0x9000);
	assert(tag == 0xDB);
	assert_file_content("files/3f00/a002", expected_second);

	/* A stale SQN answers with a synchronisation failure (tag 0xDC), and
	 * the resync path must not touch the stored values -- the migrated
	 * buckets are actually enforced. */
	assert(authenticate(ctx, 0x42, 5, &tag) == 0x9000);
	assert(tag == 0xDC);
	assert_file_content("files/3f00/a002", expected_second);

	ss_free_ctx(ctx);
	printf("ok\n");
	return 0;
}
