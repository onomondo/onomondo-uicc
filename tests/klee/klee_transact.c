/*
 * Copyright (c) 2026 Onomondo ApS. All rights reserved.
 *
 * SPDX-License-Identifier: GPL-3.0-only
 *
 * KLEE harness for the full card path: ss_application_apdu_transact() linked
 * against the in-memory backend (src/softsim/fs_ram.c). The command header is
 * pinned per command (-DKLEE_CMD_*) and only the DATA field is left free, so
 * one run is a directed exploration of one handler. Time-bounded, not
 * exhaustive -- see README.md.
 *
 * The header is pinned with klee_assume() rather than written after
 * klee_make_symbolic(): the request stays one symbolic object (KLEE requires
 * that) and the witness .ktest is the exact APDU verbatim.
 */

#include <onomondo/softsim/softsim.h>

#include <klee/klee.h>

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#if defined(KLEE_CMD_SELECT)
/* SELECT FILE by 2-byte file id (TS 102 221 Case 3). */
static const uint8_t hdr[4] = { 0x00, 0xa4, 0x00, 0x04 };
#define DATA_LEN 2
#elif defined(KLEE_CMD_VERIFY_PIN)
/* VERIFY PIN, 8-byte secret against PIN1. */
static const uint8_t hdr[4] = { 0x00, 0x20, 0x00, 0x01 };
#define DATA_LEN 8
#elif defined(KLEE_CMD_ENVELOPE)
/* ENVELOPE: the SMS-PP / CAT gateway into the BER-TLV stack. */
static const uint8_t hdr[4] = { 0x80, 0xc2, 0x00, 0x00 };
#define DATA_LEN 16
#else
#error "define one of KLEE_CMD_SELECT / KLEE_CMD_VERIFY_PIN / KLEE_CMD_ENVELOPE"
#endif

#define REQ_LEN (5 + DATA_LEN) /* CLA INS P1 P2 Lc | DATA */
#define RESP_LEN 512 /* the entry point rejects response_buf_len < 258 */

void ss_fs_ram_reset(void);

int main(void)
{
	struct ss_context *ctx;
	uint8_t *req = malloc(REQ_LEN);
	uint8_t resp[RESP_LEN];
	size_t req_len = REQ_LEN;
	int i;

	if (!req)
		return 0;

	klee_make_symbolic(req, REQ_LEN, "apdu");
	for (i = 0; i < 4; i++)
		klee_assume(req[i] == hdr[i]);
	klee_assume(req[4] == DATA_LEN); /* Lc: makes this a well-formed Case 3 */

	/* Pristine image, fresh context: each explored path starts from the same
	 * card state (the backend forks copy-on-write per KLEE state). */
	ss_fs_ram_reset();
	ctx = ss_new_ctx();
	if (ctx) {
		ss_reset(ctx);
		ss_application_apdu_transact(ctx, resp, sizeof(resp), req, &req_len);
		ss_free_ctx(ctx);
	}

	free(req);
	return 0;
}
