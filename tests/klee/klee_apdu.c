/*
 * Copyright (c) 2026 Onomondo ApS. All rights reserved.
 *
 * SPDX-License-Identifier: GPL-3.0-only
 *
 * KLEE harness for the APDU wire-format parser, one length per build
 * (-DKLEE_APDU_LEN). The buffer is allocated at exactly that length, so a read
 * past the request is an out-of-bounds access KLEE reports -- the blind spot
 * of the oversized vectors in tests/apdu. The whole buffer is symbolic in one
 * call (KLEE wants whole objects; nothing branches on the data field).
 *
 * The two post-conditions catch what the memory model cannot: apdu->cmd and
 * apdu->rsp are adjacent in one struct, so an over-long Lc writes past
 * cmd[256] into rsp[] without leaving the object; and processed_bytes running
 * past the request is a logic defect, not a memory error. See README.md.
 */

#include "src/softsim/uicc/apdu.h"

#include <klee/klee.h>

#include <assert.h>
#include <stdint.h>
#include <stdlib.h>

#ifdef KLEE_REPLAY
#include <stdio.h>
#endif

#ifndef KLEE_APDU_LEN
#error "define KLEE_APDU_LEN to the request length to explore"
#endif
#if KLEE_APDU_LEN < APDU_HEADER_SIZE
#error "KLEE_APDU_LEN must be at least APDU_HEADER_SIZE -- the parser asserts it"
#endif

int main(void)
{
	uint8_t *buf = malloc(KLEE_APDU_LEN);
	struct ss_apdu apdu = { 0 };

	if (!buf)
		return 0;

	klee_make_symbolic(buf, KLEE_APDU_LEN, "apdu");

	ss_apdu_parse_exhaustive(&apdu, buf, KLEE_APDU_LEN);

	/* cmd[256] and rsp[256] are one allocation: an over-long Lc overflows cmd
	 * into rsp without leaving the object, so the copy alone never faults. */
	assert(apdu.lc <= sizeof(apdu.cmd));
	/* the out: guard clamps both lc and processed_bytes to the request. */
	assert(apdu.processed_bytes <= KLEE_APDU_LEN);

#ifdef KLEE_REPLAY
	for (size_t i = 0; i < (size_t)KLEE_APDU_LEN; i++)
		printf("%02x", buf[i]);
	printf("\n");
#endif

	free(buf);
	return 0;
}
