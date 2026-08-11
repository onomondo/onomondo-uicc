/*
 * Copyright (c) 2026 Onomondo ApS. All rights reserved.
 *
 * SPDX-License-Identifier: GPL-3.0-only
 *
 * KLEE harness for the APDU wire-format parser.
 *
 * ss_apdu_parse_exhaustive() is the modem trust boundary: it turns raw bytes
 * from outside the card into apdu->hdr/lc/le/cmd. Fuzzing throws random bytes
 * at it; KLEE solves the branch conditions and reports the exact byte sequence
 * that drives each path -- or proves a path unreachable, which no fuzzer can.
 *
 * One length per build (-DKLEE_APDU_LEN). The buffer is allocated at exactly
 * that length, so a read one byte past the request is a real out-of-bounds
 * access KLEE reports, not a silent read into an oversized array -- the blind
 * spot the string-literal and stack-array vectors in tests/apdu share. The
 * whole buffer is made symbolic in one call: klee_make_symbolic() requires the
 * whole memory object, and nothing branches on the data field (only its
 * address is copied), so extra symbolic bytes add no paths.
 *
 * The two post-conditions catch what KLEE's memory model cannot. apdu->cmd and
 * apdu->rsp are adjacent fields of one struct, so an over-long Lc that writes
 * past cmd[256] lands in rsp[] -- in bounds for KLEE and ASan alike -- and is
 * visible only as a violated bound on apdu->lc. processed_bytes is the same
 * kind of invariant: the out: guard clamps lc but never processed_bytes.
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
