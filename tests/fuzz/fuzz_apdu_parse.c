/*
 * Copyright (c) 2026 Onomondo ApS. All rights reserved.
 *
 * SPDX-License-Identifier: GPL-3.0-only
 *
 * libFuzzer harness for the APDU wire-format parser itself.
 *
 * The entry-point harnesses (fuzz_apdu.c) can never exercise the parser past
 * 260 bytes: ss_transact() and ss_application_apdu_transact() truncate longer
 * requests before parsing. The extended-Lc arithmetic above that limit --
 * where Lc = 257 clears the data-field bound but overruns cmd[] -- is only
 * reachable by calling ss_apdu_parse_exhaustive() directly.
 *
 * The two post-conditions catch what ASan cannot: apdu->cmd and apdu->rsp are
 * adjacent in one struct, so an over-long Lc writes past cmd[256] into rsp[]
 * without leaving the object; and processed_bytes running past the request is
 * a logic defect, not a memory error.
 */

#include "src/softsim/uicc/apdu.h"

#include <assert.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#ifdef NDEBUG
#error "the post-conditions are asserts; an NDEBUG build silently tests nothing"
#endif

/* Nothing branches on bytes past header + extended Lc + 256-byte body +
 * extended Le trailer; longer inputs only cost the fuzzer time. */
#define MAX_PARSE 300

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	struct ss_apdu apdu = { 0 };
	uint8_t *req;

	if (size > MAX_PARSE) {
		return 0;
	}

	/* Exact-size heap copy: a one-byte over-read becomes an ASan report
	 * instead of a silent read. */
	req = malloc(size ? size : 1); /* malloc(0) may be NULL, which would skip the empty seed */
	if (!req) {
		return 0;
	}
	memcpy(req, data, size);

	ss_apdu_parse_exhaustive(&apdu, req, size);

	/* cmd[256] and rsp[256] are one allocation: an over-long Lc overflows cmd
	 * into rsp without leaving the object, so the copy alone never faults. */
	assert(apdu.lc <= sizeof(apdu.cmd));
	/* the out: guard clamps both lc and processed_bytes to the request. */
	assert(apdu.processed_bytes <= size);

	free(req);

	return 0;
}
