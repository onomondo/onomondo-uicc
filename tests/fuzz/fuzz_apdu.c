/*
 * Copyright (c) 2026 Onomondo ApS. All rights reserved.
 *
 * SPDX-License-Identifier: GPL-3.0-only
 *
 * libFuzzer harness for the byte-in/byte-out APDU entry points.
 *
 * ss_transact() and ss_application_apdu_transact() take the same arguments but
 * parse differently -- the former copies a fixed-size header, the latter runs
 * ss_apdu_parse_exhaustive() -- so this file is compiled once per entry point
 * with -DFUZZ_ENTRY=<symbol> rather than duplicated.
 *
 * This is the modem-facing trust boundary: every byte reaching it comes from
 * outside the card.
 */

#include <onomondo/softsim/softsim.h>
#include <onomondo/softsim/storage.h>

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef FUZZ_ENTRY
#error "define FUZZ_ENTRY to ss_transact or ss_application_apdu_transact"
#endif

#ifndef SS_FUZZ_FILES_SRC
#error "define SS_FUZZ_FILES_SRC to the EF tree to stage"
#endif

/* T=0 tops out at a 5-byte header plus a 256-byte body. Both entry points
 * truncate anything longer, so larger inputs only cost the fuzzer time. */
#define MAX_APDU 261

/* Both entry points assert response_buf_len >= sizeof(apdu->rsp) + sizeof(apdu->sw), i.e. 258. */
#define RESP_LEN 512

static char storage_dir[] = "/tmp/ss_fuzz_XXXXXX";

/* Stage a private copy of the EF tree so the fuzzer never writes into the
 * repository (the in-tree ctest suites do, which is a known annoyance) and so
 * concurrent jobs cannot corrupt each other. */
int LLVMFuzzerInitialize(int *argc, char ***argv)
{
	char cmd[2 * SS_STORAGE_PATH_MAX + sizeof(SS_FUZZ_FILES_SRC) + 32];

	(void)argc;
	(void)argv;

	if (!mkdtemp(storage_dir)) {
		perror("mkdtemp");
		abort();
	}

	/* The tree is staged exactly once per process, so cp -R carries it. */
	snprintf(cmd, sizeof(cmd), "cp -R '%s/.' '%s/'", SS_FUZZ_FILES_SRC, storage_dir);
	if (system(cmd) != 0) {
		fprintf(stderr, "fuzz: failed to stage EF tree from %s\n", SS_FUZZ_FILES_SRC);
		abort();
	}

	if (ss_storage_set_path(storage_dir) != 0) {
		fprintf(stderr, "fuzz: ss_storage_set_path(%s) failed\n", storage_dir);
		abort();
	}

	return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	struct ss_context *ctx;
	uint8_t resp[RESP_LEN];
	uint8_t *req;
	size_t req_len;

	if (size > MAX_APDU) {
		return 0;
	}

	/* The entry points take a mutable buffer, so hand them a copy rather than
	 * libFuzzer's. Heap, and exactly `size` bytes: a parser that reads one
	 * byte past the request is then an ASan report rather than a silent read
	 * of adjacent stack. That distinction is exactly what the existing tests
	 * miss -- they pass string literals and oversized arrays. */
	req = malloc(size);
	if (!req) {
		return 0;
	}
	memcpy(req, data, size);
	req_len = size;

	/* A fresh context per input keeps executions independent. The staged EF
	 * tree is shared across them, so a crash that depends on an earlier input
	 * having written to it does not replay standalone -- see "Known limits"
	 * in README.md. */
	ctx = ss_new_ctx();
	if (ctx) {
		ss_reset(ctx);
		FUZZ_ENTRY(ctx, resp, sizeof(resp), req, &req_len);
		ss_free_ctx(ctx);
	}

	free(req);

	return 0;
}
