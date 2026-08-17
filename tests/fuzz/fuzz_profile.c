/*
 * Copyright (c) 2026 Onomondo ApS. All rights reserved.
 *
 * SPDX-License-Identifier: GPL-3.0-only
 *
 * libFuzzer harness for the provisioning profile blob parser.
 *
 * ss_profile_from_string() is a trust boundary: the blob arrives from a
 * factory tool, an AT command or a FOTA payload, and a corrupted one must be
 * rejected rather than mis-parsed.
 */

#include <onomondo/utils/ss_profile.h>

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	struct ss_profile profile = { 0 };
	char *input;

	/* The length parameter is uint16_t; anything longer cannot be expressed. */
	if (size > UINT16_MAX) {
		return 0;
	}

	/* Exact-length heap copy: a read past the declared length becomes an
	 * ASan report instead of a silent read of adjacent memory. */
	input = malloc(size ? size : 1); /* malloc(0) may be NULL, which would skip the empty seed */
	if (!input) {
		return 0;
	}
	memcpy(input, data, size);

	ss_profile_from_string((uint16_t)size, input, &profile);

	free(input);

	return 0;
}
