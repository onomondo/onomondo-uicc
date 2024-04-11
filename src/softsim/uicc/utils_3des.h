/*
 * Copyright (c) 2024 Onomondo ApS. All rights reserved.
 *
 * SPDX-License-Identifier: GPL-3.0-only
 */

#pragma once

#include <stddef.h>
#include <stdint.h>

#define DES_BLOCKSIZE 8
#define TRIPLE_DES_KEYLEN 16

struct des3_key_s;
struct utils_3des_cc_ctx {
	struct des3_key_s *key;
	/* This contains the last block's ciphertext, which also represents the
	 * checksum (and the overall state of the algorithm). */
	uint8_t cbc[DES_BLOCKSIZE];
};

void ss_utils_3des_cc_setup(struct utils_3des_cc_ctx *cc, const uint8_t *key);
void ss_utils_3des_cc_feed(struct utils_3des_cc_ctx *cc, const uint8_t *data, size_t data_len);
void ss_utils_3des_cc_cleanup(struct utils_3des_cc_ctx *cc);
