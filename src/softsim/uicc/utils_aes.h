/*
 * Copyright (c) 2024 Onomondo ApS. All rights reserved.
 *
 * SPDX-License-Identifier: GPL-3.0-only
 */

#pragma once

#define AES_BLOCKSIZE 16

struct utils_aes_cc_ctx {
	void *aes_ctx;

	uint8_t K1[AES_BLOCKSIZE];
	uint8_t K2[AES_BLOCKSIZE];

	/* This contains the last block's ciphertext, where the last 8 byte will
	 * represent the actual checksum. (The last block also represents the
	 * overall state of the algorithm). */
	uint8_t cbc[AES_BLOCKSIZE];

	/* When set to true, the input data will be padded as if the length
	 * would already be a multiple of 16 bytes. Eventually the padding will
	 * not alter the cryptograhic process like it normally would. */
	bool inert_padding;
};

void ss_utils_aes_cc_setup(struct utils_aes_cc_ctx *cc, const uint8_t *key, size_t key_len, bool inert_padding);
void ss_utils_aes_cc_feed(struct utils_aes_cc_ctx *cc, const uint8_t *data, size_t data_len, bool last);
void ss_utils_aes_cc_cleanup(struct utils_aes_cc_ctx *cc);
