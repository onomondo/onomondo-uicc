/*
 * AES encrypt_block
 *
 * Copyright (c) 2003-2007, Jouni Malinen <j@w1.fi>
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#include <onomondo/softsim/crypto.h>
#include "includes.h"
#include "common.h"
#include "aes.h"
#include "aes_wrap.h"

/**
 * aes_128_encrypt_block - Perform one AES 128-bit block operation
 * @key: Key for AES
 * @in: Input data (16 bytes)
 * @out: Output of the AES block operation (16 bytes)
 * Returns: 0
 */

/* adjusted from Jouni Malinen impl */
int aes_128_encrypt_block(const u8 *key, const u8 *in, u8 *out)
{
	// ss_utils_aes_encrypt will overwrite input buffer
	uint8_t buf[AES_BLOCK_SIZE];
	memcpy(buf, in, AES_BLOCK_SIZE);

	ss_utils_aes_encrypt(buf, AES_BLOCK_SIZE, key, AES_BLOCK_SIZE);
	memcpy(out, buf, AES_BLOCK_SIZE);

	return 0;
}
