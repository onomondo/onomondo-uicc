/*
 * Copyright (c) 2024 Onomondo ApS. All rights reserved.
 *
 * SPDX-License-Identifier: GPL-3.0-only
 */

#include <stdint.h>
#include "utils.h"
#include "utils_3des.h"
#include "crypto/des_i.h"
#include <onomondo/softsim/crypto.h>

#ifndef CONFIG_EXTERNAL_CRYPTO_IMPL
void setup_key(const uint8_t *src, struct des3_key_s *dest)
{
	/* The library wants keys in 24byte form, but we have the 16byte form */
	/* If the compiler is smart, that doesn't really happen (but things re
	 * inlined down to the deskey() calls instead) */
	uint8_t key_copied[24];
	memcpy(&key_copied[0], src, TRIPLE_DES_KEYLEN);
	memcpy(&key_copied[16], src, DES_BLOCKSIZE);
	des3_key_setup(key_copied, dest);

	ss_memzero(key_copied, sizeof(key_copied));
}

/*! Perform an in-place 3DES decryption with the common settings of OTA
 *  (CBC mode, 16-byte key, zero IV).
 *  \param[inout] buffer user provided memory with plaintext to decrypt.
 *  \param[in] buffer_len length of the plaintext data to decrypt (multiple of 8).
 *  \param[in] key 16 byte DES key. */
void ss_utils_3des_decrypt(uint8_t *buffer, size_t buffer_len, const uint8_t *key)
{
	int i = 0, j = 0;
	struct des3_key_s configured_key;
	setup_key(key, &configured_key);
	uint8_t cbc[DES_BLOCKSIZE] = { 0 }; /* IV, all zero */

	/* Adjusted from hostap's crypto_internal-cipher.c */
	for (i = 0; i < buffer_len / DES_BLOCKSIZE; i++) {
		/* Some optimization would be possibly by double-buffering CBC,
		 * but that'd reduce readability. */
		uint8_t next_cbc[DES_BLOCKSIZE];
		memcpy(next_cbc, buffer, DES_BLOCKSIZE);
		des3_decrypt(buffer, &configured_key, buffer);
		for (j = 0; j < DES_BLOCKSIZE; j++)
			buffer[j] ^= cbc[j];
		memcpy(cbc, next_cbc, DES_BLOCKSIZE);
		buffer += DES_BLOCKSIZE;
	}

	ss_memzero(&configured_key, sizeof(configured_key));
}

/*! Perform an in-place 3DES encryption with the common settings of OTA
 *  (CBC mode, 16-byte key, zero IV).
 *  \param[inout] buffer user provided memory with plaintext to encrypt.
 *  \param[in] buffer_len length of the plaintext data to encrypt (multiple of 8).
 *  \param[in] key 16 byte DES key. */
void ss_utils_3des_encrypt(uint8_t *buffer, size_t buffer_len, const uint8_t *key)
{
	int i = 0, j = 0;
	struct des3_key_s configured_key;
	setup_key(key, &configured_key);

	uint8_t cbc[DES_BLOCKSIZE] = { 0 }; /* The IV */

	/* Adjusted from hostap's crypto_internal-cipher.c */
	for (i = 0; i < buffer_len / DES_BLOCKSIZE; i++) {
		for (j = 0; j < DES_BLOCKSIZE; j++)
			cbc[j] ^= buffer[j];
		des3_encrypt(cbc, &configured_key, cbc);
		memcpy(buffer, cbc, DES_BLOCKSIZE);
		buffer += DES_BLOCKSIZE;
	}

	ss_memzero(&configured_key, sizeof(configured_key));
}

/*! Setup a context for cryptographic checksum calculation.
 *  \param[out] cc user provided memory with checksum context.
 *  \param[in] key 16 byte DES key. */
void ss_utils_3des_cc_setup(struct utils_3des_cc_ctx *cc, const uint8_t *key)
{
	memset(cc, 0, sizeof(*cc));
	cc->key = SS_ALLOC(struct des3_key_s);
	setup_key(key, cc->key);
	memset(cc->cbc, 0, SS_ARRAY_SIZE(cc->cbc));
}

/*! Feed data slice into cryptographic checksum calculation.
 *  \param[inout] cc user provided memory with checksum context.
 *  \param[in] data_len length of data slice (must be multiple of 8).
 *  \param[in] data user provided memory with data slice. */
void ss_utils_3des_cc_feed(struct utils_3des_cc_ctx *cc, const uint8_t *data, size_t data_len)
{
	/*! Calculation of the cryptographic checksum (CC) using 3DES.
	 *
	 * The cryptographic checksum calculated here is the last 8 bytes of
	 * the encryption output (ciphertext) of the data fed in; unlike the
	 * utils_3des_encrypt function this works on immutable input and allows
	 * input to be fed in in slices (to avoid an extra copying step in case
	 * the data is not in contiguous memory).
	 *
	 * The data slices fed must have a length that is a multiple of 8. The
	 * last slice fed may be of arbitrary length, and is automatically
	 * padded with zeros. (The input length are not checked, feeding data
	 * unaligned will produce an incorrect hash).
	 *
	 * The calculation result is avalable to the caller in cc->cbc.
	 *
	 * Note: Earlier versions of this implementation kept an internal buffer
	 * to allow byte-wise feeding; look at the history if this does turn
	 * out to be needed again. However, It turned out that data to be
	 * checksummed is always available in suitable chunks. */

	int j;

	while (data_len != 0) {
		/* Single chunk of the "encrypt" step, see utils_3des_encrypt */
		for (j = 0; j < DES_BLOCKSIZE; j++)
			cc->cbc[j] ^= j < data_len ? data[j] : 0;
		des3_encrypt(cc->cbc, cc->key, cc->cbc);

		if (data_len <= DES_BLOCKSIZE)
			return;

		data += DES_BLOCKSIZE;
		data_len -= DES_BLOCKSIZE;
	}
}

/*! Cleanup cryptographic checksum calculation context.
 *  \param[in] cc user provided memory with checksum context. */
void ss_utils_3des_cc_cleanup(struct utils_3des_cc_ctx *cc)
{
	/*! This function removes the key from the context data in a secure.
	 *  way. The cryptographic checksum result will be retained. */
	ss_memzero(cc->key, sizeof(cc->key));
	SS_FREE(cc->key);
}
#endif // CONFIG_EXTERNAL_CRYPTO_IMPL
