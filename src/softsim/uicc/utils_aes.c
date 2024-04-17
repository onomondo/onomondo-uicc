/*
 * Copyright (c) 2024 Onomondo ApS. All rights reserved.
 *
 * SPDX-License-Identifier: GPL-3.0-only
 */

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <onomondo/utils/ss_crypto_extension.h>
#include <onomondo/softsim/crypto.h>
#include "utils.h"
#include "utils_aes.h"
#include "crypto/common.h"
#include "crypto/aes.h"

/* This allows users to fetch keys from more custom locations.
 * Very useful for devices where the filesystem isn't trusted.
 * I.e. The key is preferably loaded from a secure zone or from encrypted
 * representation etc. */

#define COPY_EXTERNAL_KEY_TO_LOCAL_VAR()                                     \
	uint8_t modified_key[AES_BLOCKSIZE];                                 \
	size_t modified_key_len = AES_BLOCKSIZE;                             \
	ss_load_key_external(key, key_len, modified_key, &modified_key_len); \
	key = modified_key;                                                  \
	key_len = modified_key_len;

#define MEMZERO_EXTERNAL_KEY() ss_memzero(modified_key, sizeof(modified_key));

#ifndef CONFIG_EXTERNAL_CRYPTO_IMPL

/*! Perform an in-place AES decryption with the common settings of OTA
 *  (CBC mode, zero IV).
 *  \param[inout] buffer user provided memory with plaintext to decrypt.
 *  \param[in] buffer_len length of the plaintext data to decrypt (multiple of 16).
 *  \param[in] key AES key.
 *  \param[in] key_len length of the AES key. */
void ss_utils_aes_decrypt(uint8_t *buffer, size_t buffer_len, const uint8_t *key, size_t key_len)
{
	void *aes_ctx;
	uint8_t cbc[AES_BLOCKSIZE] = { 0 }; /* IV, all zero */
	uint8_t next_cbc[AES_BLOCKSIZE];
	int i;
	int j;

#ifdef CONFIG_EXTERNAL_KEY_LOAD
	COPY_EXTERNAL_KEY_TO_LOCAL_VAR()
#endif // CONFIG_EXTERNAL_KEY_LOAD

	aes_ctx = aes_decrypt_init(key, key_len);

	/* Adjusted from hostap's crypto_internal-cipher.c */
	for (i = 0; i < buffer_len / AES_BLOCKSIZE; i++) {
		/* Some optimization would be possibly by double-buffering CBC, but that'd reduce readability. */
		memcpy(next_cbc, buffer, AES_BLOCKSIZE);
		aes_decrypt(aes_ctx, buffer, buffer);
		for (j = 0; j < AES_BLOCKSIZE; j++)
			buffer[j] ^= cbc[j];
		memcpy(cbc, next_cbc, AES_BLOCKSIZE);
		buffer += AES_BLOCKSIZE;
	}

	aes_decrypt_deinit(aes_ctx);

#ifdef CONFIG_EXTERNAL_KEY_LOAD
	MEMZERO_EXTERNAL_KEY()
#endif // CONFIG_EXTERNAL_KEY_LOAD
}

/*! Perform an in-place AES encryption with the common settings of OTA
 *  (CBC mode, zero IV).
 *  \param[inout] buffer user provided memory with plaintext to encrypt.
 *  \param[in] buffer_len length of the plaintext data to encrypt (multiple of 16).
 *  \param[in] key 16 byte AES key.
 *  \param[in] key_len length of the AES key. */
void ss_utils_aes_encrypt(uint8_t *buffer, size_t buffer_len, const uint8_t *key, size_t key_len)
{
	void *aes_ctx;
	uint8_t cbc[AES_BLOCKSIZE] = { 0 }; /* IV, all zero */
	int i;
	int j;

#ifdef CONFIG_EXTERNAL_KEY_LOAD
	COPY_EXTERNAL_KEY_TO_LOCAL_VAR()
#endif // CONFIG_EXTERNAL_KEY_LOAD

	aes_ctx = aes_encrypt_init(key, key_len);

	/* Adjusted from hostap's crypto_internal-cipher.c */
	for (i = 0; i < buffer_len / AES_BLOCKSIZE; i++) {
		for (j = 0; j < AES_BLOCKSIZE; j++)
			cbc[j] ^= buffer[j];
		aes_encrypt(aes_ctx, cbc, cbc);
		memcpy(buffer, cbc, AES_BLOCKSIZE);
		buffer += AES_BLOCKSIZE;
	}

	aes_encrypt_deinit(aes_ctx);

#ifdef CONFIG_EXTERNAL_KEY_LOAD
	MEMZERO_EXTERNAL_KEY()
#endif // CONFIG_EXTERNAL_KEY_LOAD
}
#endif // CONFIG_EXTERNAL_CRYPTO_IMPL

/* Shift a whole block to the left by one bit position.
 * (See also RFC 4493, appendix A) */
static void leftshift_onebit(uint8_t *input, uint8_t *output)
{
	unsigned int i;
	uint8_t carry = 0;

	for (i = AES_BLOCKSIZE; i > 0; i--) {
		output[i - 1] = input[i - 1] << 1;
		output[i - 1] |= carry;
		carry = (input[i - 1] & 0x80) ? 1 : 0;
	}
	return;
}

/* XOR two blocks bitwise (See also RFC 4493, appendix A) */
static void xor_128(uint8_t *a, uint8_t *b, uint8_t *out)
{
	unsigned int i;
	for (i = 0; i < AES_BLOCKSIZE; i++)
		out[i] = a[i] ^ b[i];
}

/*! Setup a context for cryptographic checksum calculation.
 *  \param[out] cc user provided memory with checksum context.
 *  \param[in] key AES key.
 *  \param[in] key_len length of the  AES key.
 *  \param[in] inert_padding apply padding without chaning crypto process. */
void ss_utils_aes_cc_setup(struct utils_aes_cc_ctx *cc, const uint8_t *key, size_t key_len, bool inert_padding)
{
	/*! Note: The AES-CMAC algorithm specifies a separate path in case the
	 *  input data has to be padded. The option "inert_padding" will handle
	 *  the data as if its length would be a multiple of 16 byte. A zero
	 *  padding will be applied automatically but it will have no effect on
	 *  the cryptographic process itsself. */

	const uint8_t const_zero[AES_BLOCKSIZE] = { 0 };
	uint8_t L[AES_BLOCKSIZE] = { 0 };
	uint8_t tmp[AES_BLOCKSIZE];

	uint8_t const_Rb[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			       0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x87 };

	memset(cc, 0, sizeof(*cc));
	cc->aes_ctx = aes_encrypt_init(key, key_len);
	cc->inert_padding = inert_padding;

	/* Generate subkeys K1 and K2 (See also RFC 4493, appendix A) */
	aes_encrypt(cc->aes_ctx, const_zero, L);
	if ((L[0] & 0x80) == 0) {
		leftshift_onebit(L, cc->K1);
	} else {
		leftshift_onebit(L, tmp);
		xor_128(tmp, const_Rb, cc->K1);
	}
	if ((cc->K1[0] & 0x80) == 0) {
		leftshift_onebit(cc->K1, cc->K2);
	} else {
		leftshift_onebit(cc->K1, tmp);
		xor_128(tmp, const_Rb, cc->K2);
	}
}

/*! Feed data slice into cryptographic checksum calculation.
 *  \param[inout] cc user provided memory with checksum context.
 *  \param[in] data_len length of data slice (must be multiple of 16).
 *  \param[in] data user provided memory with data slice.
 *  \param[in] last set to true when feeding the last block. */
void ss_utils_aes_cc_feed(struct utils_aes_cc_ctx *cc, const uint8_t *data, size_t data_len, bool last)
{
	/*! Calculation of the cryptographic checksum (CC) using AES.
	 *  (See also see also RFC 4493, section 2.2 and utils_3des.c */

	int j;
	uint8_t padd;
	bool padded = false;

	if (cc->inert_padding)
		/* When we do an "inert padding" we will pad with zeros only. */
		padd = 0x00;
	else
		/* Set the first padding bit to 1 and padd the remaining data
		 * with zeros, see also NIST Special Publication 800-38A,
		 * appendix A and RFC 4493, section 2.4. */
		padd = 0x80;

	do {
		/* XOR the input data with the encrypted data of the last turn,
		 * apply padding if necessary. */
		for (j = 0; j < AES_BLOCKSIZE; j++) {
			if (j < data_len)
				cc->cbc[j] ^= data[j];
			else {
				cc->cbc[j] ^= padd;
				padd = 0x00;
				padded = true;
			}
		}

		/* The last block needs special treatment using a subkey
		 * K1 or K2, depending on if padding was applied or not. */
		if (last && data_len <= AES_BLOCKSIZE) {
			/* In case of "inert padding" we will apply K1 as if
			 * we didn't pad anything. */
			if (padded && cc->inert_padding == false)
				xor_128(cc->cbc, cc->K2, cc->cbc);
			else
				xor_128(cc->cbc, cc->K1, cc->cbc);
		}

		aes_encrypt(cc->aes_ctx, cc->cbc, cc->cbc);

		if (data_len <= AES_BLOCKSIZE)
			return;

		data += AES_BLOCKSIZE;
		data_len -= AES_BLOCKSIZE;
	} while (data_len != 0);
}

/*! Cleanup cryptographic checksum calculation context.
 *  \param[in] cc user provided memory with checksum context. */
void ss_utils_aes_cc_cleanup(struct utils_aes_cc_ctx *cc)
{
	aes_encrypt_deinit(cc->aes_ctx);
	ss_memzero(&cc->K1, sizeof(cc->K1));
	ss_memzero(&cc->K2, sizeof(cc->K2));
}
