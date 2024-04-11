/*
 * Copyright (c) 2024 Onomondo ApS. All rights reserved.
 *
 * SPDX-License-Identifier: GPL-3.0-only
 */

#pragma once

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

#define AES_BLOCKSIZE 16

/* See also ETSI TS 102 225, section 5.1.1 and 5.1.2 */
enum enc_algorithm {
	NONE,
	TRIPLE_DES_CBC2,
	AES_CBC,
	AES_CMAC,
};

/*! Perform an in-place AES decryption with the common settings of OTA
 *  (CBC mode, zero IV).
 *  \param[inout] buffer user provided memory with plaintext to decrypt.
 *  \param[in] buffer_len length of the plaintext data to decrypt (multiple of 16).
 *  \param[in] key AES key.
 *  \param[in] key_len length of the AES key. */
void ss_utils_aes_decrypt(uint8_t *buffer, size_t buffer_len, const uint8_t *key, size_t key_len);

/*! Perform an in-place AES encryption with the common settings of OTA
 *  (CBC mode, zero IV).
 *  \param[inout] buffer user provided memory with plaintext to encrypt.
 *  \param[in] buffer_len length of the plaintext data to encrypt (multiple of 16).
 *  \param[in] key 16 byte AES key.
 *  \param[in] key_len length of the AES key. */
void ss_utils_aes_encrypt(uint8_t *buffer, size_t buffer_len, const uint8_t *key, size_t key_len);

/*! Perform an in-place 3DES decryption with the common settings of OTA
 *  (CBC mode, 16-byte key, zero IV).
 *  \param[inout] buffer user provided memory with plaintext to decrypt.
 *  \param[in] buffer_len length of the plaintext data to decrypt (multiple of 8).
 *  \param[in] key 16 byte DES key. */
void ss_utils_3des_decrypt(uint8_t *buffer, size_t buffer_len, const uint8_t *key);

/*! Perform an in-place 3DES encryption with the common settings of OTA
 *  (CBC mode, 16-byte key, zero IV).
 *  \param[inout] buffer user provided memory with plaintext to encrypt.
 *  \param[in] buffer_len length of the plaintext data to encrypt (multiple of 8).
 *  \param[in] key 16 byte DES key. */
void ss_utils_3des_encrypt(uint8_t *buffer, size_t buffer_len, const uint8_t *key);

/*! Calculate cryptographic checksum (CC) using a specified algorithm.
 *  \param[out] cc user provided memory for resulting cryptographic checksum.
 *  \param[out] cc_len length of user provided memory for resulting cryptographic checksum.
 *  \param[in] key cryptographic key.
 *  \param[in] key_len cryptographic key length.
 *  \param[in] data1 user buffer containing part 1 of the data.
 *  \param[in] data1_len length of data part 1 (must be multiple of blocksize)
 *  \param[in] data2 user buffer containing part 2 of the data.
 *  \param[in] data2_len length of data part 2 (unpadded).
 *  \returns 0 on success, -EINVAL on error. */
int ss_utils_ota_calc_cc(uint8_t *cc, size_t cc_len, uint8_t *key, size_t key_len, enum enc_algorithm alg,
			 uint8_t *data1, size_t data1_len, uint8_t *data2, size_t data2_len);
