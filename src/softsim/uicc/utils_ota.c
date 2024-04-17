/*
 * Copyright (c) 2024 Onomondo ApS. All rights reserved.
 *
 * SPDX-License-Identifier: GPL-3.0-only
 */

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <errno.h>
#include <onomondo/softsim/crypto.h>
#include <onomondo/softsim/log.h>
#include <onomondo/utils/ss_crypto_extension.h>
#include "utils_ota.h"
#include "utils.h"
#include "utils_3des.h"
#include "utils_aes.h"

/*! Calculate the number of padding bytes (pcnt) for a given length.
 *  \param[in] algorithm algorithm to use.
 *  \param[in] data_len length of the data.
 *  \returns number of padding bytes. */
uint8_t ss_utils_ota_calc_pcnt(enum enc_algorithm algorithm, size_t data_len)
{
	uint8_t blocksize = 0;

	switch (algorithm) {
	case TRIPLE_DES_CBC2:
		blocksize = DES_BLOCKSIZE;
		break;
	case AES_CBC:
		blocksize = AES_BLOCKSIZE;
		break;
	default:
		blocksize = 1; /* No padding */
	}

	return (-(blocksize + data_len)) % blocksize;
}

#ifndef CONFIG_EXTERNAL_CRYPTO_IMPL

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
			 uint8_t *data1, size_t data1_len, uint8_t *data2, size_t data2_len)
{
	struct utils_3des_cc_ctx cc_des;
	struct utils_aes_cc_ctx cc_aes;

	/* This allows users to fetch keys from more custom locations.
	 * Very useful for devices where the filesystem isn't trusted.
	 * I.e. The key is preferably loaded from a secure zone or from encrypted
	 * representation etc.*/
#ifdef CONFIG_EXTERNAL_KEY_LOAD
	uint8_t modified_key[AES_BLOCKSIZE];
	size_t modified_key_len = AES_BLOCKSIZE;
	ss_load_key_external(key, key_len, modified_key, &modified_key_len);
	key = modified_key;
	key_len = modified_key_len;
#endif // CONFIG_EXTERNAL_KEY_LOAD

	/* NOTE: This function accepts two separate buffers (data1 and data2).
	 * The reason for this is that the data we are going to sign is in two
	 * separate buffers and to avoid copying the two buffers into a single
	 * buffer we apply the checksum calculation on the two buffers
	 * separately. This works as long as the first buffer does not require
	 * to be padded (AES-CMAC and 3DES-CBC2 are block ciphers). The caller
	 * must ensure that the length of the buffer (data1) is a multiple of 8
	 * for 3DES-CBC2 and a multiple of 16 for AES-CMAC. Usually we have
	 * multiple of 16 in both situations. The length of the second buffer
	 * (data2) may be of arbitrary length. Both implementation (3DES-CBC2
	 * and AES-CMAC) will apply an appropriate padding internally. */

	switch (alg) {
	case TRIPLE_DES_CBC2:
		assert(data1_len % DES_BLOCKSIZE == 0);
		assert(key_len == TRIPLE_DES_KEYLEN);
		assert(cc_len <= sizeof(cc_des.cbc));
		ss_utils_3des_cc_setup(&cc_des, key);
		ss_utils_3des_cc_feed(&cc_des, data1, data1_len);
		ss_utils_3des_cc_feed(&cc_des, data2, data2_len);
		ss_utils_3des_cc_cleanup(&cc_des);
		memcpy(cc, cc_des.cbc, cc_len);
		return 0;
	case AES_CMAC:
		assert(data1_len % AES_BLOCKSIZE == 0);
		assert(cc_len <= sizeof(cc_aes.cbc));
		ss_utils_aes_cc_setup(&cc_aes, key, key_len, false);
		ss_utils_aes_cc_feed(&cc_aes, data1, data1_len, false);
		ss_utils_aes_cc_feed(&cc_aes, data2, data2_len, true);
		ss_utils_aes_cc_cleanup(&cc_aes);
		memcpy(cc, cc_aes.cbc, cc_len);
		return 0;
	default:
		SS_LOGP(SREMOTECMD, LERROR, "unable to calculate cc, improper crypto algorithm selected\n");
		return -EINVAL;
	}

#ifdef CONFIG_EXTERNAL_KEY_LOAD
	ss_memzero(modified_key, sizeof(modified_key));
#endif // CONFIG_EXTERNAL_KEY_LOAD
}

#endif // CONFIG_EXTERNAL_CRYPTO_IMPL
