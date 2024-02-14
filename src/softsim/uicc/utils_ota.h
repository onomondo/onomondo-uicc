/*
 * Copyright (c) 2024 Onomondo ApS. All rights reserved.
 * 
 * SPDX-License-Identifier: GPL-3.0-only 
 */

#pragma once

/* See also ETSI TS 102 225, section 5.1.1 and 5.1.2 */
enum enc_algorithm {
	NONE,
	TRIPLE_DES_CBC2,
	AES_CBC,
	AES_CMAC,
};

#define OTA_KEY_LEN 16
#define OTA_INTEGRITY_LEN 8

uint8_t ss_utils_ota_calc_pcnt(enum enc_algorithm algorithm, size_t data_len);
int ss_utils_ota_calc_cc(uint8_t *cc, size_t cc_len,
			 uint8_t *key, size_t key_len, enum enc_algorithm alg,
			 uint8_t *data1, size_t data1_len,
			 uint8_t *data2, size_t data2_len);
