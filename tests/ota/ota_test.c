/*
 * Copyright (c) 2024 Onomondo ApS. All rights reserved.
 *
 * SPDX-License-Identifier: GPL-3.0-only
 *
 * Author: Philipp Maier
 */

#include <stdio.h>
#include <stdbool.h>
#include <onomondo/softsim/utils.h>
#include "src/softsim/uicc/utils_3des.h"
#include "src/softsim/uicc/utils_ota.h"

static void calc_and_print_pcnt(enum enc_algorithm algorithm, size_t data_len, uint8_t pcnt_expected)
{
	char *algorithm_str;
	uint8_t pcnt;

	switch (algorithm) {
	case TRIPLE_DES_CBC2:
		algorithm_str = "DES_CBC2";
		break;
	case AES_CBC:
		algorithm_str = "AES";
		break;
	case NONE:
		algorithm_str = "NONE";
		break;
	default:
		algorithm_str = "(INVALID)";
	}

	pcnt = ss_utils_ota_calc_pcnt(algorithm, data_len);

	printf("algorithm=%s data_len=%zu, pcnt=%u, pcnt_expected=%u\n",
	       algorithm_str, data_len, ss_utils_ota_calc_pcnt(algorithm, data_len), pcnt_expected);

	assert(pcnt == pcnt_expected);

}

static void ss_utils_ota_calc_pcnt_test(void)
{
	/* DES Aligned on blocksize */
	calc_and_print_pcnt(TRIPLE_DES_CBC2, 0, 0);
	calc_and_print_pcnt(TRIPLE_DES_CBC2, 8, 0);
	calc_and_print_pcnt(TRIPLE_DES_CBC2, 16, 0);
	calc_and_print_pcnt(TRIPLE_DES_CBC2, 24, 0);

	/* DES Off by +1 */
	calc_and_print_pcnt(TRIPLE_DES_CBC2, 1, 7);
	calc_and_print_pcnt(TRIPLE_DES_CBC2, 9, 7);
	calc_and_print_pcnt(TRIPLE_DES_CBC2, 17, 7);
	calc_and_print_pcnt(TRIPLE_DES_CBC2, 25, 7);

	/* DES Off by -1 */
	calc_and_print_pcnt(TRIPLE_DES_CBC2, 7, 1);
	calc_and_print_pcnt(TRIPLE_DES_CBC2, 15, 1);
	calc_and_print_pcnt(TRIPLE_DES_CBC2, 23, 1);

	/* AES Aligned on blocksize */
	calc_and_print_pcnt(AES_CBC, 0, 0);
	calc_and_print_pcnt(AES_CBC, 16, 0);
	calc_and_print_pcnt(AES_CBC, 32, 0);
	calc_and_print_pcnt(AES_CBC, 48, 0);

	/* AES Off by +1 */
	calc_and_print_pcnt(AES_CBC, 1, 15);
	calc_and_print_pcnt(AES_CBC, 17, 15);
	calc_and_print_pcnt(AES_CBC, 33, 15);
	calc_and_print_pcnt(AES_CBC, 49, 15);

	/* AES Off by -1 */
	calc_and_print_pcnt(AES_CBC, 15, 1);
	calc_and_print_pcnt(AES_CBC, 31, 1);
	calc_and_print_pcnt(AES_CBC, 47, 1);

	/* No algorithm should always produce zero padding */
	calc_and_print_pcnt(NONE, 0, 0);
	calc_and_print_pcnt(NONE, 1, 0);
	calc_and_print_pcnt(NONE, 123, 0);
	calc_and_print_pcnt(NONE, 456, 0);
}

static void ss_utils_ota_calc_cc_test(void)
{
	int rc;
	uint8_t cc[OTA_INTEGRITY_LEN];

	uint8_t key[OTA_KEY_LEN] =
	    { 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x11, 0x22 };

	uint8_t data1[16] = {
		0x00, 0x28, 0x15, 0x1e, 0x19, 0x32, 0x32, 0xb0,
		0x00, 0x11, 0x00, 0x00, 0x00, 0x00, 0x01, 0x06,
	};

	uint8_t data2_A[16] = {
		0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
		0x01, 0x23, 0x45, 0x67, 0x01, 0x23, 0x45, 0x67,
	};

	uint8_t data2_B[17] = {
		0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
		0x01, 0x23, 0x45, 0x67, 0x01, 0x23, 0x45, 0x67,
		0xAA,
	};

	uint8_t data2_C[15] = {
		0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
		0x01, 0x23, 0x45, 0x67, 0x01, 0x23, 0x45,
	};

	rc = ss_utils_ota_calc_cc(cc, sizeof(cc), key, sizeof(key), TRIPLE_DES_CBC2,
				  data1, sizeof(data1), data2_A, sizeof(data2_A));
	printf("3DES-CMAC data1=%s, data2=%s, rc=%d, checksum=%s\n", ss_hexdump(data1, sizeof(data1)),
	       ss_hexdump(data2_A, sizeof(data2_A)), rc, ss_hexdump(cc, sizeof(cc)));

	rc = ss_utils_ota_calc_cc(cc, sizeof(cc), key, sizeof(key), TRIPLE_DES_CBC2,
				  data1, sizeof(data1), data2_B, sizeof(data2_B));
	printf("3DES-CMAC data1=%s, data2=%s, rc=%d, checksum=%s\n", ss_hexdump(data1, sizeof(data1)),
	       ss_hexdump(data2_B, sizeof(data2_B)), rc, ss_hexdump(cc, sizeof(cc)));

	rc = ss_utils_ota_calc_cc(cc, sizeof(cc), key, sizeof(key), TRIPLE_DES_CBC2,
				  data1, sizeof(data1), data2_C, sizeof(data2_C));
	printf("3DES-CMAC data1=%s, data2=%s, rc=%d, checksum=%s\n", ss_hexdump(data1, sizeof(data1)),
	       ss_hexdump(data2_C, sizeof(data2_C)), rc, ss_hexdump(cc, sizeof(cc)));

	rc = ss_utils_ota_calc_cc(cc, sizeof(cc), key, sizeof(key), AES_CMAC,
				  data1, sizeof(data1), data2_A, sizeof(data2_A));
	printf("AES-CMAC data1=%s, data2=%s, rc=%d, checksum=%s\n", ss_hexdump(data1, sizeof(data1)),
	       ss_hexdump(data2_A, sizeof(data2_A)), rc, ss_hexdump(cc, sizeof(cc)));

	rc = ss_utils_ota_calc_cc(cc, sizeof(cc), key, sizeof(key), AES_CMAC,
				  data1, sizeof(data1), data2_B, sizeof(data2_B));
	printf("AES-CMAC data1=%s, data2=%s, rc=%d, checksum=%s\n", ss_hexdump(data1, sizeof(data1)),
	       ss_hexdump(data2_B, sizeof(data2_B)), rc, ss_hexdump(cc, sizeof(cc)));

	rc = ss_utils_ota_calc_cc(cc, sizeof(cc), key, sizeof(key), AES_CMAC,
				  data1, sizeof(data1), data2_C, sizeof(data2_C));
	printf("AES-CMAC data1=%s, data2=%s, rc=%d, checksum=%s\n", ss_hexdump(data1, sizeof(data1)),
	       ss_hexdump(data2_C, sizeof(data2_C)), rc, ss_hexdump(cc, sizeof(cc)));
}

int main(int argc, char **argv)
{
	ss_utils_ota_calc_pcnt_test();
	ss_utils_ota_calc_cc_test();
	return 0;
}
