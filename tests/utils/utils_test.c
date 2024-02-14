/*
 * Copyright (c) 2024 Onomondo ApS. All rights reserved.
 *
 * SPDX-License-Identifier: GPL-3.0-only
 *
 * Author: Philipp Maier
 */

#include <stdio.h>
#include <onomondo/softsim/utils.h>

void ss_binary_from_hexstr_test(void)
{
	uint8_t output[512];
	uint8_t output_short[10];
	size_t rc;

	char testvec_1[] = "aabbccddeeff00112233445566778899";
	char testvec_2[] = "aabbccddeeff001122334455667788991";
	char testvec_3[] = "aabbccddeeff001HELLO34455667788991";

	rc = ss_binary_from_hexstr(output, sizeof(output), testvec_1);
	printf("input: %s, output: %s\n", testvec_1, ss_hexdump(output, rc));

	rc = ss_binary_from_hexstr(output_short, sizeof(output_short),
				   testvec_1);
	printf("input: %s, output (short): %s\n", testvec_1,
	       ss_hexdump(output_short, rc));

	rc = ss_binary_from_hexstr(output, sizeof(output), testvec_2);
	printf("input: %s, output: %s\n", testvec_2, ss_hexdump(output, rc));

	rc = ss_binary_from_hexstr(output_short, sizeof(output_short),
				   testvec_2);
	printf("input: %s, output (short): %s\n", testvec_2,
	       ss_hexdump(output_short, rc));

	rc = ss_binary_from_hexstr(output, sizeof(output), testvec_3);
	printf("input: %s, output: %s\n", testvec_3, ss_hexdump(output, rc));
}

int main(int argc, char **argv)
{
	ss_binary_from_hexstr_test();
	return 0;
}
