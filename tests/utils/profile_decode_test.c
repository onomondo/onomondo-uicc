/*
 * Copyright (c) 2024 Onomondo ApS. All rights reserved.
 *
 * SPDX-License-Identifier: GPL-3.0-only
 * 
 * Author: Onomondo ApS
 */

#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <onomondo/softsim/mem.h>
#include <onomondo/utils/ss_profile.h>

// clang-format off
static const char *decrypted_profile_ok =
	"01" "12" "080910101032540636"
	"02" "14" "98001032547698103214"
	"03" "20" "00000000000000000000000000000000"
	"04" "20" "000102030405060708090A0B0C0D0E0F"
	"05" "20" "000102030405060708090A0B0C0D0E0F"
	"06" "20" "000102030405060708090A0B0C0D0E0F";
// clang-format on

static const uint8_t test_profile_ki_uint8[] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
						 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F };
static const uint8_t test_profile_imsi[] = { "080910101032540636" };
static const uint8_t test_profile_iccid[] = { "98001032547698103214" };
static const uint8_t test_profile_opc[] = { "00000000000000000000000000000000" };
static const uint8_t test_profile_ki[] = { "000102030405060708090A0B0C0D0E0F" };

static void decode_softsim_profile_test_ok()
{
	printf("TEST: Decode a decrypted Onomondo SoftSIM profile\n");

	// PROFILE DECODE TEST - USING SS_STRUCT
	// Decode a profile in tlv hex string format and validate ss_profile struct.
	struct ss_profile *profile = SS_ALLOC(*profile);

	uint8_t rc = ss_profile_from_string(strlen(decrypted_profile_ok), decrypted_profile_ok, profile);
	printf("Profile decode return value: %d\n", rc);
	assert(rc == 0);

	printf("Checking ICCID\n");
	if (memcmp(test_profile_iccid, &profile->_3F00_2FE2, ICCID_LEN) == 0) {
		printf("Successfully validated ICCID: ");
		for (size_t print_counter = 0; print_counter < ICCID_LEN; print_counter++) {
			printf("%c", profile->_3F00_2FE2[print_counter]);
		}
		printf("\n");
	} else {
		fprintf(stderr, "Failed to validated ICCID\n");
	}

	printf("Checking IMSI\n");
	if (memcmp(test_profile_imsi, &profile->_3F00_7ff0_6f07, IMSI_LEN) == 0) {
		printf("Successfully validated IMSI : ");
		for (size_t print_counter = 0; print_counter < IMSI_LEN; print_counter++) {
			printf("%c", profile->_3F00_7ff0_6f07[print_counter]);
		}
		printf("\n");
	} else {
		fprintf(stderr, "Failed to validated IMSI\n");
	}

	printf("Checking OPC\n");
	if (memcmp(test_profile_opc, &profile->_3F00_A001[KEY_SIZE], KEY_SIZE) == 0) {
		printf("Successfully validated OPC  : ");
		for (size_t print_counter = 0; print_counter < KEY_SIZE; print_counter++) {
			printf("%c", profile->_3F00_A001[KEY_SIZE + print_counter]);
		}
		printf("\n");
	} else {
		fprintf(stderr, "Failed to validated OPC\n");
	}

	printf("Checking Ki\n");
	if (memcmp(test_profile_ki, &profile->_3F00_A001, KEY_SIZE) == 0) {
		printf("Successfully validated OPC  : ");
		for (size_t print_counter = 0; print_counter < KEY_SIZE; print_counter++) {
			printf("%c", profile->_3F00_A001[print_counter]);
		}
		printf("\n");
	} else {
		fprintf(stderr, "Failed to validated KI\n");
	}

	printf("Checking KIC\n");
	if (memcmp(test_profile_ki, &profile->_3F00_A004[A004_HEADER_SIZE], KEY_SIZE) == 0) {
		printf("Successfully validated KIC  : ");
		for (size_t print_counter = 0; print_counter < KEY_SIZE; print_counter++) {
			printf("%c", profile->_3F00_A004[A004_HEADER_SIZE + print_counter]);
		}
		printf("\n");
	} else {
		fprintf(stderr, "Failed to validated KIC\n");
	}

	printf("Checking KIC as bytes\n");
	if (memcmp(test_profile_ki_uint8, &profile->kic, KEY_SIZE / 2) == 0) {
		printf("Successfully validated KIC  : ");
		for (size_t print_counter = 0; print_counter < KEY_SIZE / 2; print_counter++) {
			printf("%02X", profile->kic[print_counter]);
		}
		printf("\n");
	} else {
		fprintf(stderr, "Failed to validated KIC\n");
	}

	printf("Checking KID\n");
	if (memcmp(test_profile_ki, &profile->_3F00_A004[A004_HEADER_SIZE + KEY_SIZE], KEY_SIZE) == 0) {
		printf("Successfully validated KID  : ");
		for (size_t print_counter = 0; print_counter < KEY_SIZE; print_counter++) {
			printf("%c", profile->_3F00_A004[A004_HEADER_SIZE + KEY_SIZE + print_counter]);
		}
		printf("\n");
	} else {
		fprintf(stderr, "Failed to validated KID\n");
	}

	SS_FREE(profile);
}

static void decode_softsim_profile_test_err_imsi()
{
	// clang-format off
	static const char *decrypted_profile_err =
		// Changing 2 first values in the IMSI
		"01" "12" "AA0910101032540636"
		"02" "14" "98001032547698103214"
		"03" "20" "00000000000000000000000000000000"
		"04" "20" "000102030405060708090A0B0C0D0E0F"
		"05" "20" "000102030405060708090A0B0C0D0E0F"
		"06" "20" "000102030405060708090A0B0C0D0E0F";
	// clang-format on

	printf("TEST: Decode a decrypted Onomondo SoftSIM profile with expected IMSI error\n");
	struct ss_profile *profile = SS_ALLOC(*profile);

	uint8_t rc = ss_profile_from_string(strlen(decrypted_profile_err), decrypted_profile_err, profile);
	printf("Profile decode return value: %d\n", rc);
	assert(rc == 0);

	printf("Checking ICCID\n");
	if (memcmp(test_profile_iccid, &profile->_3F00_2FE2, ICCID_LEN) == 0) {
		printf("Successfully validated ICCID: ");
		for (size_t print_counter = 0; print_counter < ICCID_LEN; print_counter++) {
			printf("%c", profile->_3F00_2FE2[print_counter]);
		}
		printf("\n");
	} else {
		fprintf(stderr, "Failed to validated ICCID\n");
	}

	printf("Checking IMSI\n");
	if (memcmp(test_profile_imsi, &profile->_3F00_7ff0_6f07, IMSI_LEN) == 0) {
		printf("Successfully validated IMSI : ");
		for (size_t print_counter = 0; print_counter < IMSI_LEN; print_counter++) {
			printf("%c", profile->_3F00_7ff0_6f07[print_counter]);
		}
		printf("\n");
	} else {
		fprintf(stderr, "Failed to validated IMSI\n");
	}

	SS_FREE(profile);
}

static void decode_softsim_profile_test_err_bad_length_encoding()
{
	// Invalidating length of KI
	// clang-format off
	static const char *decrypted_profile_err_decode =
		"01" "12" "080910101032540636"
		"02" "14" "98001032547698103214"
		"03" "20" "00000000000000000000000000000000"
		// LEN SET TO 00
		"04" "00" "000102030405060708090A0B0C0D0E0F"
		"05" "20" "000102030405060708090A0B0C0D0E0F"
		"06" "20" "000102030405060708090A0B0C0D0E0F";
	// clang-format on
	printf("TEST: Decode a decrypted Onomondo SoftSIM profile with expected decode error\n");
	struct ss_profile profile = { 0 };
	uint8_t rc =
		ss_profile_from_string(strlen(decrypted_profile_err_decode), decrypted_profile_err_decode, &profile);
	printf("Profile decode return value: %d\n", rc);
}

static void decode_softsim_profile_test_err_length_no_overflow()
{
	// Invalidating length of last tag to FF
	// clang-format off
	static const char *decrypted_profile_err_decode =
		"01" "12" "080910101032540636"
		"02" "14" "98001032547698103214"
		"03" "20" "00000000000000000000000000000000"
		"04" "20" "000102030405060708090A0B0C0D0E0F"
		"05" "20" "000102030405060708090A0B0C0D0E0F"
		// LEN SET TO FF
		"06" "FF" "000102030405060708090A0B0C0D0E0F";
	// clang-format on

	printf("TEST: Decode a decrypted Onomondo SoftSIM profile with expected decode error\n");
	struct ss_profile profile = { 0 };

	uint8_t rc =
		ss_profile_from_string(strlen(decrypted_profile_err_decode), decrypted_profile_err_decode, &profile);
	printf("Profile decode return value: %d\n", rc);
}

int main(int argc, char **argv)
{
	decode_softsim_profile_test_ok();
	decode_softsim_profile_test_err_imsi();
	decode_softsim_profile_test_err_bad_length_encoding();
	decode_softsim_profile_test_err_length_no_overflow();
	return 0;
}
