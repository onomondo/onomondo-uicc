/*
 * Copyright (c) 2024 Onomondo ApS. All rights reserved.
 *
 * SPDX-License-Identifier: GPL-3.0-only
 * 
 * Author: Onomondo ApS
 */

#include <assert.h>
#include <stdio.h>
#include <ctype.h>
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

/* An input too short to hold one TAG(2) + LEN(2) record header is rejected without
 * reading it. Fewer than four trailing characters are ignored regardless of their
 * content, so a profile arriving with a line ending decodes; four or more are
 * parsed as a record header. */
static void decode_softsim_profile_test_short_input()
{
	char with_line_ending[256];
	struct ss_profile profile = { 0 };
	uint8_t rc;

	printf("TEST: Decode a decrypted Onomondo SoftSIM profile that is too short\n");

	rc = ss_profile_from_string(0, "", &profile);
	printf("Profile decode return value: %d\n", rc);
	assert(rc != 0);

	rc = ss_profile_from_string(2, "b0", &profile);
	printf("Profile decode return value: %d\n", rc);
	assert(rc != 0);

	snprintf(with_line_ending, sizeof(with_line_ending), "%s\r\n", decrypted_profile_ok);
	rc = ss_profile_from_string(strlen(with_line_ending), with_line_ending, &profile);
	printf("Profile decode return value: %d\n", rc);
	assert(rc == 0);
}

/* The same tags as decrypted_profile_ok, as one string so a CRC can be appended.
 * This is byte for byte what the exporter emits for its own test profile, so
 * 610658d0 is the value both implementations have to agree on. */
// clang-format off
#define PROFILE_OK_TAGS \
	"01" "12" "080910101032540636" \
	"02" "14" "98001032547698103214" \
	"03" "20" "00000000000000000000000000000000" \
	"04" "20" "000102030405060708090a0b0c0d0e0f" \
	"05" "20" "000102030405060708090a0b0c0d0e0f" \
	"06" "20" "000102030405060708090a0b0c0d0e0f"
// clang-format on

/* An optional CRC32 record covers every character before it. */
static void decode_softsim_profile_test_crc()
{
	// clang-format off
	static const char *profile_crc_ok = PROFILE_OK_TAGS "fe08610658d0";
	static const char *profile_crc_upper = PROFILE_OK_TAGS "fe08610658D0";
	static const char *profile_crc_short = PROFILE_OK_TAGS "fe06016ba5";
	/* A CRC record with nothing in front of it, spelling crc32("") */
	static const char *profile_crc_only = "fe0800000000";
	/* A valid CRC, then an IMSI record the CRC does not cover. */
	static const char *profile_crc_then_imsi = PROFILE_OK_TAGS "fe08610658d0"
						   "01" "12" "999999999999999999";
	/* Same profile, one character of the Ki flipped. */
	static const char *profile_crc_body_changed =
		"01" "12" "080910101032540636"
		"02" "14" "98001032547698103214"
		"03" "20" "00000000000000000000000000000000"
		"04" "20" "000102030405060708090a0b0c0d0e0e"
		"05" "20" "000102030405060708090a0b0c0d0e0f"
		"06" "20" "000102030405060708090a0b0c0d0e0f"
		"fe" "08" "610658d0";
	// clang-format on
	struct ss_profile profile = { 0 };
	char recased[sizeof(PROFILE_OK_TAGS) + CRC32_LEN + 4];
	size_t i;
	uint8_t rc;

	printf("TEST: CRC32 known answer\n");
	printf("CRC32 of \"123456789\": %08x\n", ss_profile_crc32("123456789", 9));
	assert(ss_profile_crc32("123456789", 9) == 0xcbf43926);
	/* The fold itself: both spellings must produce one CRC. */
	assert(ss_profile_crc32("AbCdEf", 6) == ss_profile_crc32("abcdef", 6));

	printf("TEST: Decode a decrypted Onomondo SoftSIM profile carrying a matching CRC32\n");
	rc = ss_profile_from_string(strlen(profile_crc_ok), profile_crc_ok, &profile);
	printf("Profile decode return value: %d\n", rc);
	assert(rc == 0);

	printf("TEST: The same profile with the CRC written in upper case\n");
	rc = ss_profile_from_string(strlen(profile_crc_upper), profile_crc_upper, &profile);
	printf("Profile decode return value: %d\n", rc);
	assert(rc == 0);

	/* A transport that re-cases the whole string must not invalidate it. */
	printf("TEST: The same profile upper-cased in transit\n");
	strcpy(recased, profile_crc_ok);
	for (i = 0; recased[i]; i++)
		recased[i] = (char)toupper((unsigned char)recased[i]);
	rc = ss_profile_from_string(strlen(recased), recased, &profile);
	printf("Profile decode return value: %d\n", rc);
	assert(rc == 0);

	printf("TEST: Decode a profile whose body no longer matches its CRC32\n");
	rc = ss_profile_from_string(strlen(profile_crc_body_changed), profile_crc_body_changed, &profile);
	printf("Profile decode return value: %d\n", rc);
	assert(rc == 19);

	printf("TEST: Decode a profile whose CRC32 record is the wrong length\n");
	rc = ss_profile_from_string(strlen(profile_crc_short), profile_crc_short, &profile);
	printf("Profile decode return value: %d\n", rc);
	assert(rc == 18);

	/* The record ends the profile, so a record appended behind it -- which the CRC
	 * does not cover -- must not reach the struct. */
	printf("TEST: Decode a profile with a record appended after its CRC32\n");
	rc = ss_profile_from_string(strlen(profile_crc_then_imsi), profile_crc_then_imsi, &profile);
	printf("Profile decode return value: %d\n", rc);
	assert(rc == 0);
	assert(memcmp(profile._3F00_7ff0_6f07, test_profile_imsi, IMSI_LEN) == 0);
	printf("Appended record ignored\n");

	/* A profile without the record must keep decoding, which is what every
	 * profile in the field looks like. */
	printf("TEST: Decode a profile carrying no CRC32 record\n");
	rc = ss_profile_from_string(strlen(PROFILE_OK_TAGS), PROFILE_OK_TAGS, &profile);
	printf("Profile decode return value: %d\n", rc);
	assert(rc == 0);

	/* crc32("") is 0x00000000, so a lone CRC record spells its own correct value
	 * and would otherwise certify a profile carrying nothing at all. */
	printf("TEST: Decode a profile that is nothing but a CRC32 record\n");
	rc = ss_profile_from_string(strlen(profile_crc_only), profile_crc_only, &profile);
	printf("Profile decode return value: %d\n", rc);
	assert(rc == 1);
}

/* A rejected profile is cleared before it goes back to the caller, which frees it
 * without scrubbing. The record order matters: the Ki is copied in before the KIC
 * record is found to be short. */
static void decode_softsim_profile_test_err_scrubs()
{
	// clang-format off
	static const char *profile_ki_then_short_kic =
		"04" "20" "000102030405060708090A0B0C0D0E0F"
		"05" "02" "00";
	// clang-format on
	struct ss_profile profile = { 0 };
	uint8_t zero[sizeof(struct ss_profile)] = { 0 };
	uint8_t rc;

	printf("TEST: A rejected profile leaves no key material behind\n");
	rc = ss_profile_from_string(strlen(profile_ki_then_short_kic), profile_ki_then_short_kic, &profile);
	printf("Profile decode return value: %d\n", rc);
	assert(rc == 14);
	assert(memcmp(&profile, zero, sizeof(profile)) == 0);
	printf("Profile struct cleared\n");
}

int main(int argc, char **argv)
{
	decode_softsim_profile_test_ok();
	decode_softsim_profile_test_err_imsi();
	decode_softsim_profile_test_err_bad_length_encoding();
	decode_softsim_profile_test_err_length_no_overflow();
	decode_softsim_profile_test_short_input();
	decode_softsim_profile_test_crc();
	decode_softsim_profile_test_err_scrubs();
	return 0;
}
