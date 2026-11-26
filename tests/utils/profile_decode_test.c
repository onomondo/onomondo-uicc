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

static const char test_profile_imsi[] = "080910101032540636";
static const char test_profile_iccid[] = "98001032547698103214";
static const char test_profile_opc[] = "00000000000000000000000000000000";
/* The profile carries Ki, KIC and KID in upper case (0A0B...); the decoded
 * fields hold them in lower case, the format of the EFs. */
static const char test_profile_ki[] = "000102030405060708090a0b0c0d0e0f";

/* Every field holds the hex characters of its record, in lower case whatever
 * case the profile carried them in; the provisioning writer converts them for
 * its storage. */
static void check_field(const char *what, const uint8_t *field, size_t len, const char *expect)
{
	printf("Checking %s\n", what);
	assert(memcmp(field, expect, len) == 0);
	printf("Successfully validated %-5s: %.*s\n", what, (int)len, (const char *)field);
}

static void assert_cleared(const struct ss_profile *profile)
{
	static const uint8_t zero[sizeof(struct ss_profile)] = { 0 };

	assert(memcmp(profile, zero, sizeof(*profile)) == 0);
	printf("Profile struct cleared\n");
}

static void decode_softsim_profile_test_ok()
{
	printf("TEST: Decode a decrypted Onomondo SoftSIM profile\n");

	// PROFILE DECODE TEST - USING SS_STRUCT
	// Decode a profile in tlv hex string format and validate ss_profile struct.
	struct ss_profile *profile = SS_ALLOC(*profile);

	uint8_t rc = ss_profile_from_string(strlen(decrypted_profile_ok), decrypted_profile_ok, profile);
	printf("Profile decode return value: %d\n", rc);
	assert(rc == 0);

	check_field("ICCID", profile->iccid, ICCID_LEN, test_profile_iccid);
	check_field("IMSI", profile->imsi, IMSI_LEN, test_profile_imsi);
	check_field("OPC", profile->opc, KEY_SIZE, test_profile_opc);
	check_field("Ki", profile->ki, KEY_SIZE, test_profile_ki);
	check_field("KIC", profile->kic, KEY_SIZE, test_profile_ki);
	check_field("KID", profile->kid, KEY_SIZE, test_profile_ki);

	/* The profile carries every tag provisioning needs, and nothing else. */
	assert(ss_profile_has_required_tags(profile));
	assert(ss_profile_has_tag(profile, IMSI_TAG));
	assert(ss_profile_has_tag(profile, KID_TAG));
	assert(!ss_profile_has_tag(profile, SMSP_TAG));
	assert(!ss_profile_has_tag(profile, PIN_1_TAG));
	assert(!ss_profile_has_tag(profile, CRC32_TAG));
	printf("Tags: required present, optional absent\n");

	ss_profile_wipe(profile);
	SS_FREE(profile);
}

/* EF.IMSI byte 1 is the IMSI length in bytes, 1..8 (TS 31.102 4.2.2); 0xAA is not. */
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
	assert(rc == 10);
	assert_cleared(profile);

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
	assert(rc == 13);
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
	assert(rc == 1);
}

/* An input too short to hold one TAG(2) + LEN(2) record header is rejected without
 * reading it. Every character must be hex, so a line ending is refused: the caller
 * strips it. The last record must end exactly at the end of the input, so one to
 * three trailing characters -- too few for a header -- are refused as well. */
static void decode_softsim_profile_test_short_input()
{
	char buf[256];
	struct ss_profile profile = { 0 };
	uint8_t rc;

	printf("TEST: Decode a decrypted Onomondo SoftSIM profile that is too short\n");

	rc = ss_profile_from_string(0, "", &profile);
	printf("Profile decode return value: %d\n", rc);
	assert(rc == 1);

	rc = ss_profile_from_string(2, "b0", &profile);
	printf("Profile decode return value: %d\n", rc);
	assert(rc == 1);

	printf("TEST: Decode a decrypted Onomondo SoftSIM profile ending in a line ending\n");
	snprintf(buf, sizeof(buf), "%s\r\n", decrypted_profile_ok);
	rc = ss_profile_from_string(strlen(buf), buf, &profile);
	printf("Profile decode return value: %d\n", rc);
	assert(rc == 3);

	printf("TEST: Decode a decrypted Onomondo SoftSIM profile with 1 to 3 trailing characters\n");
	for (int n = 1; n <= 3; n++) {
		/* "0", "04", "042": the start of a Ki record header */
		snprintf(buf, sizeof(buf), "%s%.*s", decrypted_profile_ok, n, "042");
		rc = ss_profile_from_string(strlen(buf), buf, &profile);
		printf("Profile decode return value: %d\n", rc);
		assert(rc == 1);
		assert_cleared(&profile);
	}
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
	/* A valid CRC, then an END record: nothing may follow the CRC, END included. */
	static const char *profile_crc_then_end = PROFILE_OK_TAGS "fe08610658d0" "ff00";
	/* A CRC record cut inside its header, too short to be parsed as a record. */
	static const char *profile_crc_cut = PROFILE_OK_TAGS "fe0";
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

	/* The record covers only what is in front of it, so a record appended behind
	 * it is refused: a decoder that parses on past the CRC would take it
	 * unchecked. */
	printf("TEST: Decode a profile with a record appended after its CRC32\n");
	rc = ss_profile_from_string(strlen(profile_crc_then_imsi), profile_crc_then_imsi, &profile);
	printf("Profile decode return value: %d\n", rc);
	assert(rc == 1);
	assert_cleared(&profile);

	printf("TEST: Decode a profile with an END record after its CRC32\n");
	rc = ss_profile_from_string(strlen(profile_crc_then_end), profile_crc_then_end, &profile);
	printf("Profile decode return value: %d\n", rc);
	assert(rc == 1);

	/* Cut inside the CRC header, the record is too short to be recognised; the
	 * profile must not decode as if it never carried one. */
	printf("TEST: Decode a profile whose CRC32 record is cut inside its header\n");
	rc = ss_profile_from_string(strlen(profile_crc_cut), profile_crc_cut, &profile);
	printf("Profile decode return value: %d\n", rc);
	assert(rc == 1);

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
	uint8_t rc;

	printf("TEST: A rejected profile leaves no key material behind\n");
	rc = ss_profile_from_string(strlen(profile_ki_then_short_kic), profile_ki_then_short_kic, &profile);
	printf("Profile decode return value: %d\n", rc);
	assert(rc == 14);
	assert_cleared(&profile);
}

/* The four tags the provisioner requires plus the optional OTA keys, see
 * decode_softsim_profile_test_ok. */
// clang-format off
#define REQUIRED_TAGS \
	"01" "12" "080910101032540636" \
	"02" "14" "98001032547698103214" \
	"03" "20" "00000000000000000000000000000000" \
	"04" "20" "000102030405060708090A0B0C0D0E0F" \
	"05" "20" "000102030405060708090A0B0C0D0E0F" \
	"06" "20" "000102030405060708090A0B0C0D0E0F"
// clang-format on

static void check_pin_field(const char *what, const uint8_t *field, const char *expect)
{
	printf("%s: %.*s\n", what, PIN_SIZE, (const char *)field);
	assert(memcmp(field, expect, PIN_SIZE) == 0);
}

/* A value that cannot be decoded is refused, so a card is never left on the
 * shipped default while the profile says the value was rotated. The struct is
 * cleared with it, as on every other error return. */
static void check_refused(const char *what, const char *profile_string, uint8_t expect_rc)
{
	struct ss_profile profile = { 0 };
	uint8_t rc;

	printf("TEST: Decode a decrypted Onomondo SoftSIM profile whose %s cannot be stored\n", what);
	rc = ss_profile_from_string(strlen(profile_string), profile_string, &profile);
	printf("Profile decode return value: %d\n", rc);
	assert(rc == expect_rc);
	assert_cleared(&profile);
}

/* A profile carries a PIN as the hex encoded ASCII of its characters, so up to 8
 * characters arrive as the 16 the record holds. A 16 character ADM arrives as 32
 * and fits only because it is itself hex, naming the 8 bytes a VERIFY PIN can
 * carry (TS 102 221 clause 11.1.9.3). */
static void decode_softsim_profile_test_pins()
{
	// clang-format off
	static const char *profile_pins =
		REQUIRED_TAGS
		"08" "08" "36383638"                          /* PIN 6868 */
		"09" "10" "3132333435363738"                  /* PIN2 12345678 */
		"0b" "10" "3739373937393739"                  /* PUK 79797979 */
		"0a" "20" "38303334323730323533313133383634"; /* ADM 8034270253113864 */
	static const char *profile_adm_ascii =
		REQUIRED_TAGS
		"0a" "10" "3838383838383838";                 /* ADM 88888888 */
	/* An ADM that is not hex cannot name 8 bytes. */
	static const char *profile_adm_not_hex =
		REQUIRED_TAGS
		"0a" "20" "414143434545474749494b4b4d4d4f4f"; /* ADM AACCEEGGIIKKMMOO */
	/* 9 characters: too long for ASCII in 8 bytes, too short to be 16 hex digits */
	static const char *profile_adm_9 =
		REQUIRED_TAGS
		"0a" "12" "313233343536373839";               /* ADM 123456789 */
	static const char *profile_pin_padded =
		REQUIRED_TAGS
		"08" "08" "35363738";                         /* PIN 5678 */
	static const char *profile_pin_short =
		REQUIRED_TAGS
		"08" "04" "3132";                             /* PIN 12, under the four digit minimum */
	static const char *profile_pin_odd =
		REQUIRED_TAGS
		"08" "09" "313233343";                        /* half a byte */
	/* The profile is a hex string, so a character outside it is refused up front. */
	static const char *profile_pin_not_hex =
		REQUIRED_TAGS
		"08" "08" "3132zzzz";
	// clang-format on
	struct ss_profile profile = { 0 };
	uint8_t rc;

	printf("TEST: Decode a decrypted Onomondo SoftSIM profile carrying PIN, PIN2, PUK and ADM\n");

	rc = ss_profile_from_string(strlen(profile_pins), profile_pins, &profile);
	printf("Profile decode return value: %d\n", rc);
	assert(rc == 0);
	check_pin_field("PIN1", profile.pin1, "36383638ffffffff");
	check_pin_field("PIN2", profile.pin2, "3132333435363738");
	check_pin_field("PUK ", profile.puk, "3739373937393739");
	check_pin_field("ADM ", profile.adm, "8034270253113864");
	assert(ss_profile_has_tag(&profile, PIN_1_TAG) && ss_profile_has_tag(&profile, PIN_2_TAG) &&
	       ss_profile_has_tag(&profile, PUK_TAG) && ss_profile_has_tag(&profile, PIN_ADM_TAG));

	printf("TEST: Decode a decrypted Onomondo SoftSIM profile with a PIN shorter than the field\n");

	rc = ss_profile_from_string(strlen(profile_pin_padded), profile_pin_padded, &profile);
	printf("Profile decode return value: %d\n", rc);
	assert(rc == 0);
	check_pin_field("PIN1", profile.pin1, "35363738ffffffff");
	assert(!ss_profile_has_tag(&profile, PIN_2_TAG));

	printf("TEST: Decode a decrypted Onomondo SoftSIM profile with an 8 character ADM\n");

	rc = ss_profile_from_string(strlen(profile_adm_ascii), profile_adm_ascii, &profile);
	printf("Profile decode return value: %d\n", rc);
	assert(rc == 0);
	check_pin_field("ADM ", profile.adm, "3838383838383838");

	check_refused("ADM", profile_adm_not_hex, 20);
	check_refused("ADM", profile_adm_9, 20);
	check_refused("PIN", profile_pin_short, 20);
	check_refused("PIN", profile_pin_odd, 20);
	check_refused("PIN", profile_pin_not_hex, 3);
}

/* Deciding which tags a profile must carry belongs to whoever consumes it: the
 * provisioner refuses an incomplete profile, the decoder reports what it found.
 * Keep it that way -- the profile source emits tags only for the fields it has. */
static void decode_softsim_profile_test_partial_is_not_an_error()
{
	// clang-format off
	static const char *profile_no_keys =
		"01" "12" "080910101032540636"
		"02" "14" "98001032547698103214"
		"03" "20" "00000000000000000000000000000000"
		"04" "20" "000102030405060708090A0B0C0D0E0F";
	static const char *profile_no_opc =
		"01" "12" "080910101032540636"
		"02" "14" "98001032547698103214"
		"04" "20" "000102030405060708090A0B0C0D0E0F";
	// clang-format on
	static const uint8_t zero_key[KEY_SIZE] = { 0 };
	struct ss_profile profile = { 0 };
	uint8_t rc;

	printf("TEST: Decode a decrypted Onomondo SoftSIM profile that carries only some tags\n");

	rc = ss_profile_from_string(strlen(profile_no_keys), profile_no_keys, &profile);
	printf("Profile decode return value: %d\n", rc);
	assert(rc == 0);
	/* A field without a tag is left zeroed, and the tags say what is missing.
	 * KIC and KID are optional OTA keys, so the profile still has every tag
	 * provisioning requires. */
	assert(ss_profile_has_required_tags(&profile));
	assert(ss_profile_has_tag(&profile, KI_TAG));
	assert(!ss_profile_has_tag(&profile, KIC_TAG) && !ss_profile_has_tag(&profile, KID_TAG));
	assert(memcmp(profile.kic, zero_key, KEY_SIZE) == 0);
	printf("Missing KIC and KID reported, fields left zeroed\n");

	/* Without the OPc the profile still decodes, but is not enough to provision */
	rc = ss_profile_from_string(strlen(profile_no_opc), profile_no_opc, &profile);
	printf("Profile decode return value: %d\n", rc);
	assert(rc == 0);
	assert(!ss_profile_has_tag(&profile, OPC_TAG));
	assert(!ss_profile_has_required_tags(&profile));
	printf("Missing OPc reported as not enough to provision\n");
}

/* Unknown records are skipped, so a newer profile still decodes on this decoder;
 * an END record ends the profile and whatever follows it is not parsed. */
static void decode_softsim_profile_test_unknown_and_end()
{
	// clang-format off
	static const char *profile_unknown = REQUIRED_TAGS "80" "04" "abcd";
	static const char *profile_end = REQUIRED_TAGS "ff" "00" "01" "12" "999999999999999999";
	// clang-format on
	struct ss_profile profile = { 0 };
	uint8_t rc;

	printf("TEST: Decode a decrypted Onomondo SoftSIM profile carrying an unknown record\n");
	rc = ss_profile_from_string(strlen(profile_unknown), profile_unknown, &profile);
	printf("Profile decode return value: %d\n", rc);
	assert(rc == 0);
	assert(ss_profile_has_required_tags(&profile));

	printf("TEST: Decode a decrypted Onomondo SoftSIM profile with records after END\n");
	rc = ss_profile_from_string(strlen(profile_end), profile_end, &profile);
	printf("Profile decode return value: %d\n", rc);
	assert(rc == 0);
	check_field("IMSI", profile.imsi, IMSI_LEN, test_profile_imsi);
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
	decode_softsim_profile_test_partial_is_not_an_error();
	decode_softsim_profile_test_pins();
	decode_softsim_profile_test_unknown_and_end();
	return 0;
}
