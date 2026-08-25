/*
 * Copyright (c) 2024 Onomondo ApS. All rights reserved.
 *
 * SPDX-License-Identifier: GPL-3.0-only
 * 
 * Author: Onomondo ApS
 */

#include <stdbool.h>
#include <string.h>
#include "onomondo/softsim/log.h"
#include "onomondo/utils/ss_profile.h"

static uint8_t ss_hex_to_uint8(const char *hex);
static void ss_hex_string_to_bytes(const uint8_t *hex, size_t hex_len, uint8_t *bytes);
static uint32_t ss_profile_uint32_from_hex(const char *hex);
static uint8_t ss_profile_decode(uint16_t len, const char *input_string, struct ss_profile *profile);
static bool ss_profile_copy_pin(uint8_t *field, const char *data, uint8_t data_len);

uint8_t ss_profile_from_string(uint16_t len, const char *input_string, struct ss_profile *profile)
{
	uint8_t rc = ss_profile_decode(len, input_string, profile);

	/* Ki, OPc, KIC, KID, PINs and PUK are already in the struct by the time a
	 * later record fails a check, and the caller frees without scrubbing. */
	if (rc)
		ss_profile_wipe(profile);
	return rc;
}

/* The decode itself, factored out so every error return lands in the wipe above. */
static uint8_t ss_profile_decode(uint16_t len, const char *input_string, struct ss_profile *profile)
{
	/* TAG(2) + LEN(2): the loop bound keeps the header inside the buffer, and the
	 * data_end check below bounds the data field. Rejected before anything is
	 * written into the output struct. */
	if (len < 4)
		return 1;

	/* Stucture (a004): [TAR[3] | MSL | KIC_IND | KID_IND | KIC[32] | KID[32] | */
	static const char a004_header[] = "b00011060101";
	const size_t A004_RECORD_SIZE = A004_HEADER_SIZE + KEY_SIZE + KEY_SIZE;

	/* A field the profile carries no tag for is left zeroed, which is how a caller
	 * tells the two apart. Zeroing here rather than expecting it of the caller. */
	memset(profile, 0, sizeof *profile);

	/* set the default header values */
	memcpy(&profile->_3F00_A004, a004_header, sizeof(a004_header) - 1);
	/* and fill the rest of the record with "f" */
	memset(&profile->_3F00_A004[A004_RECORD_SIZE], 'f', A004_LEN - A004_RECORD_SIZE);

	/* Structure (a003): three records of [header(12) | PIN(16) | PUK(16)]. Must
	 * match the shipped PIN code file: the record is written out whether or not
	 * the profile carried a PIN, and the ADM record has no PUK. */
	static const char a003_default[] = "0003000a000131323334ffffffff31323334353637380003000a008131323334ffffff"
					   "ff313233343536373801030000000a31323334ffffffffffffffffffffffff";
	memcpy(profile->_3F00_A003, a003_default, sizeof(a003_default) - 1);

	size_t pos = 0, data_end = 0, data_start = 0, next_pos = 0;
	uint8_t tag = 0, data_len = 0;

	while (pos + 4 <= len) {
		bool pin_fits = true;

		data_start = pos + 4;
		tag = ss_hex_to_uint8((char *)&input_string[pos]);
		data_len = ss_hex_to_uint8((char *)&input_string[pos + 2]);

		/* advance to next tag */
		data_end = data_start + data_len;
		next_pos = data_end;

		/* bad encoding */
		if (data_end > len)
			return 1;

		switch (tag) {
		case IMSI_TAG:
			if (data_len != IMSI_LEN)
				return 10;
			memcpy(&profile->_3F00_7ff0_6f07, &input_string[data_start], data_len);
			break;
		case ICCID_TAG:
			if (data_len != ICCID_LEN)
				return 11;
			memcpy(&profile->_3F00_2FE2, &input_string[data_start], data_len);
			break;
		case OPC_TAG:
			if (data_len != KEY_SIZE)
				return 12;
			memcpy(&profile->_3F00_A001[KEY_SIZE], &input_string[data_start], data_len);
			break;
		case KI_TAG:
			if (data_len != KEY_SIZE)
				return 13;
			memcpy(&profile->_3F00_A001[0], &input_string[data_start], data_len);
			ss_hex_string_to_bytes(&input_string[data_start], data_len, profile->k);
			break;
		case KIC_TAG:
			if (data_len != KEY_SIZE)
				return 14;
			memcpy(&profile->_3F00_A004[A004_HEADER_SIZE], &input_string[data_start], data_len);
			ss_hex_string_to_bytes(&input_string[data_start], data_len, profile->kic);
			break;
		case KID_TAG:
			if (data_len != KEY_SIZE)
				return 15;
			memcpy(&profile->_3F00_A004[A004_HEADER_SIZE + KEY_SIZE], &input_string[data_start], data_len);
			ss_hex_string_to_bytes(&input_string[data_start], data_len, profile->kid);
			break;
		case SMSP_TAG:
			if (data_len != (SMSP_RECORD_SIZE * 2))
				return 16;
			memcpy(&profile->SMSP, &input_string[data_start], data_len);
			break;
		case SMSC_TAG:
			if (data_len != SMSC_LEN)
				return 17;
			memcpy(&profile->SMSC, &input_string[data_start], data_len);
			break;
		case PIN_1_TAG:
			pin_fits = ss_profile_copy_pin(&profile->_3F00_A003[0 * A003_RECORD_SIZE + PIN_OFFSET],
						       &input_string[data_start], data_len);
			break;
		case PIN_2_TAG:
			pin_fits = ss_profile_copy_pin(&profile->_3F00_A003[1 * A003_RECORD_SIZE + PIN_OFFSET],
						       &input_string[data_start], data_len);
			break;
		case PIN_ADM_TAG:
			pin_fits = ss_profile_copy_pin(&profile->_3F00_A003[2 * A003_RECORD_SIZE + PIN_OFFSET],
						       &input_string[data_start], data_len);
			break;
		case PUK_TAG:
			pin_fits = ss_profile_copy_pin(&profile->_3F00_A003[0 * A003_RECORD_SIZE + PUK_OFFSET],
						       &input_string[data_start], data_len) &&
				   ss_profile_copy_pin(&profile->_3F00_A003[1 * A003_RECORD_SIZE + PUK_OFFSET],
						       &input_string[data_start], data_len);
			break;
		case CRC32_TAG:
			if (data_len != CRC32_LEN)
				return 18;
			/* The CRC32 of nothing is 0x00000000, so a record covering no
			 * characters would certify an empty profile as intact. */
			if (pos == 0)
				return 1;
			/* The record covers every character in front of it, which is exactly
			 * what the parser has walked past to get here. */
			if (ss_profile_crc32(input_string, pos) !=
			    ss_profile_uint32_from_hex(&input_string[data_start]))
				return 19;
			/* Nothing behind the record is covered by it, so the record ends the
			 * profile. Older decoders skip it as an unknown tag, which is only
			 * safe in this position too. */
			next_pos = len;
			break;
		case END_TAG:
			/* end of profile */
			next_pos = len;
			break;
		default:
			/* unknown tag, skip (next_pos already points to the right location) */
			break;
		}

		/* The PIN code file holds state the card maintains, so the provisioner
		 * needs to know whether the profile has anything to say about it. */
		if (tag == PIN_1_TAG || tag == PIN_2_TAG || tag == PIN_ADM_TAG || tag == PUK_TAG)
			profile->pin_present = 1;

		/* Refused rather than skipped, because the alternative is a card left on
		 * the shipped default while the profile says the value was rotated. Every
		 * other tag rejects a value it cannot store, and so does this one. */
		if (!pin_fits) {
			SS_LOGP(SPIN, LERROR,
				"profile tag %02x carries %u characters that no PIN code file record can hold\n",
				(unsigned int)tag, (unsigned int)data_len);
			return 20;
		}

		/* move the parser to the next position after handling the tag */
		pos = next_pos;
	}

	profile->_3F00_A001[KEY_SIZE + KEY_SIZE] = '0';
	profile->_3F00_A001[KEY_SIZE + KEY_SIZE + 1] = '0';

	return 0;
}

/* See in ss_profile.h. Writes through a volatile pointer so the compiler keeps
 * stores to storage it can see is dead. The uicc library has ss_memzero() for
 * this, but utils links without it. */
void ss_profile_wipe(struct ss_profile *profile)
{
	volatile char *clear_this = (volatile char *)profile;
	size_t i;

	for (i = 0; i < sizeof *profile; i++)
		clear_this[i] = 0;
}

/* See in ss_profile.h */
uint32_t ss_profile_crc32(const char *data, size_t len)
{
	uint32_t crc = 0xffffffff;
	size_t i;
	unsigned int bit;

	/* Bitwise on purpose: a 256 entry table would cost more flash than this
	 * loop costs time, and a profile is only a few hundred characters. */
	for (i = 0; i < len; i++) {
		uint8_t c = (uint8_t)data[i];

		/* Fold A-Z first (ASCII lowercasing): hex case carries no meaning
		 * downstream, so re-casing in transit must not invalidate the profile. */
		if (c >= 'A' && c <= 'Z')
			c += 'a' - 'A';
		crc ^= c;
		for (bit = 0; bit < 8; bit++)
			crc = (crc >> 1) ^ ((crc & 1) ? 0xedb88320u : 0u);
	}

	return ~crc;
}

/** Read a CRC record's value.
 *  \param[in] hex CRC32_LEN characters, most significant byte first.
 *  \returns the value they spell. */
static uint32_t ss_profile_uint32_from_hex(const char *hex)
{
	return ((uint32_t)ss_hex_to_uint8(&hex[0]) << 24) | ((uint32_t)ss_hex_to_uint8(&hex[2]) << 16) |
	       ((uint32_t)ss_hex_to_uint8(&hex[4]) << 8) | (uint32_t)ss_hex_to_uint8(&hex[6]);
}

static bool is_hex_digit(uint8_t c)
{
	return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
}

/** Copy a PIN, PUK or ADM value into a PIN code file record.
 *
 *  A record holds the value as the 16 hex characters of its 8 bytes, which is
 *  what the profile carries for a value of up to 8 characters. A 16 character
 *  value does not fit that way, but when it is itself hex it names those 8 bytes
 *  exactly -- the usual form of an ADM key -- so unwrap one layer of encoding
 *  instead of dropping it. Anything longer cannot be stored, nor presented:
 *  TS 102 221 clause 11.1.9.3 carries a PIN in exactly 8 bytes.
 *
 *  A short value is padded with 'f' so the unused bytes read as the 'FF' padding
 *  TS 31.101 clause 9.6 expects. The same clause sets a four digit minimum,
 *  which is eight characters here. Every character has to be hex either way: the
 *  record is a hex string, and whatever goes in comes back out through a hex
 *  decoder.
 *
 *  \param[out] field the 16 character field to fill, left untouched on failure
 *  \param[in] data the value as it appears in the profile
 *  \param[in] data_len length of data in characters
 *  \returns true if the value was stored */
static bool ss_profile_copy_pin(uint8_t *field, const char *data, uint8_t data_len)
{
	uint8_t unwrapped[PIN_SIZE];
	size_t i;

	/* Two characters per digit, and TS 31.101 clause 9.6 wants at least four. */
	if (data_len < 8 || data_len % 2)
		return false;

	if (data_len <= PIN_SIZE) {
		/* The record is read back as hex pairs, so a character that is not hex
		 * names no byte -- it decodes to the 0xFF padding and shortens the value
		 * the card ends up holding. */
		for (i = 0; i < data_len; i++) {
			if (!is_hex_digit((uint8_t)data[i]))
				return false;
		}
		memcpy(field, data, data_len);
		memset(&field[data_len], 'f', PIN_SIZE - data_len);
		return true;
	}

	if (data_len != 2 * PIN_SIZE)
		return false;

	/* Both layers have to be hex: the characters that arrive, so they spell a byte
	 * at all, and the characters they spell, because those are what the record
	 * stores. */
	for (i = 0; i < PIN_SIZE; i++) {
		if (!is_hex_digit((uint8_t)data[i * 2]) || !is_hex_digit((uint8_t)data[i * 2 + 1]))
			return false;
		unwrapped[i] = ss_hex_to_uint8(&data[i * 2]);
		if (!is_hex_digit(unwrapped[i]))
			return false;
	}

	memcpy(field, unwrapped, PIN_SIZE);
	return true;
}

/** Hex to uint8 converter
 *  \param[in] hex a pointer to hex value to be converted
 *  \returns converted uint8 value */
static uint8_t ss_hex_to_uint8(const char *hex)
{
	char hex_str[3] = { 0 };
	hex_str[0] = hex[0];
	hex_str[1] = hex[1];
	return (hex_str[0] % 32 + 9) % 25 * 16 + (hex_str[1] % 32 + 9) % 25;
}

/** Hex string to bytes converter
 *  \param[in] hex a pointer to the hex string
 *  \param[in] hex_len the size of the string
 *  \param[out] bytes the byte array to store the result in, hex_len / 2 bytes long */
static void ss_hex_string_to_bytes(const uint8_t *hex, size_t hex_len, uint8_t *bytes)
{
	size_t i;

	for (i = 0; i < hex_len / 2; i++) {
		bytes[i] = ss_hex_to_uint8((char *)&hex[i * 2]);
	}
}
