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
#include "ss_utils_memzero.h"

#define SS_REQUIRED_TAGS (SS_TAG_BIT(IMSI_TAG) | SS_TAG_BIT(ICCID_TAG) | SS_TAG_BIT(KI_TAG) | SS_TAG_BIT(OPC_TAG))

/* EF.IMSI byte 1 is the number of bytes after it holding the IMSI (TS 31.102 4.2.2) */
#define IMSI_MAX_DATA_LEN (IMSI_BIN_LEN - 1)

static uint8_t ss_hex_to_uint8(const char *hex);
static bool ss_is_hex(const char *str, size_t len);
static uint32_t ss_profile_uint32_from_hex(const char *hex);
static uint8_t ss_profile_decode(uint16_t len, const char *input_string, struct ss_profile *profile);
static bool ss_profile_copy_pin(uint8_t *field, const char *data, uint8_t data_len);
static void ss_profile_copy_hex(uint8_t *field, const char *data, size_t len);

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
	size_t pos = 0, data_start, data_end, next_pos;
	uint8_t tag, data_len;

	/* Need at least one TAG + LEN header, and every character must be hex. */
	if (len < 4)
		return SS_PROFILE_ERR_MALFORMED;
	if (!ss_is_hex(input_string, len))
		return SS_PROFILE_ERR_NOT_HEX;

	/* A field the profile carries no tag for is left zeroed */
	memset(profile, 0, sizeof *profile);

	while (pos + 4 <= len) {
		bool pin_fits = true;

		data_start = pos + 4;
		tag = ss_hex_to_uint8(&input_string[pos]);
		data_len = ss_hex_to_uint8(&input_string[pos + 2]);
		data_end = data_start + data_len;
		next_pos = data_end;

		/* bad encoding */
		if (data_end > len)
			return SS_PROFILE_ERR_MALFORMED;

		switch (tag) {
		case IMSI_TAG: {
			uint8_t imsi_len;

			if (data_len != IMSI_LEN)
				return SS_PROFILE_ERR_IMSI;
			/* EF.IMSI byte 1 is the IMSI length in bytes (1..8, TS 31.102
			 * 4.2.2); anything else fails USIM initialisation */
			imsi_len = ss_hex_to_uint8(&input_string[data_start]);
			if (imsi_len < 1 || imsi_len > IMSI_MAX_DATA_LEN)
				return SS_PROFILE_ERR_IMSI;
			ss_profile_copy_hex(profile->imsi, &input_string[data_start], data_len);
			break;
		}
		case ICCID_TAG:
			if (data_len != ICCID_LEN)
				return SS_PROFILE_ERR_ICCID;
			ss_profile_copy_hex(profile->iccid, &input_string[data_start], data_len);
			break;
		case OPC_TAG:
			if (data_len != KEY_SIZE)
				return SS_PROFILE_ERR_OPC;
			ss_profile_copy_hex(profile->opc, &input_string[data_start], data_len);
			break;
		case KI_TAG:
			if (data_len != KEY_SIZE)
				return SS_PROFILE_ERR_KI;
			ss_profile_copy_hex(profile->ki, &input_string[data_start], data_len);
			break;
		case KIC_TAG:
			if (data_len != KEY_SIZE)
				return SS_PROFILE_ERR_KIC;
			ss_profile_copy_hex(profile->kic, &input_string[data_start], data_len);
			break;
		case KID_TAG:
			if (data_len != KEY_SIZE)
				return SS_PROFILE_ERR_KID;
			ss_profile_copy_hex(profile->kid, &input_string[data_start], data_len);
			break;
		case SMSP_TAG:
			if (data_len != SMSP_LEN)
				return SS_PROFILE_ERR_SMSP;
			ss_profile_copy_hex(profile->smsp, &input_string[data_start], data_len);
			break;
		case SMSC_TAG:
			if (data_len != SMSC_LEN)
				return SS_PROFILE_ERR_SMSC;
			ss_profile_copy_hex(profile->smsc, &input_string[data_start], data_len);
			break;
		case PIN_1_TAG:
			pin_fits = ss_profile_copy_pin(profile->pin1, &input_string[data_start], data_len);
			break;
		case PIN_2_TAG:
			pin_fits = ss_profile_copy_pin(profile->pin2, &input_string[data_start], data_len);
			break;
		case PIN_ADM_TAG:
			pin_fits = ss_profile_copy_pin(profile->adm, &input_string[data_start], data_len);
			break;
		case PUK_TAG:
			pin_fits = ss_profile_copy_pin(profile->puk, &input_string[data_start], data_len);
			break;
		case CRC32_TAG:
			if (data_len != CRC32_LEN)
				return SS_PROFILE_ERR_CRC_LEN;
			/* The CRC32 of nothing is 0x00000000, so a record covering no
			 * characters would certify an empty profile as intact. */
			if (pos == 0)
				return SS_PROFILE_ERR_MALFORMED;
			/* The record covers only what is in front of it, so nothing may
			 * follow it: a record behind it would be decoded unchecked by any
			 * decoder that parses on past the CRC. */
			if (data_end != len)
				return SS_PROFILE_ERR_MALFORMED;
			/* The record covers every character in front of it, which is exactly
			 * what the parser has walked past to get here. */
			if (ss_profile_crc32(input_string, pos) !=
			    ss_profile_uint32_from_hex(&input_string[data_start]))
				return SS_PROFILE_ERR_CRC;
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

		/* Refused rather than skipped, because the alternative is a card left on
		 * the shipped default while the profile says the value was rotated. Every
		 * other tag rejects a value it cannot store, and so does this one. */
		if (!pin_fits) {
			SS_LOGP(SPIN, LERROR,
				"profile tag %02x carries %u characters that no PIN code file record can hold\n",
				(unsigned int)tag, (unsigned int)data_len);
			return SS_PROFILE_ERR_PIN;
		}

		/* record the tag, so the provisioner knows which fields the profile set */
		if (tag >= IMSI_TAG && tag <= SMSC_TAG)
			profile->tags |= SS_TAG_BIT(tag);

		/* move the parser to the next position after handling the tag */
		pos = next_pos;
	}

	/* the last record must end exactly at the end of the string */
	if (pos != len)
		return SS_PROFILE_ERR_MALFORMED;

	return SS_PROFILE_OK;
}

/* See in ss_profile.h */
bool ss_profile_has_tag(const struct ss_profile *profile, uint8_t tag)
{
	return tag >= IMSI_TAG && tag <= SMSC_TAG && (profile->tags & SS_TAG_BIT(tag));
}

/* See in ss_profile.h */
bool ss_profile_has_required_tags(const struct ss_profile *profile)
{
	return (profile->tags & SS_REQUIRED_TAGS) == SS_REQUIRED_TAGS;
}

/* See in ss_profile.h */
void ss_profile_wipe(struct ss_profile *profile)
{
	ss_utils_memzero(profile, sizeof *profile);
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

/** Check that a string only holds hex digits */
static bool ss_is_hex(const char *str, size_t len)
{
	size_t i;

	for (i = 0; i < len; i++) {
		char c = str[i];

		if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')))
			return false;
	}
	return true;
}

/** Copy hex characters into a profile field, in lower case.
 *
 *  Hex case carries no meaning, but the EFs are lower case -- the template
 *  files/, and everything the storage layer writes ("%02x") -- so every field
 *  is normalized here, once: what a platform edits and what provisioning writes
 *  is then in the files' format whatever case the profile arrived in. The
 *  caller has already checked that data is hex.
 *
 *  \param[out] field the field to fill, len characters
 *  \param[in] data hex characters
 *  \param[in] len number of characters */
static void ss_profile_copy_hex(uint8_t *field, const char *data, size_t len)
{
	size_t i;

	for (i = 0; i < len; i++) {
		char c = data[i];

		field[i] = (uint8_t)((c >= 'A' && c <= 'F') ? c - 'A' + 'a' : c);
	}
}

/** Copy a PIN, PUK or ADM value into its PIN_SIZE character field.
 *
 *  A PIN code file record holds a value in 8 bytes, which the profile carries as
 *  16 hex characters for a value of up to 8 characters. A 16 character value does
 *  not fit that way, but when it is itself hex it names those 8 bytes exactly --
 *  the usual form of an ADM key -- so unwrap one layer of encoding instead of
 *  dropping it. Anything longer cannot be stored, nor presented: TS 102 221
 *  clause 11.1.9.3 carries a PIN in exactly 8 bytes.
 *
 *  A short value is padded with 'f', so the unused bytes read as the 0xFF padding
 *  TS 31.101 clause 9.6 expects. The same clause sets a four digit minimum, which
 *  is eight characters here. The caller has already checked that data is hex.
 *
 *  \param[out] field the PIN_SIZE character field to fill, left untouched on failure
 *  \param[in] data the value as it appears in the profile
 *  \param[in] data_len length of data in characters
 *  \returns true if the value was stored */
static bool ss_profile_copy_pin(uint8_t *field, const char *data, uint8_t data_len)
{
	char unwrapped[PIN_SIZE];
	bool ok;
	size_t i;

	/* Two characters per digit, and TS 31.101 clause 9.6 wants at least four. */
	if (data_len < 8 || data_len % 2)
		return false;

	if (data_len <= PIN_SIZE) {
		ss_profile_copy_hex(field, data, data_len);
		memset(&field[data_len], 'f', PIN_SIZE - data_len);
		return true;
	}

	if (data_len != 2 * PIN_SIZE)
		return false;

	/* The characters the value spells are what the record stores, so they have
	 * to be hex as well. */
	for (i = 0; i < PIN_SIZE; i++)
		unwrapped[i] = (char)ss_hex_to_uint8(&data[i * 2]);
	ok = ss_is_hex(unwrapped, PIN_SIZE);
	if (ok)
		ss_profile_copy_hex(field, unwrapped, PIN_SIZE);

	ss_utils_memzero(unwrapped, sizeof(unwrapped));
	return ok;
}

/** Hex to uint8 converter
 *  \param[in] hex a pointer to two hex digits, already checked with ss_is_hex()
 *  \returns converted uint8 value */
static uint8_t ss_hex_to_uint8(const char *hex)
{
	return (uint8_t)((hex[0] % 32 + 9) % 25 * 16 + (hex[1] % 32 + 9) % 25);
}
