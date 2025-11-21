/*
 * Copyright (c) 2024 Onomondo ApS. All rights reserved.
 *
 * SPDX-License-Identifier: GPL-3.0-only
 * 
 * Author: Onomondo ApS
 */

#include <string.h>
#include "onomondo/utils/ss_profile.h"

static uint8_t ss_hex_to_uint8(const char *hex);
static void ss_hex_string_to_bytes(const uint8_t *hex, size_t hex_len, uint8_t bytes[hex_len / 2]);

uint8_t ss_profile_from_string(uint16_t len, const char input_string[len], struct ss_profile *profile)
{
	/* Stucture (a004): [TAR[3] | MSL | KIC_IND | KID_IND | KIC[32] | KID[32] | */
	static const char a004_header[] = "b00011060101";
	const size_t A004_RECORD_SIZE = A004_HEADER_SIZE + KEY_SIZE + KEY_SIZE;
	/* set the default header values */
	memcpy(&profile->_3F00_A004, a004_header, sizeof(a004_header) - 1);
	/* and fill the rest of the record with "f" */
	memset(&profile->_3F00_A004[A004_RECORD_SIZE], 'f', A004_LEN - A004_RECORD_SIZE);

	/* Structure (a003): */
	static const char a003_default[] = "0003000a000131323334ffffffff31323334353637380003000a008131323334ffffff"
						"ff313233343536373801030000000a31323334ffffffff3132333435363738";
	memcpy(profile->_3F00_A003, a003_default, sizeof(a003_default) - 1);

	size_t pos = 0, data_end = 0, data_start = 0, next_pos = 0;
	uint8_t tag = 0, data_len = 0;

	while (pos < len - 2) {
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
			if (data_len > PIN_SIZE)
				break;
			memcpy(&profile->_3F00_A003[0 * A003_RECORD_SIZE + PIN_OFFSET], &input_string[data_start],
			       data_len);
			break;
		case PIN_2_TAG:
			if (data_len > PIN_SIZE)
				break;
			memcpy(&profile->_3F00_A003[1 * A003_RECORD_SIZE + PIN_OFFSET], &input_string[data_start],
			       data_len);
			break;
		case PIN_ADM_TAG:
			if (data_len > PIN_SIZE)
				break;
			memcpy(&profile->_3F00_A003[2 * A003_RECORD_SIZE + PIN_OFFSET], &input_string[data_start],
			       data_len);
			break;
		case PUK_TAG:
			if (data_len > PIN_SIZE)
				break;
			memcpy(&profile->_3F00_A003[0 * A003_RECORD_SIZE + PUK_OFFSET], &input_string[data_start],
			       data_len);
			memcpy(&profile->_3F00_A003[1 * A003_RECORD_SIZE + PUK_OFFSET], &input_string[data_start],
			       data_len);
			break;
		case END_TAG:
			/* end of profile */
			next_pos = len;
			break;
		default:
			/* unknown tag, skip (next_pos already points to the right location) */
			break;
		}

		/* move the parser to the next position after handling the tag */
		pos = next_pos;
	}

	profile->_3F00_A001[KEY_SIZE + KEY_SIZE] = '0';
	profile->_3F00_A001[KEY_SIZE + KEY_SIZE + 1] = '0';

	return 0;
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
 *  \param[inout] bytes the byte array to store the result in */
static void ss_hex_string_to_bytes(const uint8_t *hex, size_t hex_len, uint8_t bytes[hex_len / 2])
{
	int i;

	for (i = 0; i < hex_len / 2; i++) {
		bytes[i] = ss_hex_to_uint8((char *)&hex[i * 2]);
	}
}
