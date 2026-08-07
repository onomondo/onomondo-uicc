/*
 * Copyright (c) 2024 Onomondo ApS. All rights reserved.
 *
 * SPDX-License-Identifier: GPL-3.0-only
 */

#pragma once

#include <stddef.h>
#include <stdint.h>

#define IMSI_LEN 18
#define CRC32_LEN 8 /* a 4 byte CRC as hex characters */
#define A001_LEN 66
#define A003_LEN 132
#define A004_LEN 228
#define ICCID_LEN 20
#define KEY_SIZE 32
#define PIN_SIZE 16
#define PIN_OFFSET 12
#define PUK_OFFSET (PIN_OFFSET + PIN_SIZE)
#define SMSC_LEN (12 * 2) /* EF.SMSP TS-Service Centre Address */
#define SMSP_RECORD_SIZE 52
#define A003_RECORD_SIZE (A003_LEN / 3)
#define A004_HEADER_SIZE 12

#define IMSI_TAG 0x01
#define ICCID_TAG 0x02
#define OPC_TAG 0x03
#define KI_TAG 0x04
#define KIC_TAG 0x05
#define KID_TAG 0x06
#define SMSP_TAG 0x07
#define PIN_1_TAG 0x08
#define PIN_2_TAG 0x09
#define PIN_ADM_TAG 0x0a
#define PUK_TAG 0x0b
#define SMSC_TAG 0x0c

/* Records that describe the profile rather than carry a field live at the top of
 * the tag range: 0x01..0xef is profile data, 0xf0..0xff is structural. */
#define CRC32_TAG 0xFE
#define END_TAG 0xFF

// Onomondo SoftSIM Profile Struct
struct ss_profile {
	uint8_t _3F00_2FE2[ICCID_LEN];
	uint8_t _3F00_7ff0_6f07[IMSI_LEN];
	uint8_t _3F00_A001[A001_LEN];
	uint8_t _3F00_A004[A004_LEN];
	uint8_t _3F00_A003[A003_LEN];
	uint8_t SMSP[SMSP_RECORD_SIZE * 2]; /* stored as hex characters in the profile (2 chars per byte) */
	uint8_t SMSC[SMSC_LEN];
	uint8_t k[16];
	uint8_t kid[16];
	uint8_t kic[16];
};

/* Onomondo SoftSIM Profile Decoder
 * --------------------------------------------------------
 * This function is used to decode a SoftSIM profile, as exported by
 * the Onomondo SoftSIM CLI tool.
 *
 * For future compatibility we use TLV encoding for the profile
 * I.e. TAG | LEN | DATA[LEN] || TAG | LEN | DATA[LEN] || TAG | LEN | DATA[LEN] || ...
 *
 * Maximum length of the tlv encoded hex string, in characters, with all 13 value
 * carrying records present (an END record would add 4 more):
 * Chars: Tag + Len + IMSI + ICCID + OPC + KIx  + SMSP + SMSC + PINx + PUK + CRC
 * Chars: 13x2 + 13x2 + 18  + 20   + 32  + 32x3 + 104  + 24   + 16x3 + 16  + 8   = 418
 *
 * An optional CRC32 record (CRC32_TAG) covers every character before it, so it has to be
 * the last record and cannot be the only one -- the CRC32 of nothing is 0x00000000, which
 * a lone record would spell and thereby certify an empty profile. A profile without the
 * record decodes as before; one carrying it is rejected if the CRC does not match. The
 * characters are covered as they arrive, so a profile whose hex is re-cased in transit no
 * longer matches its own CRC. */

/** Parse an TLV encoded string and get back the decoded struct.
 *  This decoder is made specifically to fit the Onomondo SoftSIM
 *  CLI tools decrypted output format.
 *  
 *  \param[in] len the length of the profile string.
 *  \param[in] input_string a pointer to the input data source of the profile,
 *             at least len characters long.
 *  \param[out] profile a pointer to the receiving profile struct. On any error
 *              return it is cleared, so a partly decoded profile never leaves
 *              key material behind.
 *  \returns return 0 if valid profile is decoded. error code otherwise: 1 for a
 *  malformed blob, 10..17 for a tag of the wrong length, 18 for a CRC record of
 *  the wrong length and 19 for a CRC that does not match the profile.
 */
uint8_t ss_profile_from_string(uint16_t len, const char *input_string, struct ss_profile *profile);

/** Compute the CRC32 a profile's CRC record must carry.
 *
 *  CRC-32/ISO-HDLC, as used by zlib: reflected polynomial 0xedb88320, initial and
 *  final inversion. Exposed so a tool that builds a profile can append the record
 *  the decoder expects.
 *
 *  \param[in] data the characters to cover, i.e. the profile up to the CRC record.
 *  \param[in] len number of characters.
 *  \returns the CRC32 of data. */
uint32_t ss_profile_crc32(const char *data, size_t len);
