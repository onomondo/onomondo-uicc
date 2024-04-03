/*
 * Copyright (c) 2024 Onomondo ApS. All rights reserved.
 *
 * SPDX-License-Identifier: GPL-3.0-only
 */

#pragma once

#include <stdint.h>

#define IMSI_LEN 18
#define A001_LEN 66
#define A003_LEN 132
#define A004_LEN 228
#define ICCID_LEN 20
#define KEY_SIZE 32
#define PIN_SIZE 16
#define PIN_OFFSET 12
#define PUK_OFFSET (PIN_OFFSET + PIN_SIZE)
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
#define END_TAG 0xFF

// Onomondo SoftSIM Profile Struct
struct ss_profile {
	uint8_t _3F00_2FE2[ICCID_LEN];
	uint8_t _3F00_7ff0_6f07[IMSI_LEN];
	uint8_t _3F00_A001[A001_LEN];
	uint8_t _3F00_A004[A004_LEN];
	uint8_t _3F00_A003[A003_LEN];
	uint8_t SMSP[SMSP_RECORD_SIZE];
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
 * Maximum string length of AT command tlv encoded hex string, when containing all tags
 * Byte count: Tag  + Len  + IMSI + ICCID + OPC + KIx  + SMSP + PINx + PUK
 * Byte count: 11x2 + 11x2 + 18   + 20    + 32  + 32x3 + 52   + 16x3 + 16 = 326 bytes */

/** Parse an TLV encoded string and get back the decoded struct.
 *  This decoder is made specifically to fit the Onomondo SoftSIM
 *  CLI tools decrypted output format.
 *  
 *  \param[in] input_string a pointer to the input data source of the profile.
 *  \param[in] len the length of the profile string.
 *  \param[in] profile a pointer to the receiving profile struct.
 *  \returns return 0 if valid profile is decoded. error code otherwise.
 */
uint8_t ss_profile_from_string(uint16_t len, const char input_string[len], struct ss_profile *profile);
