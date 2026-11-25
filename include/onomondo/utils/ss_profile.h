/*
 * Copyright (c) 2024 Onomondo ApS. All rights reserved.
 *
 * SPDX-License-Identifier: GPL-3.0-only
 */

#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Field lengths in hex characters, as the profile string carries them. The
 * parser checks each record's LEN against these. */
#define IMSI_LEN 18
#define ICCID_LEN 20
#define KEY_SIZE 32
#define PIN_SIZE 16
#define SMSP_RECORD_SIZE 52
#define SMSP_LEN (SMSP_RECORD_SIZE * 2) /* EF.SMSP record 1 */
#define SMSC_LEN (12 * 2) /* EF.SMSP TS-Service Centre Address */
#define CRC32_LEN 8 /* a 4 byte CRC */

/* EF layout, in hex characters: where the provisioning writers put each field.
 * The binary writer halves every offset and length. */
#define A001_LEN 66 /* Ki | OPc | OP/OPc flag */
#define A001_KI_OFFSET 0
#define A001_OPC_OFFSET KEY_SIZE
#define A001_FLAG_OFFSET (2 * KEY_SIZE) /* "00": the key is an OPc, "01": an OP */
#define A003_LEN 132 /* PIN code file: 3 records of header | PIN | PUK */
#define A003_RECORD_SIZE (A003_LEN / 3)
/* Record header, as struct pin_context in uicc_pin.c: enabled | max_tries | tries |
 * max_unblock_tries | unblock_tries | pin_no */
#define A003_TRIES_OFFSET 4 /* failed PIN attempts */
#define A003_UNBLOCK_TRIES_OFFSET 8 /* failed PUK attempts */
#define PIN_OFFSET 12
#define PUK_OFFSET (PIN_OFFSET + PIN_SIZE)
#define A004_LEN 228 /* OTA keys: 3 records of header | KIC | KID */
#define A004_HEADER_SIZE 12
#define A004_KIC_OFFSET A004_HEADER_SIZE
#define A004_KID_OFFSET (A004_HEADER_SIZE + KEY_SIZE)
#define SMSC_OFFSET 74 /* TS-Service Centre Address inside an EF.SMSP record (TS 51.011) */

/* Decoded sizes in bytes, for the binary writer. Spelled the same as the platform
 * port spells them, so both can be in scope. */
#define ICCID_BIN_LEN (ICCID_LEN / 2)
#define IMSI_BIN_LEN (IMSI_LEN / 2)
#define A001_BIN_LEN (A001_LEN / 2)
#define A003_BIN_LEN (A003_LEN / 2)
#define A004_BIN_LEN (A004_LEN / 2)
#define KEY_BIN_LEN (KEY_SIZE / 2)
#define PIN_BIN_LEN (PIN_SIZE / 2)
#define SMSC_BIN_LEN (SMSC_LEN / 2)
#define SMSP_BIN_LEN (SMSP_LEN / 2)
#define A003_BIN_RECORD_SIZE (A003_BIN_LEN / 3)
#define PIN_BIN_OFFSET (PIN_OFFSET / 2)
#define PUK_BIN_OFFSET (PUK_OFFSET / 2)
#define A004_BIN_HEADER_SIZE (A004_HEADER_SIZE / 2)
#define A004_BIN_RECORD_SIZE (A004_BIN_HEADER_SIZE + 2 * KEY_BIN_LEN)
#define SMSC_BIN_OFFSET (SMSC_OFFSET / 2)

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

/* Bit for a field tag (IMSI_TAG..SMSC_TAG) in struct ss_profile.tags */
#define SS_TAG_BIT(tag) ((uint16_t)(1u << (tag)))

/* Records that describe the profile rather than carry a field live at the top of
 * the tag range: 0x01..0xef is profile data, 0xf0..0xff is structural. */
#define CRC32_TAG 0xFE
#define END_TAG 0xFF

/* Return values of ss_profile_from_string(). The numbers are fixed: callers log
 * them and tests check them (platform ports report 18 and 19 as a CRC failure). */
enum ss_profile_err {
	SS_PROFILE_OK = 0,
	SS_PROFILE_ERR_MALFORMED = 1, /* too short, a record runs past the end, or a CRC record covers nothing */
	SS_PROFILE_ERR_NOT_HEX = 3, /* a character that is not a hex digit */
	SS_PROFILE_ERR_IMSI = 10, /* IMSI record of the wrong length, or its length byte not 1..8 */
	SS_PROFILE_ERR_ICCID = 11, /* ICCID record of the wrong length */
	SS_PROFILE_ERR_OPC = 12, /* OPc record of the wrong length */
	SS_PROFILE_ERR_KI = 13, /* Ki record of the wrong length */
	SS_PROFILE_ERR_KIC = 14, /* KIC record of the wrong length */
	SS_PROFILE_ERR_KID = 15, /* KID record of the wrong length */
	SS_PROFILE_ERR_SMSP = 16, /* SMSP record of the wrong length */
	SS_PROFILE_ERR_SMSC = 17, /* SMSC record of the wrong length */
	SS_PROFILE_ERR_CRC_LEN = 18, /* CRC32 record of the wrong length */
	SS_PROFILE_ERR_CRC = 19, /* CRC32 does not match the profile */
	SS_PROFILE_ERR_PIN = 20, /* PIN, PUK or ADM value no PIN code file record can hold */
};

/* Onomondo SoftSIM Profile Struct
 *
 * One field per profile record, as lower case hex characters whatever case the
 * profile carried them in, the format of the EFs. A profile patches fields: the
 * provisioning writer puts each field the profile carried at its place in its EF
 * (see the EF layout above) and leaves everything else in the EF as it is. Which
 * fields were carried is in tags; ask with ss_profile_has_tag().
 *
 * A platform may edit the struct between decoding and writing, e.g. replace a key
 * with a reference to where it really lives. An edited field stays lower case hex
 * of the same length: the writer stores fields as they are, it does not convert. */
struct ss_profile {
	uint8_t iccid[ICCID_LEN]; /* EF.ICCID */
	uint8_t imsi[IMSI_LEN]; /* EF.IMSI */
	uint8_t ki[KEY_SIZE]; /* A001 */
	uint8_t opc[KEY_SIZE]; /* A001 */
	uint8_t kic[KEY_SIZE]; /* A004 record 1 */
	uint8_t kid[KEY_SIZE]; /* A004 record 1 */
	uint8_t smsp[SMSP_LEN]; /* EF.SMSP record 1 */
	uint8_t smsc[SMSC_LEN]; /* inside EF.SMSP record 1 */
	uint8_t pin1[PIN_SIZE]; /* A003 record 1, padded with 'f' */
	uint8_t pin2[PIN_SIZE]; /* A003 record 2 */
	uint8_t adm[PIN_SIZE]; /* A003 record 3 */
	uint8_t puk[PIN_SIZE]; /* A003 records 1 and 2 */
	uint16_t tags; /* which field tags the profile carried */
};

/* Onomondo SoftSIM Profile Decoder
 * --------------------------------------------------------
 * This function is used to decode a SoftSIM profile, as exported by
 * the Onomondo SoftSIM CLI tool.
 *
 * For future compatibility we use TLV encoding for the profile
 * I.e. TAG | LEN | DATA[LEN] || TAG | LEN | DATA[LEN] || TAG | LEN | DATA[LEN] || ...
 * TAG and LEN are two hex characters each, DATA is LEN hex characters.
 *
 * Maximum length of the tlv encoded hex string, in characters, with all 13 value
 * carrying records present (an END record would add 4 more):
 * Chars: Tag + Len + IMSI + ICCID + OPC + KIx  + SMSP + SMSC + PINx + PUK + CRC
 * Chars: 13x2 + 13x2 + 18  + 20   + 32  + 32x3 + 104  + 24   + 16x3 + 16  + 8   = 418
 *
 * An optional CRC32 record (CRC32_TAG) covers every character before it, so it has to be
 * the last record and cannot be the only one -- the CRC32 of nothing is 0x00000000, which
 * a lone record would spell and thereby certify an empty profile. A profile without the
 * record decodes as before; one carrying it is rejected if the CRC does not match.
 * Characters are ASCII-case-folded before they are covered, so a profile re-cased in
 * transit still matches its CRC. The record only guards what it covers: corruption that
 * removes the record itself -- its own tag flipping to END_TAG, or a truncation at a
 * record boundary -- leaves a profile that decodes cleanly unchecked. The record proves
 * integrity when present; its absence proves nothing. */

/** Parse an TLV encoded string and get back the decoded struct.
 *
 *  The decoder reports what the profile carries and does not judge whether that is
 *  enough to provision; see ss_profile_has_required_tags(). A field without a tag
 *  is left zeroed. A PIN, PUK or ADM value is stored as the 16 hex characters of
 *  its 8 byte record field.
 *
 *  \param[in] len the length of the profile string.
 *  \param[in] input_string a pointer to the input data source of the profile,
 *             at least len characters long.
 *  \param[out] profile a pointer to the receiving profile struct. On any error
 *              return it is cleared, so a partly decoded profile never leaves
 *              key material behind.
 *  \returns SS_PROFILE_OK, or an enum ss_profile_err value.
 */
uint8_t ss_profile_from_string(uint16_t len, const char *input_string, struct ss_profile *profile);

/** Whether the profile carried a record with this field tag (IMSI_TAG..SMSC_TAG). */
bool ss_profile_has_tag(const struct ss_profile *profile, uint8_t tag);

/** Whether the profile carried every tag provisioning requires: IMSI, ICCID, Ki
 *  and OPc. KIC and KID are optional OTA keys. */
bool ss_profile_has_required_tags(const struct ss_profile *profile);

/** Clear a decoded profile before its memory is released.
 *  ss_profile_from_string() already clears on error; call this once the profile
 *  has been consumed, so no key material outlives its use.
 *  \param[out] profile the profile to clear. */
void ss_profile_wipe(struct ss_profile *profile);

/** Compute the CRC32 a profile's CRC record must carry.
 *
 *  CRC-32/ISO-HDLC, as used by zlib: reflected polynomial 0xedb88320, initial and
 *  final inversion, computed over the ASCII-lowercased characters. Exposed so a
 *  tool that builds a profile can append the record the decoder expects.
 *
 *  \param[in] data the characters to cover, i.e. the profile up to the CRC record;
 *             case is folded internally.
 *  \param[in] len number of characters.
 *  \returns the CRC32 of data. */
uint32_t ss_profile_crc32(const char *data, size_t len);

#ifdef __cplusplus
}
#endif
