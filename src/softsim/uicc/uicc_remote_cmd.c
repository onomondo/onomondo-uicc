/*
 * Copyright (c) 2024 Onomondo ApS. All rights reserved.
 *
 * SPDX-License-Identifier: GPL-3.0-only
 */

#include "uicc_remote_cmd.h"

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <errno.h>

#include <onomondo/softsim/file.h>
#include <onomondo/softsim/log.h>
#include <onomondo/softsim/softsim.h>
#include <onomondo/softsim/crypto.h>

#include "context.h"
#include "fcp.h"
#include "fs.h"
#include "sw.h"
#include "uicc_pin.h"
#include "utils.h"
#include "utils_3des.h"
#include "utils_ota.h"

/* Information element identifier for command packets, as used in TS 23.048
 * V5.9.0 Seciton 6.2 */
#define IEI_RPI 0x71

/* File containing TARs and their keys
 *
 * Format: (22 bytes per record)
 * +----------+--------+---------+---------+---------+---------+
 * |  3 byte  | 1 byte | 1 byte  | 1 byte  | 16 byte | 16 byte |
 * |   TAR    |   MSL  | KIC ind | KID ind |   KIC   |   KID   |
 * +----------+--------+---------+---------+---------+---------+
 *
 * Records are read iteratively until the MSL could be checked, and KIC and KID
 * were popualated as needed. A record matches a KIC / KID indicator if either
 * the request's indicator is 0 (indicating that it's implicitly clear, ie.
 * taking any record) or they are equal.
 *
 * If KIC and KIDs are not provided pair-wise, or (which is not recommended)
 * unencrypted communication is allowed and no keys are present, then the
 * record's indications can say 0xff, which never matches any request's
 * indications.
 *
 * All MSLs associated with a TAR need to be identical (this is not checked in
 * the code, and more a matter of defensive style). */
#define TAR_KEY_FID 0xA004
#define TAR_CNTR_FID 0xA005

#define TAR_LEN 3
#define CNTR_LEN 5
#define PCNT_LEN 1
#define RSC_LEN 1

struct tar_record {
	uint8_t tar[TAR_LEN];
	uint8_t msl;
	uint8_t kic_indication;
	uint8_t kid_indication;
	uint8_t kic[OTA_KEY_LEN];
	uint8_t kid[OTA_KEY_LEN];
} __attribute__((packed));

struct cntr_record {
	uint8_t tar[TAR_LEN];
	uint8_t tar_mask[TAR_LEN];
	uint8_t cntr[CNTR_LEN];
} __attribute__((packed));

/* TS 23.048 V5.9.0 Section 5.2 */
#define RSC_POR_OK 0x00
/* TS 131.115 V12.1.0 Section 7 */
#define RSC_WILL_SMS_SUBMIT 0x0b

/* Arbitrary limit for response sizes: "The limitation of 256 bytes does not
 * apply for the length of the response data." */
#define SS_UICC_REMOTE_COMMAND_RESPONSE_MAXSIZE 4096

/* See also ETSI TS 102 225, section 5.1.1 */
enum cntr_mgmnt {
	/* No counter available
	 * (the message contains the field, but it is ignored.) */
	CNTR_IGNORE = 0,

	/* Set the start value of the RE counter to the counter value from the
	 * SE (propritary) */
	CNTR_SET_START = 1,

	/* Check whether the counter value from the SE is greater than the
	 * counter in the RE, If so, top up the counter in the RE, so that it
	 * matches the counter value from the SE and increment it by one. */
	CNTR_CHECK_GREATER = 2,

	/* Check whether the counter value from the SE is one higher than the
	 * counter in the RE. If so, increment RE counter by one. */
	CNTR_CHECK_STRICT = 3,
};

/** Properties extracted from the header of a command packet */
struct command_parameters {
	/* Is the integrity protected by a cryptographic checksum? */
	bool in_cc;
	/* Is the request integrity protection CC? */
	bool in_ciphering;
	size_t in_integrity_len;

	/* Should the response be encrypted? */
	bool out_ciphering;
	/* Is the response integrity protection CC? */
	bool out_cc;
	size_t out_integrity_len;

	/* Encryption Keys (if any integrity / ciphering is set) */
	uint8_t kic_indication;
	uint8_t kid_indication;

	/* Encryption Algorithm (if any integrity / ciphering is set) */
	enum enc_algorithm kic_algorithm;
	enum enc_algorithm kid_algorithm;

	/* The TAR (Toolkit Application Reference) */
	uint8_t tar[3];

	/* Replay detection and Sequence Integrity counter. */
	uint64_t cntr;
	enum cntr_mgmnt cntr_mgmnt;

	/* Number of padding octets at the end of the message */
	uint8_t pcntr;

	/* ETSI TS 131 115, section 4.1, b6 of SPI2:
	 * 0: PoR via SMS-DELIVER-REPORT
	 * 1: PoR via SMS-SUBMIT */
	bool out_por_via_sms_submit;
};

/* Parse the clear text part of the command packet header
 * (until and including tar). This function returns the length of the consumed
 * header bytes or a suitable SW as error code (negative) */
static int parse_cmd_hdr_clrtxt(struct command_parameters *param, size_t cmd_packet_len, const uint8_t *cmd_packet)
{
	/* CPL, CHL, SPI, KIc, KID, TAR */
	const size_t minimal_length = 2 + 1 + 2 + 1 + 1 + 3;
	if (cmd_packet_len <= minimal_length || (((size_t)cmd_packet[0] << 8) | cmd_packet[1]) != cmd_packet_len - 2) {
		SS_LOGP(SREMOTECMD, LERROR, "Received comand packet too short\n");
		/* Is there any better guidance? This is only based on general ISO 7816
		 * ENVELOPE descriptions. */
		return SS_SW_ERR_CHECKING_WRONG_LENGTH;
	}

	SS_LOGP(SREMOTECMD, LDEBUG, "command packet header data (cleartext): %s\n", ss_hexdump(cmd_packet, 10));

	/* Interpreting incoming message */
	uint8_t chl = cmd_packet[2];
	uint8_t spi1 = cmd_packet[3];
	uint8_t spi2 = cmd_packet[4];
	uint8_t kic = cmd_packet[5];
	uint8_t kid = cmd_packet[6];

	SS_LOGP(SREMOTECMD, LDEBUG, "Received command with CHL %02x, SPI %02x %02x, KIc %02x, KID %02x\n", chl, spi1,
		spi2, kic, kid);

	if (chl < 4) {
		/* Checking this after the DEBUG line because the access were all
		 * memory-valid, just not semantically valid within the command header, but
		 * the above should still be helpful in fixing that. */
		SS_LOGP(SREMOTECMD, LERROR, "CHL too short\n");
		return -SS_SW_ERR_CHECKING_WRONG_LENGTH;
	}

	/* NOTE: for a SPI format see also ETSI TS 102 225, section 5.1.1 */

	/* Masking to ignore reserved bits and bits that control the counter
	 * options (see also below) */
	switch (spi1 & 0x07) {
	case 0x00:
		param->in_cc = false;
		param->in_ciphering = false;
		param->in_integrity_len = 0;
		break;
	case 0x06:
		param->in_cc = true;
		param->in_ciphering = true;
		param->in_integrity_len = OTA_INTEGRITY_LEN;
		break;
	default:
		SS_LOGP(SREMOTECMD, LERROR, "Unsupported SPI1\n");
		/* Is that the correct error code? It's what SJA2 returns. */
		return -SS_SW_WARN_NO_INFO_NV_UNCHANGED;
	}

	/* Parse counter options (see also enum cntr_mgmnt) */
	param->cntr_mgmnt = (spi1 >> 3) & 0x03;

	if ((spi2 & 0x03) != 0x01) {
		SS_LOGP(SREMOTECMD, LERROR, "SPI2 supported values are limited to \"PoR required\"\n");
		return -SS_SW_WARN_NO_INFO_NV_UNCHANGED;
	}
	param->out_ciphering = spi2 & 0x10;
	switch (spi2 & 0x0c) {
	case 0x00:
		param->out_cc = false;
		param->out_integrity_len = 0;
		break;
	case 0x08:
		param->out_cc = true;
		param->out_integrity_len = OTA_INTEGRITY_LEN;
		break;
	default:
		SS_LOGP(SREMOTECMD, LERROR, "Unsupported SPI2 integrity mode\n");
		return -SS_SW_WARN_NO_INFO_NV_UNCHANGED;
	}

	param->out_por_via_sms_submit = (spi2 & 0x20) >> 5;

	if (chl !=
	    2 /* SPI */ + 1 /* KIc */ + 1 /* KID */ + TAR_LEN + CNTR_LEN + 1 /* PCNTR */ + param->in_integrity_len) {
		SS_LOGP(SREMOTECMD, LERROR, "CHL does not match expected integrity length\n");
		return -SS_SW_WARN_NO_INFO_NV_UNCHANGED;
	}

	/* Parse KIC/KID algorithm and indication */
	param->kic_indication = kic >> 4;
	param->kid_indication = kid >> 4;
	if (param->in_ciphering || param->out_ciphering) {
		switch (kic & 0x0F) {
		case 0x05:
			param->kic_algorithm = TRIPLE_DES_CBC2;
			break;
		case 0x02:
			param->kic_algorithm = AES_CBC;
			break;
		default:
			SS_LOGP(SREMOTECMD, LERROR, "Key KIc uses unsupported algorithm / key setup\n");
			return -SS_SW_WARN_NO_INFO_NV_UNCHANGED;
		}
		switch (kid & 0x0F) {
		case 0x05:
			param->kid_algorithm = TRIPLE_DES_CBC2;
			break;
		case 0x02:
			param->kid_algorithm = AES_CMAC;
			break;
		default:
			SS_LOGP(SREMOTECMD, LERROR, "Key KID uses unsupported algorithm / key setup\n");
			return -SS_SW_WARN_NO_INFO_NV_UNCHANGED;
		}
	} else {
		param->kic_algorithm = NONE;
		param->kid_algorithm = NONE;
	}

	memcpy(param->tar, &cmd_packet[7], TAR_LEN);

	SS_LOGP(SREMOTECMD, LDEBUG, "command parameters (cleartext):\n");
	SS_LOGP(SREMOTECMD, LDEBUG, "  cryptographic checksum (in): %s\n", param->in_cc ? "yes" : "no");
	SS_LOGP(SREMOTECMD, LDEBUG, "  cryptographic checksum (out): %s\n", param->out_cc ? "yes" : "no");
	SS_LOGP(SREMOTECMD, LDEBUG, "  chiphering (in): %s\n", param->in_ciphering ? "yes" : "no");
	SS_LOGP(SREMOTECMD, LDEBUG, "  chiphering (out): %s\n", param->out_ciphering ? "yes" : "no");
	SS_LOGP(SREMOTECMD, LDEBUG, "  integrity parameter len (in): %zu\n", param->in_integrity_len);
	SS_LOGP(SREMOTECMD, LDEBUG, "  integrity parameter len (out): %zu\n", param->out_integrity_len);
	SS_LOGP(SREMOTECMD, LDEBUG, "  KIC indication: %02x\n", param->kic_indication);
	SS_LOGP(SREMOTECMD, LDEBUG, "  KID indication: %02x\n", param->kid_indication);
	switch (param->kic_algorithm) {
	case NONE:
		SS_LOGP(SREMOTECMD, LDEBUG, "  KIC algorithm: NONE\n");
		break;
	case TRIPLE_DES_CBC2:
		SS_LOGP(SREMOTECMD, LDEBUG, "  KIC algorithm: 3DES CBC2\n");
		break;
	case AES_CBC:
		SS_LOGP(SREMOTECMD, LDEBUG, "  KIC algorithm: AES CBC\n");
		break;
	case AES_CMAC:
		SS_LOGP(SREMOTECMD, LDEBUG, "  KIC algorithm: AES CMAC\n");
		break;
	default:
		SS_LOGP(SREMOTECMD, LERROR, "  KIC algorithm: invalid\n");
		return -SS_SW_WARN_NO_INFO_NV_UNCHANGED;
	}
	switch (param->kid_algorithm) {
	case NONE:
		SS_LOGP(SREMOTECMD, LDEBUG, "  KID algorithm: NONE\n");
		break;
	case TRIPLE_DES_CBC2:
		SS_LOGP(SREMOTECMD, LDEBUG, "  KID algorithm: 3DES CBC2\n");
		break;
	case AES_CBC:
		SS_LOGP(SREMOTECMD, LDEBUG, "  KID algorithm: AES CBC\n");
		break;
	case AES_CMAC:
		SS_LOGP(SREMOTECMD, LDEBUG, "  KID algorithm: AES CMAC\n");
		break;
	default:
		SS_LOGP(SREMOTECMD, LERROR, "  KID algorithm: invalid\n");
		return -SS_SW_WARN_NO_INFO_NV_UNCHANGED;
	}
	SS_LOGP(SREMOTECMD, LDEBUG, "  TAR: %s\n", ss_hexdump(param->tar, sizeof(param->tar)));
	switch (param->cntr_mgmnt) {
	case CNTR_IGNORE:
		SS_LOGP(SREMOTECMD, LDEBUG, "  cntr mgmnt: ignore\n");
		break;
	case CNTR_SET_START:
		SS_LOGP(SREMOTECMD, LDEBUG, "  cntr mgmnt: set start value\n");
		break;
	case CNTR_CHECK_GREATER:
		SS_LOGP(SREMOTECMD, LDEBUG, "  cntr mgmnt: match greater\n");
		break;
	case CNTR_CHECK_STRICT:
		SS_LOGP(SREMOTECMD, LDEBUG, "  cntr mgmnt: match greater one (strict)\n");
		break;
	default:
		SS_LOGP(SREMOTECMD, LERROR, "  cntr mgmnt: invalid\n");
		return -SS_SW_WARN_NO_INFO_NV_UNCHANGED;
	}

	return 10;
}

/* Parse the cipher text part (after decryption) of the command packet header
 * This function returns the length of the consumed header bytes or a suitable
 * SW as error code (negative). The input data must start at the beginning of
 * the CNTR value. */
static int parse_cmd_hdr_ciphtxt(struct command_parameters *param, size_t cmd_packet_len, const uint8_t *cmd_packet)
{
	SS_LOGP(SREMOTECMD, LDEBUG, "command packet header data (decrypted ciphertext): %s\n",
		ss_hexdump(cmd_packet, 6));

	/* We need at least 6 bytes of data (5 byte CNTR + 1 byte PCNTR) */
	if (cmd_packet_len < 6) {
		SS_LOGP(SREMOTECMD, LERROR, "message too short\n");
		return -SS_SW_ERR_CHECKING_WRONG_LENGTH;
	}

	param->cntr = ss_uint64_from_array(&cmd_packet[0], CNTR_LEN);
	param->pcntr = cmd_packet[5];

	SS_LOGP(SREMOTECMD, LDEBUG, "command parameters (decrypted cleartext):\n");
	SS_LOGP(SREMOTECMD, LDEBUG, "  CNTR: %lu/%010lx\n", param->cntr, param->cntr);
	SS_LOGP(SREMOTECMD, LDEBUG, "  PCNTR: %u/%02x\n", param->pcntr, param->pcntr);

	return 6;
}

/* Given a TAR for which credentials have been accepted, configure a context as
 * required by that TAR's description.
 *
 * Reference: TS 102 226 V8.2.0 Section 7.3 and TS 101 220 V8.4.0 Annex D
 *
 * This typically involves two steps:
 * - Selecting the relevant ADF that should be pre-selected before commands are
 *   executed in this TAR. This should follow the Annex D tabulated TARs to the
 *   extent implemented.
 * - Setting the relevant PINs (CHVs) to be given, so that access control can
 *   be applied. The precise codes to be set might yet be configured; ADM1 is
 *   the default permission level associated with TARs per this implementer's
 *   choice. */
static void setup_ctx_from_tar(struct ss_context *ctx, uint8_t *tar)
{
	/* Values from TS 101 221 Annex D. When extending, take care not to use any
	 * TARs that imply extended data format unless that is implemented and
	 * signalled to the decoder. */

	if (tar[0] == 0xb0 && tar[1] == 0x00 && (tar[2] & 0xf0) == 0x10) {
		/* b0 00 10 to b0 00 1f: SIM File system */
		/* SELECT ADF.USIM */
		ss_fs_select(&ctx->lchan.fs_path, 0x7ff0);
	} else {
		/* Add else-if chains as more are implemented. For what is currently
		 * available (UICC Shared File System), the default of keeping the MF
		 * selected is fine. */
	}

	/* Unconditional default until the need for further customization arises */
	ctx->lchan.pin_verfied[SS_PIN_ADM1] = true;
}

/* Given a TAR and key IDs, provide key material.
 *
 * This populates kic and kid as necessitated by param.
 *
 * It returns true if all requested data has been populated, and the request
 * matches the TAR's MSL.
 *
 * The precise evaluation logic is part of the file description provided with
 * @ref TAR_KEY_FID. */
static bool setup_keys_from_tar(struct command_parameters *param, uint8_t *kic, uint8_t *kid)
{
	struct ss_list tar_path;
	struct ss_buf *tar_buf;
	struct ss_file *tar_file = NULL;
	size_t n_tars;
	bool checked_msl = false;
	bool ready_kic = !(param->in_ciphering || param->out_ciphering);
	bool ready_kid = !(param->in_cc || param->out_cc);
	struct tar_record *record;
	int rc;
	int i;

	ss_fs_init(&tar_path);
	rc = ss_fs_select(&tar_path, TAR_KEY_FID);
	if (rc < 0) {
		SS_LOGP(SREMOTECMD, LERROR, "TAR file not selectable\n");
		goto exit;
	}
	tar_file = ss_get_file_from_path(&tar_path);
	if (tar_file == NULL) {
		SS_LOGP(SREMOTECMD, LERROR, "TAR file not available\n");
		goto exit;
	}
	n_tars = tar_file->fcp_file_descr->number_of_records;
	for (i = 0; i < n_tars && !(checked_msl && ready_kic && ready_kid); i++) {
		tar_buf = ss_fs_read_file_record(&tar_path, i + 1);
		if (!tar_buf) {
			SS_LOGP(SREMOTECMD, LERROR, "TAR file inconsistent -- cannot read record\n");
			goto exit;
		}
		if (tar_buf->len != sizeof(struct tar_record)) {
			SS_LOGP(SREMOTECMD, LERROR, "TAR file has wrong record length\n");
			i = n_tars; /* goto exit but leave through cleanup */
			goto continue_;
		}

		/* Cast OK: Struct is packed, and none of its fields have alignment
		 * requirements */
		record = (struct tar_record *)tar_buf->data;

		if (memcmp(&record->tar, param->tar, TAR_LEN) != 0)
			goto continue_;

		if (!checked_msl) {
			/* TS 102 226 V9.4.0 Section 8.2.1.3.2.4.2 describes that check in more
			 * detail, but a full implementation is considered too error prone given
			 * that only two (really, one -- unencrypted is not recommended) values
			 * make sense */
			switch (record->msl) {
			case 0x00:
				SS_LOGP(SREMOTECMD, LINFO, "Accepting SPI1 based on permissive MSL\n");
				checked_msl = true;
				break;
			case 0x06:
				if (!param->in_cc || !param->in_ciphering) {
					SS_LOGP(SREMOTECMD, LERROR, "Request SPI1 does not satisfy MSL\n");
					i = n_tars; /* goto exit but leave through cleanup */
					goto continue_;
				} else {
					SS_LOGP(SREMOTECMD, LINFO,
						"Accepting SPI1 as it is encrypted and cryptographically checksummed\n");
					checked_msl = true;
				}
				break;
			default:
				SS_LOGP(SREMOTECMD, LERROR, "Unsupported MSL, rejecting\n");
				i = n_tars; /* goto exit but leave through cleanup */
				goto continue_;
			}
		}

		if (!ready_kic && record->kic_indication != 0xff &&
		    (record->kic_indication == param->kic_indication || param->kic_indication == 0)) {
			memcpy(kic, record->kic, OTA_KEY_LEN);
			ready_kic = true;
		}

		if (!ready_kid && record->kid_indication != 0xff &&
		    (record->kid_indication == param->kid_indication || param->kid_indication == 0)) {
			memcpy(kid, record->kid, OTA_KEY_LEN);
			ready_kid = true;
		}

continue_:
		ss_memzero(tar_buf->data, tar_buf->len);
		ss_buf_free(tar_buf);
	}

exit:
	ss_path_reset(&tar_path);
	SS_LOGP(SREMOTECMD, LINFO, "Key selection result: MSL check %d, KIC readiness %d, KID readiness %d\n",
		checked_msl, ready_kic, ready_kid);
	return checked_msl && ready_kic && ready_kid;
}

/* Get the current CNTR value for a specified TAR (param). The record number of
 * the matching record is also returned to directly update the record later. */
static int get_cntr_from_tar(uint64_t *cntr, size_t *record_no, struct command_parameters *param)
{
	struct ss_list cntr_path;
	struct ss_buf *cntr_buf;
	struct ss_file *cntr_file = NULL;
	int rc_select;
	size_t n_cntrs;
	unsigned int i;
	unsigned int k;
	bool tar_match = false;
	int rc = 0;

	*cntr = 0xffffffffff;
	*record_no = 0;

	ss_fs_init(&cntr_path);
	rc_select = ss_fs_select(&cntr_path, TAR_CNTR_FID);
	if (rc_select < 0) {
		SS_LOGP(SREMOTECMD, LERROR, "CNTR file not selectable\n");
		rc = -EINVAL;
		goto exit;
	}
	cntr_file = ss_get_file_from_path(&cntr_path);
	if (cntr_file == NULL) {
		SS_LOGP(SREMOTECMD, LERROR, "CNTR file not available\n");
		rc = -EINVAL;
		goto exit;
	}
	n_cntrs = cntr_file->fcp_file_descr->number_of_records;

	for (i = 0; i < n_cntrs; i++) {
		cntr_buf = ss_fs_read_file_record(&cntr_path, i + 1);
		if (!cntr_buf) {
			SS_LOGP(SREMOTECMD, LERROR, "CNTR file inconsistent -- cannot read record\n");
			rc = -EINVAL;
			goto exit;
		}
		if (cntr_buf->len != sizeof(struct cntr_record)) {
			SS_LOGP(SREMOTECMD, LERROR, "CNTR file has wrong record length\n");
			i = n_cntrs; /* goto exit but leave through cleanup */
			ss_buf_free(cntr_buf);
			rc = -EINVAL;
			goto exit;
		}

		/* Cast OK: Struct is packed, and none of its fields have alignment
		 * requirements */
		struct cntr_record *record = (struct cntr_record *)cntr_buf->data;

		tar_match = true;
		for (k = 0; k < TAR_LEN; k++) {
			if ((record->tar[k] & record->tar_mask[k]) != (param->tar[k] & record->tar_mask[k]))
				tar_match = false;
		}

		if (tar_match) {
			*cntr = ss_uint64_from_array(record->cntr, CNTR_LEN);
			*record_no = i + 1;
			SS_LOGP(SREMOTECMD, LINFO,
				"CNTR selection result: record %zu, TAR %s, TAR mask %s, CNTR %lu/%010lx\n", *record_no,
				ss_hexdump(record->tar, sizeof(record->tar)),
				ss_hexdump(record->tar_mask, sizeof(record->tar_mask)), *cntr, *cntr);
			ss_buf_free(cntr_buf);
			break;
		}
		ss_buf_free(cntr_buf);
	}

	if (!tar_match) {
		SS_LOGP(SREMOTECMD, LERROR, "CNTR file does not contain record for TAR %s\n",
			ss_hexdump(param->tar, sizeof(param->tar)));
		rc = -EINVAL;
	}

exit:
	ss_path_reset(&cntr_path);
	return rc;
}

/* Updata a counter value at a specified record, use record number returned
 * by get_cntr_from_tar(), which should be called earlier. */
static int update_cntr(uint64_t cntr, size_t record_no)
{
	struct ss_list cntr_path;
	struct ss_buf *cntr_buf = NULL;
	struct ss_file *cntr_file = NULL;
	struct cntr_record *record;
	int rc = 0;

	ss_fs_init(&cntr_path);
	rc = ss_fs_select(&cntr_path, TAR_CNTR_FID);
	if (rc < 0) {
		SS_LOGP(SREMOTECMD, LERROR, "CNTR file not selectable\n");
		rc = -EINVAL;
		goto exit;
	}
	cntr_file = ss_get_file_from_path(&cntr_path);
	if (cntr_file == NULL) {
		SS_LOGP(SREMOTECMD, LERROR, "CNTR file not available\n");
		rc = -EINVAL;
		goto exit;
	}

	cntr_buf = ss_fs_read_file_record(&cntr_path, record_no);
	if (!cntr_buf) {
		SS_LOGP(SREMOTECMD, LERROR, "CNTR file inconsistent -- cannot read record\n");
		rc = -EINVAL;
		goto exit;
	}
	if (cntr_buf->len != sizeof(struct cntr_record)) {
		SS_LOGP(SREMOTECMD, LERROR, "CNTR file has wrong record length\n");
		rc = -EINVAL;
		goto exit;
	}

	/* Cast OK: Struct is packed, and none of its fields have alignment
	 * requirements */
	record = (struct cntr_record *)cntr_buf->data;
	ss_array_from_uint64(record->cntr, CNTR_LEN, cntr);

	SS_LOGP(SREMOTECMD, LINFO, "CNTR update: record %zu, CNTR %lu/%010lx\n", record_no, cntr, cntr);

	rc = ss_fs_write_file_record(&cntr_path, record_no, cntr_buf->data, cntr_buf->len);
exit:
	ss_buf_free(cntr_buf);
	ss_path_reset(&cntr_path);
	return rc;
}

/* Process decrypted commands
 *
 * @param[in] tar TAR that identifies the application, guides context setup and
 *                encodes the virtual terminal's authorizations
 * @param[in] commands_len Number of bytes in @p commands
 * @param[in] commands Commands encoded in Remote APDU format (TS 102 226 V9.4.0 Seciton 5.1)
 * @param[in] outbuf_len Usable space inside @p outbuf.
 * @param[out] outbuf Buffer into which the response is written.
 *
 * @return The number of bytes written to the @pb outbuf.
 *
 * While most of the error handling relevant for this happens internally (if
 * anything goes wrong, it'll just return the index of the failed command and
 * an unsuccessful SW), allocation errors before comand processing result in a
 * return value of 0 (which is otherwise invalid, as the result encoding
 * demands at least 1 byte for the command index, and 2 bytes of SW) */
static size_t process_commands(uint8_t *tar, size_t commands_len, uint8_t *commands, size_t outbuf_len, uint8_t *outbuf,
			       uint8_t *main_ctx_filelist)
{
	size_t this_command_length;
	struct ss_context *ctx = ss_new_reporting_ctx(main_ctx_filelist);
	size_t written_length = 0;

	if (ctx == NULL)
		return 0;
	SS_LOGP(SREMOTECMD, LDEBUG, "+++++++++++++ command processing on RFM context begins ++++++++++++++\n");

	ss_reset(ctx);

	setup_ctx_from_tar(ctx, tar);

	/* Number of commands executed within the script */
	outbuf[0] = 0;

	while (commands_len >= 4) {
		/* Count number of executed commands */
		outbuf[0]++;

		SS_LOGP(SREMOTECMD, LDEBUG, "Processing command %d: %s\n", outbuf[0],
			ss_hexdump(commands, commands_len));
		this_command_length = commands_len;

		/* Note: the compact APDU format used with RFM stores the SW at
		 * the beginning. But ss_transact() will store the SW at the
		 * end. We will use an offset in order to be able to put the
		 * SW at the beginning after the command excution. */
		written_length = ss_transact(ctx, &outbuf[3], outbuf_len - 3, commands, &this_command_length);
		outbuf[1] = outbuf[1 + written_length];
		outbuf[2] = outbuf[2 + written_length];
		SS_LOGP(SREMOTECMD, LDEBUG, "Command %d produced %ld bytes of output: %s\n", outbuf[0], written_length,
			ss_hexdump(&outbuf[1], written_length));

		/* Align to the beginning of the next command. */
		commands_len -= this_command_length;
		commands += this_command_length;

		/* Abort in case the command was not executed successfully. */
		if (!ss_sw_is_successful((outbuf[1] << 8) | outbuf[2])) {
			SS_LOGP(SREMOTECMD, LINFO,
				"Command %d was not successful, not executing any further commands\n", outbuf[0]);
			break;
		}
	}
	if (commands_len != 0) {
		SS_LOGP(SREMOTECMD, LERROR,
			"%lu bytes left after last remote command; can not express error to remote (and might be OK after unsuccessful command).\n",
			commands_len);
	}

	SS_LOGP(SREMOTECMD, LDEBUG, "+++++++++++++ command processing on RFM context ended +++++++++++++++\n");
	ss_free_ctx(ctx);

	return written_length + 1;
}

/* Decrypt data using a specified algorithm. */
static int decrypt(uint8_t *data, size_t data_len, uint8_t *key, size_t key_len, enum enc_algorithm alg)
{
	switch (alg) {
	case TRIPLE_DES_CBC2:
		assert(key_len == TRIPLE_DES_KEYLEN);
		if (data_len % DES_BLOCKSIZE != 0) {
			SS_LOGP(SREMOTECMD, LERROR,
				"cannot decrypt, ciphertext length (%zu) must be a multiple of %u (padding error)\n",
				data_len, DES_BLOCKSIZE);
			return -EINVAL;
		}
		ss_utils_3des_decrypt(data, data_len, key);
		break;
	case AES_CBC:
		if (data_len % AES_BLOCKSIZE != 0) {
			SS_LOGP(SREMOTECMD, LERROR,
				"cannot decrypt, ciphertext length (%zu) must be a multiple of %u (padding error)\n",
				data_len, AES_BLOCKSIZE);
			return -EINVAL;
		}
		ss_utils_aes_decrypt(data, data_len, key, key_len);
		break;
	default:
		SS_LOGP(SREMOTECMD, LERROR, "unable to decrypt, improper crypto algorithm selected\n");
		return -EINVAL;
	}

	return 0;
}

/* Encrypt data using a specified algorithm. */
static int encrypt(uint8_t *data, size_t data_len, uint8_t *key, size_t key_len, enum enc_algorithm alg)
{
	switch (alg) {
	case TRIPLE_DES_CBC2:
		assert(key_len == TRIPLE_DES_KEYLEN);
		if (data_len % DES_BLOCKSIZE != 0) {
			SS_LOGP(SREMOTECMD, LERROR,
				"cannot encrypt, ciphertext length (%zu) must be a multiple of %u (padding error)\n",
				data_len, DES_BLOCKSIZE);
			return -EINVAL;
		}
		ss_utils_3des_encrypt(data, data_len, key);
		break;
	case AES_CBC:
		if (data_len % AES_BLOCKSIZE != 0) {
			SS_LOGP(SREMOTECMD, LERROR,
				"cannot encrypt, ciphertext length (%zu) must be a multiple of %u (padding error)\n",
				data_len, AES_BLOCKSIZE);
			return -EINVAL;
		}
		ss_utils_aes_encrypt(data, data_len, key, key_len);
		break;
	default:
		SS_LOGP(SREMOTECMD, LERROR, "unable to decrypt, improper crypto algorithm selected\n");
		return -EINVAL;
	}

	return 0;
}

/**
 * Build, (usually) encrypt and integrity-protect a whole OTA message whose
 * plaintext has already been put in place
 *
 * The plaintext needs to be placed already at the right offset inside the
 * buffer.
 *
 * @param[inout] outbuf_len Size of @p outbuf. After the function has returned,
 *                          this is lowered to the length of data that is now
 *                          initialized in the buffer, and constitutes the
 *                          message.
 * @param[inout] outbuf     Output buffer. The parts of it that contain the
 *                          plaintext must already be initialized by the
 *                          caller.
 * @param[in]    plaintext_len Size of @p plaintext
 * @param[in]    plaintext  Buffer inside @p outbuf where the plaintext has
 *                          been placed by the caller. These argument's
 *                          correctness is assert()ed by this function..
 * @param[in]    rsc        Response Status Code to place in the encrypted part
 *                          of the header
 * @param[in]    param      Request parameters
 * @param[in]    kic_key    Key KIC (for encryption)
 * @param[in]    kid_key    Key KID (for integrity protection)
 * @param[in]    cntr       Counter value (CNTR) to place in the encrypted part
 *                          of the header
 */
static void build_message(uint8_t *outbuf, size_t *outbuf_len, uint8_t *plaintext, size_t plaintext_len, uint8_t rsc,
			  struct command_parameters *param, uint8_t *kic_key, uint8_t *kid_key, uint8_t *cntr)
{
	uint8_t cc[OTA_INTEGRITY_LEN];
	uint8_t pcnt = 0;
	int rc;
	size_t outbuf_len_orig = *outbuf_len;

	/* NOTE: when this function is called, *outbuf will already contain
	 * data that is decorated and encrypted to a valid response packet. */

	if (plaintext_len != 0) {
		/* On gross violations by the caller this would be UB, but it
		 * should detect the usual things that'd go wrong if one piece
		 * of the code started implementing variations that the other
		 * didn't account for */
		assert(&plaintext[plaintext_len] <= &outbuf[*outbuf_len]);
		assert(plaintext == &outbuf[16 + param->out_integrity_len]);
	}

	/* Calculate PCNT and apply padding at the correct location in the
	 * output buffer. */
	if (param->out_ciphering) {
		/* The padding counter PCNT refers to the padding that is
		 * required to encrypt the message properly. It does not refer
		 * to the calculation of the cryptographic checksum (the CC
		 * calculation applies a suitable padding internally). The
		 * encrypted part of the message starts at the location of
		 * the sequence counter (CNTR). */
		pcnt = ss_utils_ota_calc_pcnt(param->kic_algorithm,
					      CNTR_LEN + PCNT_LEN + RSC_LEN + param->out_integrity_len + plaintext_len);
	};
	if (pcnt > 0) {
		switch (param->kic_algorithm) {
		case AES_CBC:
			/* NIST Special Publication 800-38A states that the padding for the AES should be 0x80 0x00 ... 0x00 */
			outbuf[16 + param->out_integrity_len + plaintext_len] = 0x80;
			memset(&outbuf[16 + param->out_integrity_len + plaintext_len + 1], 0, pcnt - 1);
			break;
		case TRIPLE_DES_CBC2:
			memset(&outbuf[16 + param->out_integrity_len + plaintext_len], 0, pcnt);
		default:
			break;
		}
	};

	/* We don't have a shrinking realloc, but this is still a convenient
	 * place to store this length */
	*outbuf_len = 16 + param->out_integrity_len + plaintext_len + pcnt;

	/* User Data Header */
	outbuf[0] = 0x02;    /* UDHL */
	outbuf[1] = IEI_RPI; /* IEIa: Response Packet Identifier */
	outbuf[2] = 0;	     /* IEIDLa, length of IEa data */
	/* Length of Response Packet */
	outbuf[3] = (*outbuf_len - 5) >> 8;
	outbuf[4] = (*outbuf_len - 5);
	/* RHL, Response Header length; TAR, integrity, CNTR, PCNT, response status code */
	outbuf[5] = 10 + param->out_integrity_len;
	/* TAR */
	memcpy(&outbuf[6], &param->tar, sizeof(param->tar));
	/* CNTR */
	memcpy(&outbuf[9], cntr, CNTR_LEN);
	outbuf[14] = pcnt;
	/* Response Status Code */
	outbuf[15] = rsc;

	/* outbuf[16 + ...]@plaintext_len was populated already */

	if (param->out_cc) {
		/* "In order to achieve a modulo 8/16 length of the data before the
		 * RC/CC/DS field in the Response Header, the Length of the Response
		 * Packet, the Length of the Response Header and the three preceding
		 * octets (UDHL, IEIa and IEIDLa in the above table) shall be
		 * included in the calculation of RC/CC/DS if used." */
		rc = ss_utils_ota_calc_cc(cc, param->out_integrity_len, kid_key, OTA_KEY_LEN, param->kid_algorithm,
					  outbuf, 16, &outbuf[16 + param->out_integrity_len], plaintext_len + pcnt);
		if (rc < 0) {
			/* Clear output buffer before we leave, just to be sure no
			 * unencrypted data will leak. */
			memset(outbuf, 0, outbuf_len_orig);
			*outbuf_len = 0;
			return;
		}
		memcpy(&outbuf[16], cc, param->out_integrity_len);
	}

	/* all set up for encryption */

	if (param->out_ciphering) {
		/* Encrypt everything after TAR */
		rc = encrypt(&outbuf[9], *outbuf_len - 9, kic_key, OTA_KEY_LEN, param->kic_algorithm);
		if (rc < 0) {
			/* Clear output buffer before we leave, just to be sure no
			 * unencrypted data will leak. */
			memset(outbuf, 0, outbuf_len_orig);
			*outbuf_len = 0;
			return;
		}
	}
}

/* Process a Command Packet (which is an SMS TPDU) and return a Response Packet
 * (also an SMS TPDU) in the response buffer.
 *
 * @param[in]     cmd_packet_len    Length of @p cmd_packet
 * @param[in]     cmd_packet        Input command; the UD (without header) of
 *                                  an SMS with an IEI_CPI header.
 * @param[inout]  response_len      Length of the @p response buffer. The
 *                                  function decreases the pointed value to the
 *                                  actually populated length.
 * @param[out]    response          Buffer for the SMS response (a message
 *                                  implicitly flagged to contain a UDH) that
 *                                  should be returned to the message the
 *                                  command packet arrived in.
 * @param[out]    sms_response      Place at which a response message can be
 *                                  deposited; that message is returned by the
 *                                  caller in a response SMS that the caller is
 *                                  responsible to set up as indicating the
 *                                  presence of a UDH.
 *
 * @return the status word with which to respond to the SMS delivery that sent
 *         the command packet. */
int ss_uicc_remote_cmd_receive(size_t cmd_packet_len, uint8_t *cmd_packet, size_t *response_len, uint8_t *response,
			       struct ss_buf **sms_response, uint8_t *main_ctx_filelist)
{
	struct command_parameters param;
	int ret;
	uint8_t kic_key[OTA_KEY_LEN];
	uint8_t kid_key[OTA_KEY_LEN];
	uint8_t *ciphertext;
	size_t ciphertext_len;
	uint8_t *plaintext;
	size_t plaintext_len;
	uint8_t *request_cc;
	uint8_t compare_cc[OTA_INTEGRITY_LEN];
	struct ss_buf *response_message;
	size_t command_output_length;
	size_t ciph_hdr_len;
	uint64_t cntr;
	size_t cntr_rec_no;
	int rc;

	/* Decode cleartext part of the command packet header */
	ret = parse_cmd_hdr_clrtxt(&param, cmd_packet_len, cmd_packet);
	if (ret <= 0)
		return -ret;

	/* Decrypt the encrypted part of the command packet. This includes
	 * the remaining encrypted header bytes and the secured payload data */
	if (setup_keys_from_tar(&param, kic_key, kid_key) == false)
		return SS_SW_WARN_NO_INFO_NV_UNCHANGED;
	ciphertext = &cmd_packet[ret];
	ciphertext_len = cmd_packet_len - ret;
	SS_LOGP(SREMOTECMD, LDEBUG, "Ciphertext command: %s\n", ss_hexdump(ciphertext, ciphertext_len));
	if (param.in_ciphering) {
		rc = decrypt(ciphertext, ciphertext_len, kic_key, sizeof(kic_key), param.kic_algorithm);
		if (rc < 0) {
			ret = SS_SW_WARN_NO_INFO_NV_UNCHANGED;
			goto clear_out;
		}
	}
	plaintext = ciphertext;
	plaintext_len = ciphertext_len;
	SS_LOGP(SREMOTECMD, LDEBUG, "Plaintext command: %s\n", ss_hexdump(plaintext, plaintext_len));

	ret = parse_cmd_hdr_ciphtxt(&param, plaintext_len, plaintext);
	if (ret <= 0)
		return -ret;
	ciph_hdr_len = ret;

	/* Guard against invalid length params */
	if (ciph_hdr_len + param.pcntr + param.in_integrity_len > plaintext_len) {
		SS_LOGP(SREMOTECMD, LERROR, "one or more inconsistent length params/fields received.\n");
		ret = SS_SW_WARN_NO_INFO_NV_UNCHANGED;
		goto clear_out;
	}

	/* The header is now completely in param, and can be split off */
	plaintext += ciph_hdr_len;
	plaintext_len -= ciph_hdr_len;

	/* Calculate and verify the cryptographic checksum (if requested) */
	if (param.in_cc) {
		request_cc = plaintext;
		/* ... and splitting it out: */
		plaintext += param.in_integrity_len;
		plaintext_len -= param.in_integrity_len;

		/* At this point, cmd_packet contains precisely what is needed
		 * to go with a non-buffering checksum: 2 bytes of CPL (not
		 * that we'd read it in any other place, currently), CHL, 2
		 * bytes of SPI, KIC, KID, TAR, CNTR and PCNTR. */
		rc = ss_utils_ota_calc_cc(compare_cc, param.in_integrity_len, kid_key, OTA_KEY_LEN, param.kid_algorithm,
					  cmd_packet, 16, plaintext, plaintext_len);
		if (rc < 0) {
			ret = SS_SW_WARN_NO_INFO_NV_UNCHANGED;
			goto clear_out;
		}
		if (memcmp(request_cc, compare_cc, param.in_integrity_len) != 0) {
			SS_LOGP(SREMOTECMD, LERROR,
				"CC error, message was signed with: %s, local calculation result is: %s\n",
				ss_hexdump(request_cc, param.in_integrity_len),
				ss_hexdump(compare_cc, param.in_integrity_len));
			ret = SS_SW_WARN_NO_INFO_NV_UNCHANGED;
			goto clear_out;
		}
	}

	/* Execute counter management logic (see also enum cntr_mgmnt) */
	rc = get_cntr_from_tar(&cntr, &cntr_rec_no, &param);
	if (rc < 0) {
		ret = SS_SW_WARN_NO_INFO_NV_UNCHANGED;
		goto clear_out;
	}

	switch (param.cntr_mgmnt) {
	case CNTR_IGNORE:
		SS_LOGP(SREMOTECMD, LDEBUG, "No counter checks performed, counter ignored\n");
		break;
	case CNTR_SET_START:
		/* Make sure the counter cannot be overset. */
		if (param.cntr >= 0xffffffffff)
			cntr = 0xffffffffff;
		else
			cntr = param.cntr;
		SS_LOGP(SREMOTECMD, LDEBUG, "No counter checks performed, counter set to: %lu\n", cntr);
		break;
	case CNTR_CHECK_GREATER:
		/* Detect blocked counter */
		if (cntr >= 0xffffffffff) {
			SS_LOGP(SREMOTECMD, LDEBUG, "Counter has reached its maximum value, blocked!\n");
			ret = SS_SW_WARN_NO_INFO_NV_UNCHANGED;
			goto clear_out;
		}

		/* Verify counter condition: must be greater than stored
		 * counter value */
		if (param.cntr <= cntr) {
			SS_LOGP(SREMOTECMD, LDEBUG,
				"Received counter value %lu not greater than stored counter value %lu\n", param.cntr,
				cntr);
			ret = SS_SW_WARN_NO_INFO_NV_UNCHANGED;
			goto clear_out;
		}
		cntr = param.cntr;
		SS_LOGP(SREMOTECMD, LDEBUG,
			"Received counter value %lu greater than stored counter value, counter incremented to: %lu\n",
			param.cntr, cntr);
		break;
	case CNTR_CHECK_STRICT:
		/* Detect blocked counter */
		if (cntr >= 0xffffffffff) {
			SS_LOGP(SREMOTECMD, LDEBUG, "Counter has reached its maximum value, blocked!\n");
			ret = SS_SW_WARN_NO_INFO_NV_UNCHANGED;
			goto clear_out;
		}

		/* Verify counter condition: must be exactly greater one than
		 * stored counter value */
		if (param.cntr != cntr + 1) {
			SS_LOGP(SREMOTECMD, LDEBUG,
				"Received counter value %lu not greater by one than stored counter value %lu\n",
				param.cntr, cntr);
			ret = SS_SW_WARN_NO_INFO_NV_UNCHANGED;
			goto clear_out;
		}
		cntr = param.cntr;
		SS_LOGP(SREMOTECMD, LDEBUG,
			"Received counter value %lu greater by one than stored counter value, counter incremented to: %lu\n",
			param.cntr, cntr);
		break;
	default:
		SS_LOGP(SREMOTECMD, LERROR, "Invalid counter options requested\n");
		ret = SS_SW_WARN_NO_INFO_NV_UNCHANGED;
		goto clear_out;
	}

	rc = update_cntr(cntr, cntr_rec_no);
	if (rc < 0) {
		ret = SS_SW_WARN_NO_INFO_NV_UNCHANGED;
		goto clear_out;
	}

	/* NOTE: At this point the remote command message is decrypted and
	 * and verfied (cryptographic checksum). We now begin with the active
	 * execution of the remote command. */

	/* Allocate memory for the response. */
	response_message = ss_buf_alloc(SS_UICC_REMOTE_COMMAND_RESPONSE_MAXSIZE);
	if (response_message == NULL) {
		SS_LOGP(SREMOTECMD, LERROR, "No space to allocate response message\n");
		ret = SS_SW_ERR_EXEC_MEMORY_PROBLEM;
		goto clear_out;
	}

	/* Execute the command string as RFM (remote file management)
	 * commands. */
	command_output_length = process_commands(param.tar, plaintext_len - param.pcntr, plaintext,
						 response_message->len - (16 + param.out_integrity_len),
						 &response_message->data[16 + param.out_integrity_len],
						 main_ctx_filelist);
	if (command_output_length == 0) {
		SS_LOGP(SREMOTECMD, LERROR, "Command processing encountered internal allocation error\n");
		ret = SS_SW_ERR_EXEC_MEMORY_PROBLEM;
		ss_buf_free(response_message);
		goto clear_out;
	}

	/* NOTE: the response is encrypted just the same, no matter whether it
	 * is encrypted to be sent in the confirmation or in a separate SMS, so
	 * we can encrypt the large part either way, and later decide where it
	 * goes. (we will either just copy the buffer once more or give the
	 * caller the ownership.) */
	build_message(response_message->data, &response_message->len,
		      &response_message->data[16 + param.out_integrity_len], command_output_length, RSC_POR_OK, &param,
		      kic_key, kid_key, &cmd_packet[10]);

	/* Return response message to the caller */
	if (response_message->len <= *response_len && !param.out_por_via_sms_submit) {
		/* The response fits in the GET RESPONSE buffer of the UICC,
		 * the MS will take care of the SMS sending. */
		memcpy(response, response_message->data, response_message->len);
		SS_LOGP(SREMOTECMD, LERROR, "------------ setresponse len %ld\n", response_message->len);
		*response_len = response_message->len;
		ss_buf_free(response_message);
	} else {
		/* The response is to large to fit in the GET RESPONSE buffer
		 * of the UICC. The UICC (caller) will have to generate one
		 * or more SM himself and send them through STK commands. */
		SS_LOGP(SREMOTECMD, LDEBUG, "Response too large for reply, will submit SMS instead.\n");

		*sms_response = response_message;

		build_message(response, response_len, NULL, 0, RSC_WILL_SMS_SUBMIT, &param, kic_key, kid_key,
			      &cmd_packet[10]);
	}
	ret = 0;

clear_out:
	ss_memzero(kic_key, sizeof(kic_key));
	ss_memzero(kid_key, sizeof(kid_key));
	return ret;
}
