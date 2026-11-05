/*
 * Copyright (c) 2024 Onomondo ApS. All rights reserved.
 *
 * SPDX-License-Identifier: GPL-3.0-only
 */

#include <string.h>
#include <onomondo/softsim/log.h>
#include <onomondo/softsim/mem.h>
#include <onomondo/softsim/utils.h>
#include "apdu.h"
#include "context.h"
#include "uicc_lchan.h"

/* Index of the P3 byte: Le (Case 2), Lc (Case 3/4) or the 00 marker of an
 * extended length field */
#define P3 4

/* CLA INS P1 P2 P3: the header of a short-length command */
#define SHORT_HEADER_LEN (APDU_HEADER_SIZE + 1)

/* CLA INS P1 P2 00 Lx Lx: the header of an extended-length command, where 00
 * in the P3 slot announces a two-byte length field (ISO/IEC 7816-4 §5.1) */
#define EXT_HEADER_LEN (APDU_HEADER_SIZE + 3)

/*! Create a new APDU struct for use with the SoftSIM API.
 *  \returns pointer to allocated APDU struct, NULL on allocation failure. */
struct ss_apdu *ss_apdu_new(struct ss_context *ctx)
{
	struct ss_apdu *apdu;
	apdu = SS_ALLOC(struct ss_apdu);
	memset(apdu, 0, sizeof(*apdu));
	apdu->ctx = ctx;
	SS_LOGP(SLCHAN, LDEBUG, "allocating APDU %p\n", apdu);
	return apdu;
}

/*! Toss APDU that is no longer needed by the API user.
 *  \param[in] apdu to toss. */
void ss_apdu_toss(struct ss_apdu *apdu)
{
	/*! NOTE: The APDU struct is either freed here or parked as
	 *  lchan->last_apdu for one more cycle. The caller must not touch
	 *  the pointer after this call. */

	/* NOTE: An APDU without lchan may occur when it was impossible to
	 * resolve a valid lchan. This may happen when a non existing lchan
	 * is addressed. Nothing can reference it later -- GET RESPONSE reaches
	 * the previous APDU through lchan->last_apdu -- so free it now instead
	 * of keeping it for another cycle. */
	if (!apdu->lchan) {
		SS_LOGP(SLCHAN, LDEBUG, "tossing APDU %p without lchan\n", apdu);
		SS_FREE(apdu);
		return;
	}

	/* free any previous last_apdu we might still be keeping. If we decide
	 * to keep the last apdu, then we free the current APDU instead.
	 *
	 * Note that if there is ever anything more to freeing the old APDU, this
	 * also needs to be extended in ss_lchan_reset, which is the other place
	 * where an APDU is freed. */

	if (apdu->lchan->last_apdu_keep) {
		SS_LOGP(SLCHAN, LDEBUG, "freeing APDU %p (current), keeping APDU %p (last)\n", apdu,
			apdu->lchan->last_apdu);
		SS_FREE(apdu);
	} else {
		if (apdu->lchan->last_apdu)
			SS_FREE(apdu->lchan->last_apdu);
		SS_LOGP(SLCHAN, LDEBUG, "freeing APDU %p (last), keeping APDU %p (current)\n", apdu->lchan->last_apdu,
			apdu);
		apdu->lchan->last_apdu = apdu;
	}
}

/* Body of a short-length command: P3 is Lc, optionally followed by a one-byte
 * Le. Sets lc, le, processed_bytes and, for Case 4, hdr.p3.
 * \returns start of the data field. */
static const uint8_t *parse_short_body(struct ss_apdu *apdu, const uint8_t *buffer, size_t len)
{
	uint16_t lc = buffer[P3];
	uint16_t le;

	if (len == SHORT_HEADER_LEN + lc) {
		/* Case 3 Command: HEADER + LC + DATA
		 * [ CLA, INS, P1, P2, LC DATA[LC] ] */
		le = 0;
		SS_LOGP(SAPDU, LDEBUG, "Case 3 -  lc %d\n", lc);
		apdu->processed_bytes = len;
	} else {
		/* Case 4 Command: HEADER + LC + DATA + LE */
		le = buffer[len - 1];
		le = le == 0 ? 256 : le;
		SS_LOGP(SAPDU, LDEBUG, "Case 4:  lc %d, le %d \n", lc, le);
		apdu->hdr.p3 = lc;
		apdu->processed_bytes = SHORT_HEADER_LEN + lc + 1;
	}

	apdu->lc = lc;
	apdu->le = le;
	return buffer + SHORT_HEADER_LEN;
}

/* Body of an extended-length command: the 00 in the P3 slot is followed by a
 * two-byte Le (Case 2) or a two-byte Lc (Case 3/4). Sets lc, le,
 * processed_bytes and malformed.
 * \returns start of the data field, NULL when the command has none. */
static const uint8_t *parse_extended_body(struct ss_apdu *apdu, const uint8_t *buffer, size_t len)
{
	uint16_t lc, le;
	uint8_t le_bytes;

	if (len == EXT_HEADER_LEN) {
		/* Case 2 Command: Header + Le (extended case)
		 * [ CLA, INS, P1, P2, 0, LE1, LE2 ]
		 * parse next two bytes as length */
		le = buffer[P3 + 1] << 8 | buffer[P3 + 2];
		le = le == 0 ? 65535 : le;
		apdu->lc = 0;
		apdu->le = le;
		apdu->processed_bytes = len;
		SS_LOGP(SAPDU, LDEBUG, "APDU is CASE 2 extended - le=%d\n", le);
		return NULL;
	}

	/* P3 == 0 promises two length bytes; here the second one is missing. */
	if (len < EXT_HEADER_LEN) {
		SS_LOGP(SAPDU, LERROR, "APDU malformed. Extended length field truncated. Len: %u, apdu: %s\n",
			(unsigned int)len, ss_hexdump(buffer, len));
		apdu->lc = 0;
		apdu->le = 0;
		apdu->processed_bytes = len;
		apdu->malformed = true;
		return NULL;
	}

	/* [ CLA, INS, P1, P2, 0, LC1, LC2 [REST] ] */
	lc = buffer[P3 + 1] << 8 | buffer[P3 + 2];

	if (len == EXT_HEADER_LEN + lc) {
		/* Case 3 Command: [ CLA, INS, P1, P2, 0, LC1, LC2 DATA[LC] ] */
		le = 0;
		SS_LOGP(SAPDU, LDEBUG, "Case 3 extended - lc %d\n", lc);
	} else {
		/* Case 4 Command: HEADER + LC + DATA + LE. IF LC is extended then LE is also extended
		 * It __should__ always be same format - but we can't be sure that the call respects
		 * this at all times */
		le_bytes = len - (EXT_HEADER_LEN + lc);

		switch (le_bytes) {
		case 1:
			le = buffer[len - 1];
			break;
		case 2:
		case 3:
			le = buffer[len - 2] << 8 | buffer[len - 1];
			break;
		default:
			/* can't really recover well from this */
			le = 0;
			SS_LOGP(SAPDU, LERROR, "APDU malformed. LE couldn't be derived. Len: %zu, lc: %d, apdu: %s\n",
				len, lc, ss_hexdump(buffer, len));
			apdu->malformed = true;
			break;
		}

		SS_LOGP(SAPDU, LDEBUG, "Case 4 extended  - lc %d, le %d \n", lc, le);
	}

	apdu->lc = lc;
	apdu->le = le;
	apdu->processed_bytes = len;
	return buffer + EXT_HEADER_LEN;
}

/** Parse an APDU's wire format into apdu->hdr, apdu->lc, apdu->le, apdu->cmd and
 *  apdu->processed_bytes, and set apdu->malformed on inconsistent length fields.
 *  Handles the four ISO/IEC 7816-4 §5.1 command cases in their short and extended
 *  length forms (Case 1; Case 2/3/4 short; Case 2/3/4 extended).
 *  \param[in] apdu struct allocated by caller.
 *  \param[in] buffer with apdu request.
 *  \param[in] len bytes in buffer */
void ss_apdu_parse_exhaustive(struct ss_apdu *apdu, uint8_t *buffer, size_t len)
{
	const uint8_t *data_start;

	/* Not an assert: -DNDEBUG would strip it, and the header memcpy below
	 * reads APDU_HEADER_SIZE bytes from a caller-supplied buffer. */
	if (len < APDU_HEADER_SIZE) {
		SS_LOGP(SAPDU, LERROR, "APDU malformed. Shorter than the header. Len: %u\n", (unsigned int)len);
		apdu->lc = 0;
		apdu->le = 0;
		apdu->processed_bytes = 0;
		apdu->malformed = true;
		return;
	}

	SS_LOGP(SAPDU, LDEBUG, "Parsing APDU %s\n", ss_hexdump(buffer, len));

	/* First 4 bytes are directly inserted to the header.
	 * This function will handle extended cases as well so p3 isn't directly used */
	memcpy(&(apdu->hdr), buffer, APDU_HEADER_SIZE);
	apdu->hdr.p3 = 0;

	/* Case 1 Command: Header only.
	 * A C-APDU of {CLA INS P1 P2} is passed from the terminal to the UICC
	 * (TS 102 221 table 10.2). */
	if (len == APDU_HEADER_SIZE) {
		SS_LOGP(SAPDU, LDEBUG, "APDU is CASE 1 - header only\n");
		apdu->processed_bytes = APDU_HEADER_SIZE;
		return;
	}

	/* Case 2 Command: Header + Le
	 * [ CLA, INS, P1, P2, LE ]
	 * Tested before the extended-length marker below: a five-byte APDU with
	 * P3 = 00 is a short Case 2 asking for 256 bytes, not an extended header
	 * cut short after its 00 marker. */
	if (len == SHORT_HEADER_LEN) {
		uint16_t le = buffer[P3];

		apdu->lc = 0;
		apdu->le = le == 0 ? 256 : le;
		apdu->processed_bytes = len;
		SS_LOGP(SAPDU, LDEBUG, "APDU is CASE 2 - le=%d\n", apdu->le);
		return;
	}

	/* 00 in the P3 slot announces two-byte length fields (ISO/IEC 7816-4 §5.1) */
	if (buffer[P3] == 0)
		data_start = parse_extended_body(apdu, buffer, len);
	else
		data_start = parse_short_body(apdu, buffer, len);

	/* extended Case 2 or a truncated length field: no data field to check or copy */
	if (!data_start)
		return;

	/* lc is externally supplied so we can't trust it at all. It must fit both
	 * the bytes that follow data_start and apdu->cmd, which bound the memcpy
	 * below. */
	if (apdu->lc) {
		size_t available = len - (size_t)(data_start - buffer);

		if (apdu->lc > available || apdu->lc > sizeof(apdu->cmd)) {
			SS_LOGP(SAPDU, LERROR,
				"APDU malformed. LC is larger than the remaining buffer. Len: %u, lc: %d, apdu: %s\n",
				(unsigned int)len, apdu->lc, ss_hexdump(buffer, len));
			apdu->lc = 0;
			apdu->hdr.p3 = 0;
			/* the count derived from the untrusted Lc is equally untrusted */
			apdu->processed_bytes = len;
			apdu->malformed = true;
		}
	}

	/* copy data field if present */
	if (apdu->lc)
		memcpy(apdu->cmd, data_start, apdu->lc);
}
