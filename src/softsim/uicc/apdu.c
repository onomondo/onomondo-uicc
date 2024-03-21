/*
 * Copyright (c) 2024 Onomondo ApS. All rights reserved.
 *
 * SPDX-License-Identifier: GPL-3.0-only
 */

#include <assert.h>
#include <string.h>
#include <onomondo/softsim/log.h>
#include <onomondo/softsim/mem.h>
#include <onomondo/softsim/utils.h>
#include "apdu.h"
#include "context.h"
#include "uicc_lchan.h"

#define P3 4
#define HEADER_SIZE 4

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
	/*! NOTE: By calling this function the APDU struct is not freed
	 *  immediately. It is kept for another cycle for internal
	 *  references. */

	/* NOTE: An APDU without lchan may occur when it was impossible to
	 * resolve a valid lchan. This may happen when a non existing lchan
	 * is addressed. */
	if (!apdu->lchan) {
		SS_LOGP(SLCHAN, LERROR, "tossing APDU without lchan\n");
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

/** This enables support for extended APDU cases.
 *  \param[in] apdu struct allocated by caller.
 *  \param[in] buffer with apdu request.
 *  \param[in] len bytes in buffer */
void ss_apdu_parse_exhaustive(struct ss_apdu *apdu, uint8_t *buffer, size_t len)
{
	assert(len >= HEADER_SIZE);
	// resulting apdu is collected in the end
	uint16_t le = 0, lc = 0, processed_bytes = 0;
	uint8_t *data_start = NULL;

	SS_LOGP(SAPDU, LDEBUG, "Parsing APDU %s\n", ss_hexdump(buffer, len));

	/* First 4 bytes are directly inserted to the header.
	 * This function will handle extended cases as well so p3 isn't directly used */
	memcpy(&(apdu->hdr), buffer, HEADER_SIZE);
	apdu->hdr.p3 = 0;
	processed_bytes = HEADER_SIZE;

	/* Case 1 Command: Header only.
	 * A C-APDU of {CLA INS P1 P2} is passed from the terminal to the UICC.
	 * https://www.etsi.org/deliver/etsi_ts/102200_102299/102221/13.02.00_60/ts_102221v130200p.pdf */
	if (len == HEADER_SIZE) {
		SS_LOGP(SAPDU, LDEBUG, "APDU is CASE 1 - header only\n");
		apdu->processed_bytes = HEADER_SIZE;
		return;
	}

	if (len == HEADER_SIZE + 1) {
		// Case 2 Command: Header + Le
		// [ CLA, INS, P1, P2, LE ]
		le = buffer[P3];
		le = le == 0 ? 256 : le;
		processed_bytes = len;

		SS_LOGP(SAPDU, LDEBUG, "APDU is CASE 2 - le=%d\n", le);
		goto out;
	}

	// Check for extended cases
	if (buffer[P3] == 0) {
		// Case 2 Command: Header + Le (extended case)
		// [ CLA, INS, P1, P2, 0, LE1, LE2 ]
		if (len == HEADER_SIZE + 3) {
			// parse next two bytes as length
			le = buffer[P3 + 1] << 8 | buffer[P3 + 2];
			le = le == 0 ? 65535 : le;

			processed_bytes = len;
			SS_LOGP(SAPDU, LDEBUG, "APDU is CASE 2 extended - le=%d\n", le);
			goto out;
		}

		// [ CLA, INS, P1, P2, 0, LC1, LC2 [REST] ]
		lc = buffer[P3 + 1] << 8 | buffer[P3 + 2];
		data_start = buffer + HEADER_SIZE + 3;

		if (len == HEADER_SIZE + 3 + lc) {
			// [ CLA, INS, P1, P2, 0, LC1, LC2 DATA[LC] ]
			le = 0;
			processed_bytes = len;
			SS_LOGP(SAPDU, LDEBUG, "Case 3 extended - lc %dd\n", lc);

			goto out;
		}

		/* Case 4 Command: HEADER + LC + DATA + LE. IF LC is extended then LE is also extended
		 * It __should__ always be same format - but we can't be sure that the call respects
		 * this at all times */
		uint8_t le_bytes = 0;
		le_bytes = len - (HEADER_SIZE + 3 + lc);

		switch (le_bytes) {
		case 1:
			le = buffer[len - 1];
			break;
		case 2:
		case 3:
			le = buffer[len - 2] << 8 | buffer[len - 1];
			break;
		default:
			// can't really recover well from this
			le = 0;
			SS_LOGP(SAPDU, LERROR, "APDU malformed. LE couldn't be derived. Len: %zu, lc: %d, apdu: %s\n",
				len, lc, ss_hexdump(buffer, len));
			break;
		}

		SS_LOGP(SAPDU, LDEBUG, "Case 4 extended  - lc %d, le %d \n", lc, le);

		processed_bytes = len;
		goto out;
	}

	lc = buffer[P3];
	data_start = buffer + HEADER_SIZE + 1;

	// Case 3 Command: HEADER + LC + DATA
	if (len == HEADER_SIZE + 1 + lc) {
		// [ CLA, INS, P1, P2, LC DATA[LC] ]
		le = 0;
		SS_LOGP(SAPDU, LDEBUG, "Case 3 -  lc %d\n", lc);
		processed_bytes = len;
		goto out;
	}

	// Case 4 Command: HEADER + LC + DATA + LE
	le = buffer[len - 1];
	le = le == 0 ? 65535 : le;
	SS_LOGP(SAPDU, LDEBUG, "Case 4:  lc %d, le %d \n", lc, le);
	apdu->hdr.p3 = lc;
	processed_bytes = HEADER_SIZE + 1 + lc + 1;
out:
	// lc is externally supplied so we can't trust it at all
	if (lc > len - HEADER_SIZE) {
		SS_LOGP(SAPDU, LERROR,
			"APDU malformed. LC is larger than the remaining buffer. Len: %zu, lc: %d, apdu: %s\n", len, lc,
			ss_hexdump(buffer, len));
		lc = 0;
		apdu->hdr.p3 = 0;
	}
	apdu->lc = lc;
	apdu->le = le;
	apdu->processed_bytes = processed_bytes;
	// copy data field if present
	if (lc && data_start) {
		memcpy(apdu->cmd, data_start, lc);
	}
}
