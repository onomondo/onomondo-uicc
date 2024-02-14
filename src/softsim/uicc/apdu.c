/*
 * Copyright (c) 2024 Onomondo ApS. All rights reserved.
 * 
 * SPDX-License-Identifier: GPL-3.0-only 
 */

#include <assert.h>
#include <string.h>
#include <onomondo/softsim/mem.h>
#include <onomondo/softsim/log.h>
#include "uicc_lchan.h"
#include "apdu.h"
#include "context.h"

/*! Create a new APDU struct for use with the softsim API.
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
		SS_LOGP(SLCHAN, LDEBUG, "freeing APDU %p (current), keeping APDU %p (last)\n", apdu, apdu->lchan->last_apdu);
		SS_FREE(apdu);
	} else {
		if (apdu->lchan->last_apdu)
			SS_FREE(apdu->lchan->last_apdu);
		SS_LOGP(SLCHAN, LDEBUG, "freeing APDU %p (last), keeping APDU %p (current)\n", apdu->lchan->last_apdu, apdu);
		apdu->lchan->last_apdu = apdu;
	}
}
