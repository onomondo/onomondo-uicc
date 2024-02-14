/*
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * 3GPP AKA - SIM side validation as per TS 33.102
 * Author: Harald Welte <hwelte@sysmocom.de>
 *
 * The hostap milenage.c code doesn't really work for the "USIM side",
 * as it doesn't implement Annex C of 3GPP TS 33.102.  So we don't use
 * milenage_check() from there, but the code from here.
 * 
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#pragma once

#include "crypto/common.h"

/* Length of the IND bits (lower bits of SQN)
 *
 * The value of 5 is constant across all the profiles in TS 133 102 V16.0.0
 * Appendix C.3
 * */
#define MILENAGE_IND_LEN	5

struct milenage_key_data {
	u8 k[16];			/* Secret key K */
	u8 opc[16];			/* OPc or OP value */
	int opc_is_op;			/* does opc store OPc or OP? */
};

/* As described in TS 133 102 V16.0.0 Appendix C.2 */
struct milenage_seq_data {
	uint64_t seq[(1 << MILENAGE_IND_LEN)];	/* array of SEQ_MS indexed by IND */
	uint64_t delta;			/* limit "delta" as per 33.102. Typically configured to 2**28 */
};

struct milenage_result {
	u8 ik[16];
	u8 ck[16];
	u8 res[8];
	u8 res_len;
	u8 auts[14];
};

int milenage_usim_check(const struct milenage_key_data *kd,
			struct milenage_seq_data *sd,
			struct milenage_result *mr,
			const u8 *_rand, const u8 *autn);
