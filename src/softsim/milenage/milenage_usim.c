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

#include "crypto/includes.h"
#include "crypto/common.h"
#include "uicc/utils.h"

#include "milenage.h"
#include "milenage_usim.h"

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))
#endif

#define MILENAGE_IND_MASK	((1<<MILENAGE_IND_LEN)-1)

static u64 get_highest_seq_ms(const struct milenage_seq_data *sd)
{
	u64 highest = 0;

	for (unsigned int i = 0; i < ARRAY_SIZE(sd->seq); i++) {
		if (sd->seq[i] > highest)
			highest = sd->seq[i];
	}
	return highest;
}

static u64 load_u48be(const u8 *in)
{
	u64 ret;

	ret =  ((u64)in[0]) << (5 * 8);
	ret |= ((u64)in[1]) << (4 * 8);
	ret |= ((u64)in[2]) << (3 * 8);
	ret |= ((u64)in[3]) << (2 * 8);
	ret |= ((u64)in[4]) << (1 * 8);
	ret |= ((u64)in[5]) << (0 * 8);

	return ret;
}

static void store_u48be(u8 *out, u64 in)
{
	out[0] = (in >> (5 * 8));
	out[1] = (in >> (4 * 8));
	out[2] = (in >> (3 * 8));
	out[3] = (in >> (2 * 8));
	out[4] = (in >> (1 * 8));
	out[5] = (in >> (0 * 8));
}


/**
 * milenage_usim_check - Check MILENAGE authentication
 * @kd: caller-provided key data (k/op/opc/...)
 * @sd: caller-provided sequence number data. may be updated!
 * @mr: caller-allocated memory for output data
 * @_rand: RAND = 128-bit random challenge
 * @autn: AUTN = 128-bit authentication token
 * Returns: 0 on success, -1 on failure, or -2 on synchronization failure
 *
 * See Annex C.2.2 of 3GPP TS 33.102 for the details on how the USIM checks for
 * SQN freshness.
 */
int milenage_usim_check(const struct milenage_key_data *kd,
			struct milenage_seq_data *sd,
			struct milenage_result *mr,
			const u8 *_rand, const u8 *autn)
{
	u8 opc[16];
	u8 mac_a[8], ak[6], rx_sqn[6];
	const u8 *amf;
	u8 ind;
	u64 rx_sqn64, rx_seq, seq_ms;
	int ret = -1;

	u8 auts_amf[2] = { 0x00, 0x00 }; /* TS 33.102 v7.0.0, 6.3.3 */
	/* USIM shall generate a synchronisation failure message
	 * using the highest previously accepted sequence number
	 * anywhere in the array, i.e. SQN_MS. */
	u64 highest_seq_ms = get_highest_seq_ms(sd);
	u8 highest_sqn_ms[6];

	wpa_hexdump(MSG_DEBUG, "Milenage: AUTN", autn, 16);
	wpa_hexdump(MSG_DEBUG, "Milenage: RAND", _rand, 16);

	if (!kd->opc_is_op) {
		/* OPC is already the OPC */
		os_memcpy(opc, kd->opc, sizeof(opc));
	} else {
		int rc = milenage_opc_gen(opc, kd->k, kd->opc);
		if (rc < 0)
			goto out;
	}

	if (milenage_f2345(opc, kd->k, _rand, mr->res, mr->ck, mr->ik, ak, NULL))
		goto out;

	mr->res_len = 8;
	wpa_hexdump_key(MSG_DEBUG, "Milenage: RES", mr->res, kd->res_len);
	wpa_hexdump_key(MSG_DEBUG, "Milenage: CK", mr->ck, 16);
	wpa_hexdump_key(MSG_DEBUG, "Milenage: IK", mr->ik, 16);
	wpa_hexdump_key(MSG_DEBUG, "Milenage: AK", mr->ak, 6);

	/* AUTN = (SQN ^ AK) || AMF || MAC */
	for (unsigned int i = 0; i < 6; i++)
		rx_sqn[i] = autn[i] ^ ak[i];
	wpa_hexdump(MSG_DEBUG, "Milenage: SQN", rx_sqn, 6);

	/* Determine IND and SEQ from SQN */
	rx_sqn64 = load_u48be(rx_sqn);
	ind = rx_sqn64 & MILENAGE_IND_MASK;
	rx_seq = rx_sqn64 >> MILENAGE_IND_LEN;

	/* FIXME #54: check whether this can be anything else than highest_seq_ms */
	seq_ms = get_highest_seq_ms(sd);

	/* the received sequence number SQN shall only be
	   accepted by the USIM if SEQ - SEQ_MS ≤ delta */
	if (rx_seq - seq_ms >= sd->delta) {
		/* C.2.1 unsuccessful case: SEQ - SEQ_MS >= delta */
		goto out_auts;
	}

	if (rx_seq <= sd->seq[ind]) {
		/* C.2.2 unsuccessful case: SEQ <= SEQ_MS(i) */
		goto out_auts;
	}

	/* C.2.2 successful case: SEQ > SEQ_MS(i) */
	sd->seq[ind] = rx_seq;

	amf = autn + 6;
	wpa_hexdump(MSG_DEBUG, "Milenage: AMF", amf, 2);
	if (milenage_f1(opc, kd->k, _rand, rx_sqn, amf, mac_a, NULL))
		goto out;

	wpa_hexdump(MSG_DEBUG, "Milenage: MAC_A", mac_a, 8);

	if (os_memcmp_const(mac_a, autn + 8, 8) != 0) {
		wpa_printf(MSG_DEBUG, "Milenage: MAC mismatch");
		wpa_hexdump(MSG_DEBUG, "Milenage: Received MAC_A",
			    autn + 8, 8);
		goto out;
	}

	ret = 0;

out:
	/* clear cryptographic sensitive data from stack */
	ss_memzero(opc, sizeof(opc));
	ss_memzero(mac_a, sizeof(mac_a));
	ss_memzero(ak, sizeof(ak));
	ss_memzero(rx_sqn, sizeof(rx_sqn));

	return ret;


out_auts:

	store_u48be(highest_sqn_ms, (highest_seq_ms << MILENAGE_IND_LEN) | ind);

	if (milenage_f2345(opc, kd->k, _rand, NULL, NULL, NULL, NULL, ak))
		goto out;
	wpa_hexdump_key(MSG_DEBUG, "Milenage: AK*", ak, 6);
	for (unsigned int i = 0; i < 6; i++)
		mr->auts[i] = highest_sqn_ms[i] ^ ak[i];
	if (milenage_f1(opc, kd->k, _rand, highest_sqn_ms, auts_amf, NULL, mr->auts + 6))
		goto out;
	wpa_hexdump(MSG_DEBUG, "Milenage: AUTS", mr->auts, 14);

	/* clear cryptographic sensitive data from stack */
	ret = -2;
	goto out;

}
