/*
 * Copyright (c) 2024 Onomondo ApS. All rights reserved.
 *
 * SPDX-License-Identifier: GPL-3.0-only
 */

#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <assert.h>
#include <errno.h>
#include <onomondo/softsim/log.h>
#include <onomondo/softsim/utils.h>
#include <onomondo/softsim/storage.h>
#include "sw.h"
#include "uicc_lchan.h"
#include "../milenage/milenage.h"
#include "../milenage/milenage_usim.h"
#include "command.h"
#include "uicc_ins.h"
#include "apdu.h"
#include "fs.h"
#include "fs_utils.h"

/* 3GPP TS 31.102 Table 7.1.2-1 + Table 7.1.2-2 */
enum usim_auth_ctx {
	USIM_AUTH_CTX_GSM = 0,
	USIM_AUTH_CTX_3G = 1,
	USIM_AUTH_CTX_VGCS_VBS = 2,
	USIM_AUTH_CTX_GBA = 4,
	USIM_AUTH_CTX_MBMS = 5,
	USIM_AUTH_CTX_LOCAL_KEY = 6,
};

/* convenience struct for the response APDU */
struct auth_res_success_3g {
	uint8_t tag;
	uint8_t res_len;
	uint8_t res[8];
	uint8_t ck_len;
	uint8_t ck[16];
	uint8_t ik_len;
	uint8_t ik[16];
	/* Generally we do make service 27 available; consequently, that bit
	 * needs to be set when configuring the file system. */
	uint8_t kc_len;
	uint8_t kc[8];
} __attribute__((packed));

#define KEY_DATA_FID 0xA001
#define SEQ_DATA_FID_BASE 0xA100

/* Populate key data from file */
static int get_key_data(struct milenage_key_data *key_data)
{
	struct ss_list key_data_path;
	struct ss_buf *key_data_raw;
	int rc;

	/* File format:
	 * |16 byte K|16 byte OP/OPc|1 byte flag|
	 * flag: 0x01 = OP/OPc is OP, 0x00 = OP/OPc is OPc */

	ss_fs_init(&key_data_path);
	rc = ss_fs_select(&key_data_path, KEY_DATA_FID);
	if (rc < 0) {
		SS_LOGP(SAUTH, LERROR, "key data file (%04x) not found -- abort\n", KEY_DATA_FID);
		ss_path_reset(&key_data_path);
		return -EINVAL;
	}

	key_data_raw = ss_storage_read_file(&key_data_path, 0, ss_storage_get_file_len(&key_data_path));
	if (!key_data_raw) {
		SS_LOGP(SAUTH, LERROR, "key data file (%s) not readable -- abort\n",
			ss_fs_utils_dump_path(&key_data_path));
		ss_path_reset(&key_data_path);
		return -EINVAL;
	}

	if (key_data_raw->len < sizeof(key_data->k) + sizeof(key_data->opc) + 1) {
		SS_LOGP(SAUTH, LERROR, "key data file (%s) too short -- abort\n",
			ss_fs_utils_dump_path(&key_data_path));
		ss_path_reset(&key_data_path);
		ss_buf_free(key_data_raw);
		return -EINVAL;
	}

	memcpy(key_data->k, key_data_raw->data, sizeof(key_data->k));
	memcpy(key_data->opc, key_data_raw->data + sizeof(key_data->k), sizeof(key_data->opc));
	if (key_data_raw->data[sizeof(key_data->k) + sizeof(key_data->opc)] == 0x01)
		key_data->opc_is_op = true;
	else
		key_data->opc_is_op = false;

	SS_LOGP(SAUTH, LDEBUG, "key data file (%s) loaded\n", ss_fs_utils_dump_path(&key_data_path));

	ss_path_reset(&key_data_path);
	ss_buf_free(key_data_raw);
	return 0;
}

/* Populate SEQ data from file */
static int get_seq_data(struct milenage_seq_data *seq_data)
{
	struct ss_list seq_data_path;
	struct ss_buf *seq_data_raw;
	int rc;
	int file_offset = 0;

	/* File format:
	 * | 64-bit SEQ_M values ]
   * [ 64-bit delta ]
	 * (all big endian)
	 * */

	ss_fs_init(&seq_data_path);

	for (file_offset = 0; file_offset < SS_ARRAY_SIZE(seq_data->seq) + 1; file_offset++) {
		rc = ss_fs_select(&seq_data_path, SEQ_DATA_FID_BASE + file_offset);

		if (rc < 0) {
			SS_LOGP(SAUTH, LERROR, "seq data file (%04x) not found -- abort\n", KEY_DATA_FID);
			ss_path_reset(&seq_data_path);
			return -EINVAL;
		}

		seq_data_raw = ss_storage_read_file(&seq_data_path, 0, ss_storage_get_file_len(&seq_data_path));
		if (!seq_data_raw) {
			SS_LOGP(SAUTH, LERROR, "seq data file (%s) not readable -- abort\n",
				ss_fs_utils_dump_path(&seq_data_path));

			ss_path_reset(&seq_data_path);
			return -EINVAL;
		}

		if (seq_data_raw->len < sizeof(uint64_t)) {
			SS_LOGP(SAUTH, LERROR, "seq data file (%s) too short -- abort\n",
				ss_fs_utils_dump_path(&seq_data_path));
			ss_path_reset(&seq_data_path);

			ss_buf_free(seq_data_raw);
			return -EINVAL;
		}

		if (file_offset < SS_ARRAY_SIZE(seq_data->seq)) {
			seq_data->seq[file_offset] = ss_uint64_load_from_be(seq_data_raw->data);

			SS_LOGP(SAUTH, LDEBUG, "seq data file (%s) loaded\n", ss_fs_utils_dump_path(&seq_data_path));
		} else {
			seq_data->delta = ss_uint64_load_from_be(seq_data_raw->data);

			SS_LOGP(SAUTH, LDEBUG, "delta data file (%s) loaded\n", ss_fs_utils_dump_path(&seq_data_path));
		}

		ss_buf_free(seq_data_raw);
	}

	ss_path_reset(&seq_data_path);
	return 0;
}

/* Sync SEQ data back to file */
static int update_seq_data(struct milenage_seq_data *seq_data)
{
	struct ss_list seq_data_path;
	uint8_t write_buffer[sizeof(seq_data->delta)]; // 8 bytes

	int rc;
	int file_offset = 0;

	ss_fs_init(&seq_data_path);

	for (file_offset = 0; file_offset < SS_ARRAY_SIZE(seq_data->seq) + 1; file_offset++) {
		rc = ss_fs_select(&seq_data_path, SEQ_DATA_FID_BASE + file_offset);

		if (rc < 0) {
			SS_LOGP(SAUTH, LERROR, "seq data file (%04x) not found -- abort\n", KEY_DATA_FID);
			ss_path_reset(&seq_data_path);
			return -EINVAL;
		}

		if (file_offset < SS_ARRAY_SIZE(seq_data->seq)) {
			ss_uint64_store_to_be(write_buffer, seq_data->seq[file_offset]);

		} else {
			ss_uint64_store_to_be(write_buffer, seq_data->delta);
		}

		rc = ss_storage_write_file(&seq_data_path, write_buffer, 0, sizeof(write_buffer));

		if (rc < 0) {
			SS_LOGP(SAUTH, LERROR, "seq data file (%s) not writeable -- abort\n",
				ss_fs_utils_dump_path(&seq_data_path));
			ss_path_reset(&seq_data_path);
			return -EINVAL;
		}
	}

	SS_LOGP(SAUTH, LDEBUG, "seq data file (%s) updated\n", ss_fs_utils_dump_path(&seq_data_path));
	ss_path_reset(&seq_data_path);
	return 0;
}

/* determine OPc: Either we have OPC already in akd, or we generate it from K+OP */
static int gen_opc(uint8_t *opc, const struct milenage_key_data *akd)
{
	if (akd->opc_is_op) {
		return milenage_opc_gen(opc, akd->k, akd->opc);
	} else {
		memcpy(opc, akd->opc, sizeof(akd->opc));
		return 0;
	}
}

static int authenticate_milenage(struct ss_apdu *apdu, enum usim_auth_ctx auth_ctx, const uint8_t *rand,
				 uint8_t rand_len, const uint8_t *autn, uint8_t autn_len)
{
	struct milenage_key_data mkd_storage;
	struct milenage_key_data *mkd = &mkd_storage;
	struct milenage_seq_data msd_storage;
	struct milenage_seq_data *msd = &msd_storage;
	struct milenage_result mres;
	struct auth_res_success_3g *res_3g;
	int rc;

	/* Load key material and SEQ from file */
	rc = get_key_data(mkd);
	if (rc < 0)
		return -EINVAL;
	rc = get_seq_data(msd);
	if (rc < 0)
		return -EINVAL;

	u8 opc[16];
	gen_opc(opc, mkd);

	memset(&mres, 0, sizeof(mres));

	switch (auth_ctx) {
	case USIM_AUTH_CTX_GSM:
		if (rand_len != 128 / 8) {
			SS_LOGP(SAUTH, LERROR, "unexpected RAND len -- authentication failed\n");
			goto out_err;
		}
		/* actually perform authentication */
		rc = gsm_milenage(opc, mkd->k, rand, &apdu->rsp[1], &apdu->rsp[1 + 4 + 1]);
		if (rc < 0) {
			SS_LOGP(SAUTH, LERROR, "milenage computation failed -- authentication failed\n");
			goto out_err;
		}
		/* put together response data */
		apdu->rsp[0] = 4;     /* length of SRES */
		apdu->rsp[1 + 4] = 8; /* length of Kc */
		apdu->rsp_len = 1 + 4 + 1 + 8;
		break;
	case USIM_AUTH_CTX_3G:
		if (rand_len != 128 / 8) {
			SS_LOGP(SAUTH, LERROR, "unexpected RAND len -- authentication failed\n");
			goto out_err;
		}
		if (autn_len != 128 / 8) {
			SS_LOGP(SAUTH, LERROR, "unexpected AUTN len -- authentication failed\n");
			goto out_err;
		}
		/* actually perform authentication */
		rc = milenage_usim_check(mkd, msd, &mres, rand, autn);
		switch (rc) {
		case 0: /* successful case */
			SS_LOGP(SAUTH, LDEBUG, "Milenage successful\n");
			assert(mres.res_len == 8);
			/* FIXME #59: update SEQ bucket for IND */
			/* generate response */
			res_3g = (struct auth_res_success_3g *)apdu->rsp;
			res_3g->tag = 0xDB;
			res_3g->res_len = mres.res_len;
			memcpy(res_3g->res, mres.res, mres.res_len);
			res_3g->ck_len = sizeof(mres.ck);
			memcpy(res_3g->ck, mres.ck, sizeof(mres.ck));
			res_3g->ik_len = sizeof(mres.ik);
			memcpy(res_3g->ik, mres.ik, sizeof(mres.ik));

			res_3g->kc_len = 8;
			rc = gsm_milenage(opc, mkd->k, rand, NULL, res_3g->kc);
			if (rc < 0) {
				SS_LOGP(SAUTH, LERROR, "Failing milenage: GSM Kc could not be derived.\n");
				goto out_err;
			}

			/* Sync SEQ to file */
			rc = update_seq_data(msd);
			if (rc < 0) {
				SS_LOGP(SAUTH, LERROR, "Failing milenage: Sequence data could not be stored\n");
				return -EINVAL;
			}

			apdu->rsp_len = sizeof(*res_3g);
			return 0;
		case -2:
			SS_LOGP(SAUTH, LINFO, "Milenage requesting resync (returning AUTS)\n");
			apdu->rsp[0] = 0xDC;
			apdu->rsp[1] = sizeof(mres.auts);
			memcpy(&apdu->rsp[2], mres.auts, sizeof(mres.auts));
			apdu->rsp_len = 2 + sizeof(mres.auts);
			return 0;
		default:
			SS_LOGP(SAUTH, LERROR, "authentication failed\n");
			break;
		}
		break;
	default:
		assert(0);
	}

out_err:
	memset(&mres, 0, sizeof(mres));
	return -1;
}

/* AUTHENTICATE, see 3GPP TS 31.102 Section 7.1 */
int ss_uicc_auth_cmd_authenticate_even_fn(struct ss_apdu *apdu)
{
	uint8_t auth_ctx;
	const uint8_t *rand, *autn;
	uint8_t rand_len, autn_len;

	if (apdu->hdr.p1 != 0x00) {
		apdu->sw = SS_SW_ERR_CHECKING_WRONG_P1_P2;
		return 0;
	}

	if (!(apdu->hdr.p2 & 0x80)) {
		apdu->sw = SS_SW_ERR_CHECKING_WRONG_P1_P2;
		return 0;
	}

	/* we only support GSM and 3G context */
	auth_ctx = apdu->hdr.p2 & 0x07;
	switch (auth_ctx) {
	case USIM_AUTH_CTX_GSM:
	case USIM_AUTH_CTX_3G:
		break;
	default:
		apdu->sw = SS_SW_ERR_CHECKING_WRONG_P1_P2;
		return 0;
	}

	if (apdu->lc < 1)
		goto err_len;
	rand_len = apdu->cmd[0];

	if (apdu->lc < 1 + rand_len)
		goto err_len;
	rand = &apdu->cmd[1];

	if (auth_ctx == USIM_AUTH_CTX_3G) {
		if (apdu->lc < 1 + rand_len + 1)
			goto err_len;
		autn_len = apdu->cmd[1 + rand_len];

		if (apdu->lc < 1 + rand_len + 1 + autn_len)
			goto err_len;
		autn = &apdu->cmd[1 + rand_len + 1];
	} else {
		autn_len = 0;
		autn = NULL;
	}

	return authenticate_milenage(apdu, auth_ctx, rand, rand_len, autn, autn_len);

err_len:
	apdu->sw = SS_SW_ERR_CHECKING_WRONG_LENGTH;
	return 0;
}
