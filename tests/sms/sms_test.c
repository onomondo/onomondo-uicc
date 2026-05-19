/*
 * Copyright (c) 2024 Onomondo ApS. All rights reserved.
 *
 * SPDX-License-Identifier: GPL-3.0-only
 *
 * Author: Philipp Maier
 */

#include <stdio.h>
#include <stdbool.h>
#include <stddef.h>
#include <string.h>
#include <onomondo/softsim/utils.h>
#include <onomondo/softsim/list.h>
#include "src/softsim/uicc/sw.h"
#include "src/softsim/uicc/sms.h"
#include "src/softsim/uicc/uicc_sms_rx.h"
#include "src/softsim/uicc/uicc_sms_tx.h"
#include "src/softsim/uicc/context.h"

/* Clear a conetxt, clear its TX state, and set all the bits required for proactive SMS */
static void ready_ctx(struct ss_context *ctx)
{
	memset(ctx, 0, sizeof(*ctx));
	ss_uicc_sms_rx_clear(ctx);
	ss_uicc_sms_tx_clear(ctx);
	/* Simulate context that set all the relevant bits */
	ctx->proactive.term_profile[0] = 0xff;
	ctx->proactive.term_profile[1] = 0xff;
	ctx->proactive.term_profile[3] = 0xff;
	ctx->proactive.term_profile[4] = 0xff;
	ctx->proactive.term_profile[5] = 0xff;
}

void ss_sms_hdr_decode_sms_deliver_test(void)
{
	uint8_t sms_tpdu[] =
	    { 0x40, 0x08, 0x81, 0x55, 0x66, 0x77, 0x88, 0x7f, 0xf6, 0x00, 0x11,
		0x29, 0x12, 0x00, 0x00, 0x04, 0x3d, 0x02, 0x70,
		0x00, 0x00, 0x38, 0x15, 0x06, 0x01, 0x25, 0x25, 0xb0, 0x00,
		0x10, 0x80, 0x76, 0x6f, 0x57, 0xf0, 0xf8, 0x9b, 0xbd,
		0xbc, 0x09, 0xaf, 0x97, 0xb8, 0xb7, 0xef, 0x7e, 0xdc, 0x6c,
		0x8b, 0xd2, 0xa3, 0x5a, 0x57, 0x14, 0x70, 0x37, 0x49,
		0x75, 0x00, 0x3b, 0xfd, 0x77, 0xac, 0x39, 0x53, 0x1c, 0xc4,
		0x82, 0x71, 0x4e, 0x75, 0x47, 0xa3, 0xf8, 0x5c, 0xc5,
		0xdc, 0x10
	};
	struct ss_sm_hdr sm_hdr;
	int rc;

	printf("receive SMS-DELIVER tpu\n");

	rc = ss_sms_hdr_decode(&sm_hdr, sms_tpdu, sizeof(sms_tpdu));

	printf(" rc=%i\n", rc);

	printf(" tp_mti=%02x\n", sm_hdr.tp_mti);
	printf(" tp_mms=%u\n", sm_hdr.u.sms_deliver.tp_mms);
	printf(" tp_rp=%u\n", sm_hdr.u.sms_deliver.tp_rp);
	printf(" tp_udhi=%u\n", sm_hdr.u.sms_deliver.tp_udhi);
	printf(" tp_sri=%u\n", sm_hdr.u.sms_deliver.tp_sri);
	printf(" tp_oa.extension=%u\n", sm_hdr.u.sms_deliver.tp_oa.extension);
	printf(" tp_oa.type_of_number=%u\n",
	       sm_hdr.u.sms_deliver.tp_oa.type_of_number);
	printf(" tp_oa.numbering_plan=%u\n",
	       sm_hdr.u.sms_deliver.tp_oa.numbering_plan);
	printf(" tp_oa.digits=%s\n", sm_hdr.u.sms_deliver.tp_oa.digits);
	printf(" tp_pid=%02x\n", sm_hdr.u.sms_deliver.tp_pid);
	printf(" tp_dcs=%02x\n", sm_hdr.u.sms_deliver.tp_dcs);
	printf(" tp_scts=%s\n",
	       ss_hexdump(sm_hdr.u.sms_deliver.tp_scts,
			  sizeof(sm_hdr.u.sms_deliver.tp_scts)));
	printf(" tp_udl=%u\n", sm_hdr.u.sms_deliver.tp_udl);

	printf(" user data: %s\n",
	       ss_hexdump(sms_tpdu + rc, sm_hdr.u.sms_deliver.tp_udl));

	printf("\n");
}

void ss_sms_hdr_decode_sms_status_report(void)
{
	uint8_t sms_tpdu[] =
	    { 0x02, 0x23, 0x08, 0x81, 0x55, 0x66, 0x77, 0x88, 0x00, 0x11, 0x29,
		0x12, 0x00, 0x00, 0x04, 0x00, 0x11, 0x29, 0x12, 0x00, 0x00,
		0x04, 0x42
	};
	struct ss_sm_hdr sm_hdr;
	int rc;

	printf("receive SMS-STATUS-REPORT tpu\n");

	rc = ss_sms_hdr_decode(&sm_hdr, sms_tpdu, sizeof(sms_tpdu));

	printf(" rc=%i\n", rc);

	printf(" tp_mti=%02x\n", sm_hdr.tp_mti);
	printf(" tp_mr=%02x\n", sm_hdr.u.sms_status_report.tp_mr);
	printf(" tp_mms=%u\n", sm_hdr.u.sms_status_report.tp_mms);
	printf(" tp_ra.extension=%u\n",
	       sm_hdr.u.sms_status_report.tp_ra.extension);
	printf(" tp_ra.type_of_number=%u\n",
	       sm_hdr.u.sms_status_report.tp_ra.type_of_number);
	printf(" tp_ra.numbering_plan=%u\n",
	       sm_hdr.u.sms_status_report.tp_ra.numbering_plan);
	printf(" tp_ra.digits=%s\n", sm_hdr.u.sms_status_report.tp_ra.digits);
	printf(" tp_scts=%s\n",
	       ss_hexdump(sm_hdr.u.sms_status_report.tp_scts,
			  sizeof(sm_hdr.u.sms_status_report.tp_scts)));
	printf(" tp_dt=%s\n",
	       ss_hexdump(sm_hdr.u.sms_status_report.tp_dt,
			  sizeof(sm_hdr.u.sms_status_report.tp_dt)));
	printf(" tp_st=%02x\n", sm_hdr.u.sms_status_report.tp_st);

	printf("\n");
}

void ss_sms_hdr_decode_sms_submit_report(void)
{
	uint8_t sms_tpdu[] = { 0x01, 0x42 };
	struct ss_sm_hdr sm_hdr;
	int rc;

	printf("receive SMS-DELIVER tpu\n");

	rc = ss_sms_hdr_decode(&sm_hdr, sms_tpdu, sizeof(sms_tpdu));

	printf(" rc=%i\n", rc);

	printf(" tp_mti=%02x\n", sm_hdr.tp_mti);
	printf(" tp_fcs=%02x\n", sm_hdr.u.sms_submit_report.tp_fcs);

	printf("\n");
}

void ss_sms_hdr_encode_test_sms_deliver_report(void)
{
	int rc;
	uint8_t result[256];
	struct ss_sm_hdr sm_hdr;

	printf("send SMS-DELIVER-REPORT tpu\n");

	memset(&sm_hdr, 0, sizeof(sm_hdr));

	sm_hdr.tp_mti = SMS_MTI_DELIVER_REPORT;
	sm_hdr.u.sms_deliver_report.tp_udhi = true;
	sm_hdr.u.sms_deliver_report.tp_fcs = 0x42;
	sm_hdr.u.sms_deliver_report.tp_pid_present = true;
	sm_hdr.u.sms_deliver_report.tp_pid = 0x23;
	sm_hdr.u.sms_deliver_report.tp_dcs_present = true;
	sm_hdr.u.sms_deliver_report.tp_dcs = 0x24;
	sm_hdr.u.sms_deliver_report.tp_udl_present = true;
	sm_hdr.u.sms_deliver_report.tp_udl = 0x25;

	rc = ss_sms_hdr_encode(result, sizeof(result), &sm_hdr);
	printf(" rc=%i\n", rc);
	printf(" result=%s\n", ss_hexdump(result, rc));
	printf("\n");
}

void ss_sms_hdr_encode_test_sms_command(void)
{
	int rc;
	uint8_t result[256];
	struct ss_sm_hdr sm_hdr;

	printf("send SMS-COMMAND tpu\n");

	memset(&sm_hdr, 0, sizeof(sm_hdr));

	sm_hdr.tp_mti = SMS_MTI_COMMAND;
	sm_hdr.u.sms_command.tp_udhi = true;
	sm_hdr.u.sms_command.tp_srr = true;
	sm_hdr.u.sms_command.tp_mr = 0x23;
	sm_hdr.u.sms_command.tp_pid = 0x42;
	sm_hdr.u.sms_command.tp_ct = 0x03;
	sm_hdr.u.sms_command.tp_mn = 0x11;
	sm_hdr.u.sms_command.tp_da.extension = true;
	sm_hdr.u.sms_command.tp_da.type_of_number = 0;
	sm_hdr.u.sms_command.tp_da.numbering_plan = 1;
	strcpy(sm_hdr.u.sms_command.tp_da.digits, "1234567");
	sm_hdr.u.sms_command.tp_cdl = 0x99;

	rc = ss_sms_hdr_encode(result, sizeof(result), &sm_hdr);
	printf(" rc=%i\n", rc);
	if (rc >= 0)
		printf(" result=%s\n", ss_hexdump(result, rc));
	printf("\n");
}

void ss_sms_hdr_encode_test_sms_submit(void)
{
	int rc;
	uint8_t result[256];
	struct ss_sm_hdr sm_hdr;

	printf("send SMS-SUBMIT tpu\n");

	memset(&sm_hdr, 0, sizeof(sm_hdr));
	sm_hdr.tp_mti = SMS_MTI_SUBMIT;
	sm_hdr.u.sms_submit.tp_rd = true;
	sm_hdr.u.sms_submit.tp_vpf = 0x03;
	sm_hdr.u.sms_submit.tp_rp = true;
	sm_hdr.u.sms_submit.tp_udhi = true;
	sm_hdr.u.sms_submit.tp_srr = true;
	sm_hdr.u.sms_submit.tp_mr = 0x23;
	sm_hdr.u.sms_submit.tp_da.extension = true;
	sm_hdr.u.sms_submit.tp_da.type_of_number = 0;
	sm_hdr.u.sms_submit.tp_da.numbering_plan = 1;
	strcpy(sm_hdr.u.sms_submit.tp_da.digits, "1234567");
	sm_hdr.u.sms_submit.tp_pid = 0x23;
	sm_hdr.u.sms_submit.tp_dcs = 0x24;
	memset(sm_hdr.u.sms_submit.tp_vp, 0xAA,
	       sizeof(sm_hdr.u.sms_submit.tp_vp));
	sm_hdr.u.sms_submit.tp_udl = 0x99;

	rc = ss_sms_hdr_encode(result, sizeof(result), &sm_hdr);
	printf(" rc=%i\n", rc);
	if (rc >= 0)
		printf(" result=%s\n", ss_hexdump(result, rc));
	printf("\n");
}

static void sms_tx_state_show(struct ss_context *ctx)
{
	struct ss_uicc_sms_tx_sm *sm;

	printf(" resulting ss_uicc_sms_tx_state:\n");

	if (ctx->proactive.sms_tx_state.pending) {
		printf("  pending SMS as command:  %s\n", ss_hexdump(ctx->proactive.data, ctx->proactive.data_len));
	}

	SS_LIST_FOR_EACH(&ctx->proactive.sms_tx_state.sm, sm, struct ss_uicc_sms_tx_sm, list) {
		printf("  SM:%s, last_msg=%s\n",
		       ss_hexdump(sm->msg, sm->msg_len),
		       sm->last_msg ? "true" : "false");
	}
}

void ss_uicc_sms_tx_test_single(void)
{
	struct ss_context ctx;
	int rc;
	struct ss_sm_hdr sm_hdr;
	uint8_t tp_ud[] =
	    { 0xc8, 0x22, 0x93, 0xf9, 0x64, 0x5d, 0x9f, 0x52, 0x26, 0x11 };

	printf("test ss_uicc_sms_tx (message that fits in a single SM)\n");
	ready_ctx(&ctx);

	memset(&sm_hdr, 0, sizeof(sm_hdr));
	sm_hdr.tp_mti = SMS_MTI_SUBMIT;
	sm_hdr.u.sms_submit.tp_da.extension = true;
	sm_hdr.u.sms_submit.tp_da.type_of_number = 0;
	sm_hdr.u.sms_submit.tp_da.numbering_plan = 1;
	strcpy(sm_hdr.u.sms_submit.tp_da.digits, "23001");
	sm_hdr.u.sms_submit.tp_udl = sizeof(tp_ud) + 1;	/* Depends on encoding, 10 bytes, but 11 digits */
	rc = ss_uicc_sms_tx(&ctx, &sm_hdr, NULL, 0, tp_ud, sizeof(tp_ud),
			    NULL);
	if (rc < 0)
		assert(false);

	sms_tx_state_show(&ctx);
	ss_uicc_sms_tx_clear(&ctx);
}

void ss_uicc_sms_tx_test_multi(void)
{
	struct ss_context ctx;
	int rc;
	struct ss_sm_hdr sm_hdr;
	uint8_t tp_ud[300];
	uint8_t ud_hdr[10];
	size_t i;

	printf
	    ("test ss_uicc_sms_tx (message that needs to be splitted over multiple SM)\n");

	memset(ud_hdr, 0xf1, sizeof(ud_hdr));

	/* Fill tp_ud with distinctive pattern */
	for (i = 0; i < sizeof(tp_ud); i++) {
		tp_ud[i] = (uint8_t) i & 0x0f;
		tp_ud[i] |= tp_ud[i] << 4;
	}
	tp_ud[sizeof(tp_ud) - 1] = 0x41;

	ready_ctx(&ctx);

	memset(&sm_hdr, 0, sizeof(sm_hdr));
	sm_hdr.tp_mti = SMS_MTI_SUBMIT;
	sm_hdr.u.sms_submit.tp_da.extension = true;
	sm_hdr.u.sms_submit.tp_da.type_of_number = 0;
	sm_hdr.u.sms_submit.tp_da.numbering_plan = 1;
	strcpy(sm_hdr.u.sms_submit.tp_da.digits, "23001");
	sm_hdr.u.sms_submit.tp_dcs = 0xF6;
	rc = ss_uicc_sms_tx(&ctx, &sm_hdr, ud_hdr, sizeof(ud_hdr), tp_ud,
			    sizeof(tp_ud), NULL);
	if (rc < 0)
		assert(false);

	sms_tx_state_show(&ctx);

	ss_uicc_sms_tx_clear(&ctx);
}

static size_t make_sms_deliver_with_udhl(uint8_t *sms_tpdu, size_t sms_tpdu_len, const uint8_t tp_oa[4],
					 uint8_t udhl, const uint8_t *ud_hdr, size_t ud_hdr_len,
					 const uint8_t *tp_ud, size_t tp_ud_len)
{
	static const uint8_t scts[7] = { 0x00, 0x11, 0x29, 0x12, 0x00, 0x00, 0x04 };
	size_t pos = 0;
	size_t tp_udl = 1 + ud_hdr_len + tp_ud_len;

	assert(tp_udl <= 255);
	assert(sms_tpdu_len >= 18 + ud_hdr_len + tp_ud_len);

	sms_tpdu[pos++] = 0x40; /* SMS-DELIVER with TP-UDHI */
	sms_tpdu[pos++] = 0x08;
	sms_tpdu[pos++] = 0x81;
	memcpy(&sms_tpdu[pos], tp_oa, 4);
	pos += 4;
	sms_tpdu[pos++] = 0x7f;
	sms_tpdu[pos++] = 0xf6;
	memcpy(&sms_tpdu[pos], scts, sizeof(scts));
	pos += sizeof(scts);
	sms_tpdu[pos++] = (uint8_t)tp_udl;
	sms_tpdu[pos++] = udhl;
	if (ud_hdr_len > 0) {
		memcpy(&sms_tpdu[pos], ud_hdr, ud_hdr_len);
		pos += ud_hdr_len;
	}
	if (tp_ud_len > 0) {
		memcpy(&sms_tpdu[pos], tp_ud, tp_ud_len);
		pos += tp_ud_len;
	}

	return pos;
}

static size_t make_sms_deliver(uint8_t *sms_tpdu, size_t sms_tpdu_len, const uint8_t tp_oa[4],
			       const uint8_t *ud_hdr, size_t ud_hdr_len, const uint8_t *tp_ud, size_t tp_ud_len)
{
	assert(ud_hdr_len <= 255);
	return make_sms_deliver_with_udhl(sms_tpdu, sms_tpdu_len, tp_oa, (uint8_t)ud_hdr_len, ud_hdr,
					  ud_hdr_len, tp_ud, tp_ud_len);
}

static int sms_rx_part(struct ss_context *ctx, const uint8_t tp_oa[4], const uint8_t *ud_hdr, size_t ud_hdr_len,
		       const uint8_t *tp_ud, size_t tp_ud_len, size_t *response_len)
{
	uint8_t sms_tpdu[256];
	uint8_t response[256];
	struct ss_buf buf;
	size_t sms_tpdu_len;

	sms_tpdu_len = make_sms_deliver(sms_tpdu, sizeof(sms_tpdu), tp_oa, ud_hdr, ud_hdr_len, tp_ud, tp_ud_len);
	buf.data = sms_tpdu;
	buf.len = sms_tpdu_len;
	*response_len = sizeof(response);
	return ss_uicc_sms_rx(ctx, &buf, response_len, response);
}

static void expect_sms_rx_part(struct ss_context *ctx, const uint8_t tp_oa[4], const uint8_t *ud_hdr,
			       size_t ud_hdr_len, const uint8_t *tp_ud, size_t tp_ud_len, int expected_rc,
			       size_t expected_response_len)
{
	size_t response_len;
	int rc;

	rc = sms_rx_part(ctx, tp_oa, ud_hdr, ud_hdr_len, tp_ud, tp_ud_len, &response_len);
	assert(rc == expected_rc);
	assert(response_len == expected_response_len);
}

static void ss_uicc_sms_rx_concat_8bit_test(void)
{
	static const uint8_t tp_oa[4] = { 0x55, 0x66, 0x77, 0x88 };
	struct ss_context ctx;
	uint8_t udh_1[] = { 0x00, 0x03, 0x21, 0x02, 0x01 };
	uint8_t udh_2[] = { 0x00, 0x03, 0x21, 0x02, 0x02 };
	uint8_t tp_ud_1[] = { 0xde, 0xad };
	uint8_t tp_ud_2[] = { 0xbe, 0xef };

	printf("test ss_uicc_sms_rx concat 8-bit\n");
	ready_ctx(&ctx);
	expect_sms_rx_part(&ctx, tp_oa, udh_1, sizeof(udh_1), tp_ud_1, sizeof(tp_ud_1), 0, 0);
	assert(ctx.proactive.sms_rx_state.reassembly_count == 1);
	expect_sms_rx_part(&ctx, tp_oa, udh_2, sizeof(udh_2), tp_ud_2, sizeof(tp_ud_2), 0, 0);
	assert(ctx.proactive.sms_rx_state.reassembly_count == 0);
	ss_uicc_sms_rx_clear(&ctx);
}

static void ss_uicc_sms_rx_concat_16bit_test(void)
{
	static const uint8_t tp_oa[4] = { 0x55, 0x66, 0x77, 0x88 };
	struct ss_context ctx;
	uint8_t udh_1[] = { 0x08, 0x04, 0x12, 0x34, 0x02, 0x01 };
	uint8_t udh_2[] = { 0x08, 0x04, 0x12, 0x34, 0x02, 0x02 };
	uint8_t tp_ud_1[] = { 0x10 };
	uint8_t tp_ud_2[] = { 0x20 };

	printf("test ss_uicc_sms_rx concat 16-bit\n");
	ready_ctx(&ctx);
	expect_sms_rx_part(&ctx, tp_oa, udh_1, sizeof(udh_1), tp_ud_1, sizeof(tp_ud_1), 0, 0);
	assert(ctx.proactive.sms_rx_state.reassembly_count == 1);
	expect_sms_rx_part(&ctx, tp_oa, udh_2, sizeof(udh_2), tp_ud_2, sizeof(tp_ud_2), 0, 0);
	assert(ctx.proactive.sms_rx_state.reassembly_count == 0);
	ss_uicc_sms_rx_clear(&ctx);
}

static void ss_uicc_sms_rx_concat_out_of_order_test(void)
{
	static const uint8_t tp_oa[4] = { 0x55, 0x66, 0x77, 0x88 };
	struct ss_context ctx;
	uint8_t udh_1[] = { 0x00, 0x03, 0x22, 0x02, 0x01 };
	uint8_t udh_2[] = { 0x00, 0x03, 0x22, 0x02, 0x02 };
	uint8_t tp_ud_1[] = { 0x01 };
	uint8_t tp_ud_2[] = { 0x02 };

	printf("test ss_uicc_sms_rx concat out-of-order\n");
	ready_ctx(&ctx);
	expect_sms_rx_part(&ctx, tp_oa, udh_2, sizeof(udh_2), tp_ud_2, sizeof(tp_ud_2), 0, 0);
	assert(ctx.proactive.sms_rx_state.reassembly_count == 1);
	expect_sms_rx_part(&ctx, tp_oa, udh_1, sizeof(udh_1), tp_ud_1, sizeof(tp_ud_1), 0, 0);
	assert(ctx.proactive.sms_rx_state.reassembly_count == 0);
	ss_uicc_sms_rx_clear(&ctx);
}

static void ss_uicc_sms_rx_concat_duplicate_test(void)
{
	static const uint8_t tp_oa[4] = { 0x55, 0x66, 0x77, 0x88 };
	struct ss_context ctx;
	uint8_t udh_1[] = { 0x00, 0x03, 0x23, 0x02, 0x01 };
	uint8_t udh_2[] = { 0x00, 0x03, 0x23, 0x02, 0x02 };
	uint8_t tp_ud_1[] = { 0x01 };
	uint8_t tp_ud_2[] = { 0x02 };

	printf("test ss_uicc_sms_rx concat duplicate\n");
	ready_ctx(&ctx);
	expect_sms_rx_part(&ctx, tp_oa, udh_1, sizeof(udh_1), tp_ud_1, sizeof(tp_ud_1), 0, 0);
	expect_sms_rx_part(&ctx, tp_oa, udh_1, sizeof(udh_1), tp_ud_1, sizeof(tp_ud_1), 0, 0);
	assert(ctx.proactive.sms_rx_state.reassembly_count == 1);
	expect_sms_rx_part(&ctx, tp_oa, udh_2, sizeof(udh_2), tp_ud_2, sizeof(tp_ud_2), 0, 0);
	assert(ctx.proactive.sms_rx_state.reassembly_count == 0);
	ss_uicc_sms_rx_clear(&ctx);
}

static void ss_uicc_sms_rx_concat_conflicting_duplicate_test(void)
{
	static const uint8_t tp_oa[4] = { 0x55, 0x66, 0x77, 0x88 };
	struct ss_context ctx;
	uint8_t udh_1[] = { 0x00, 0x03, 0x24, 0x02, 0x01 };
	uint8_t tp_ud_1[] = { 0x01 };
	uint8_t tp_ud_1_conflict[] = { 0x99 };

	printf("test ss_uicc_sms_rx concat conflicting duplicate\n");
	ready_ctx(&ctx);
	expect_sms_rx_part(&ctx, tp_oa, udh_1, sizeof(udh_1), tp_ud_1, sizeof(tp_ud_1), 0, 0);
	assert(ctx.proactive.sms_rx_state.reassembly_count == 1);
	expect_sms_rx_part(&ctx, tp_oa, udh_1, sizeof(udh_1), tp_ud_1_conflict, sizeof(tp_ud_1_conflict),
			   SS_SW_ERR_WRONG_PARAM_INCORRECT_DATA, 0);
	assert(ctx.proactive.sms_rx_state.reassembly_count == 0);
	ss_uicc_sms_rx_clear(&ctx);
}

static void ss_uicc_sms_rx_concat_interleaved_test(void)
{
	static const uint8_t tp_oa[4] = { 0x55, 0x66, 0x77, 0x88 };
	struct ss_context ctx;
	uint8_t udh_a1[] = { 0x00, 0x03, 0x31, 0x02, 0x01 };
	uint8_t udh_a2[] = { 0x00, 0x03, 0x31, 0x02, 0x02 };
	uint8_t udh_b1[] = { 0x00, 0x03, 0x32, 0x02, 0x01 };
	uint8_t udh_b2[] = { 0x00, 0x03, 0x32, 0x02, 0x02 };
	uint8_t tp_ud[] = { 0x01 };

	printf("test ss_uicc_sms_rx concat interleaved refs\n");
	ready_ctx(&ctx);
	expect_sms_rx_part(&ctx, tp_oa, udh_a1, sizeof(udh_a1), tp_ud, sizeof(tp_ud), 0, 0);
	expect_sms_rx_part(&ctx, tp_oa, udh_b1, sizeof(udh_b1), tp_ud, sizeof(tp_ud), 0, 0);
	assert(ctx.proactive.sms_rx_state.reassembly_count == 2);
	expect_sms_rx_part(&ctx, tp_oa, udh_a2, sizeof(udh_a2), tp_ud, sizeof(tp_ud), 0, 0);
	assert(ctx.proactive.sms_rx_state.reassembly_count == 1);
	expect_sms_rx_part(&ctx, tp_oa, udh_b2, sizeof(udh_b2), tp_ud, sizeof(tp_ud), 0, 0);
	assert(ctx.proactive.sms_rx_state.reassembly_count == 0);
	ss_uicc_sms_rx_clear(&ctx);
}

static void ss_uicc_sms_rx_concat_same_ref_different_originator_test(void)
{
	static const uint8_t tp_oa_a[4] = { 0x55, 0x66, 0x77, 0x88 };
	static const uint8_t tp_oa_b[4] = { 0x55, 0x66, 0x77, 0x98 };
	struct ss_context ctx;
	uint8_t udh_1[] = { 0x00, 0x03, 0x33, 0x02, 0x01 };
	uint8_t udh_2[] = { 0x00, 0x03, 0x33, 0x02, 0x02 };
	uint8_t tp_ud[] = { 0x01 };

	printf("test ss_uicc_sms_rx concat same ref different originator\n");
	ready_ctx(&ctx);
	expect_sms_rx_part(&ctx, tp_oa_a, udh_1, sizeof(udh_1), tp_ud, sizeof(tp_ud), 0, 0);
	expect_sms_rx_part(&ctx, tp_oa_b, udh_1, sizeof(udh_1), tp_ud, sizeof(tp_ud), 0, 0);
	assert(ctx.proactive.sms_rx_state.reassembly_count == 2);
	expect_sms_rx_part(&ctx, tp_oa_a, udh_2, sizeof(udh_2), tp_ud, sizeof(tp_ud), 0, 0);
	assert(ctx.proactive.sms_rx_state.reassembly_count == 1);
	expect_sms_rx_part(&ctx, tp_oa_b, udh_2, sizeof(udh_2), tp_ud, sizeof(tp_ud), 0, 0);
	assert(ctx.proactive.sms_rx_state.reassembly_count == 0);
	ss_uicc_sms_rx_clear(&ctx);
}

static void ss_uicc_sms_rx_concat_cpi_first_part_only_test(void)
{
	static const uint8_t tp_oa[4] = { 0x55, 0x66, 0x77, 0x88 };
	struct ss_context ctx;
	uint8_t udh_1[] = { 0x00, 0x03, 0x34, 0x02, 0x01, 0x70, 0x01, 0xaa };
	uint8_t udh_2[] = { 0x00, 0x03, 0x34, 0x02, 0x02 };
	uint8_t tp_ud_1[] = { 0xde };
	uint8_t tp_ud_2[] = { 0xad };

	printf("test ss_uicc_sms_rx concat CPI on first part only\n");
	ready_ctx(&ctx);
	expect_sms_rx_part(&ctx, tp_oa, udh_1, sizeof(udh_1), tp_ud_1, sizeof(tp_ud_1), 0, 0);
	assert(ctx.proactive.sms_rx_state.reassembly_count == 1);
	expect_sms_rx_part(&ctx, tp_oa, udh_2, sizeof(udh_2), tp_ud_2, sizeof(tp_ud_2),
			   SS_SW_ERR_CHECKING_WRONG_LENGTH, 0);
	assert(ctx.proactive.sms_rx_state.reassembly_count == 0);
	ss_uicc_sms_rx_clear(&ctx);
}

static void ss_uicc_sms_rx_concat_malformed_test(void)
{
	static const uint8_t tp_oa[4] = { 0x55, 0x66, 0x77, 0x88 };
	struct ss_context ctx;
	uint8_t sms_tpdu[256];
	uint8_t response[256];
	struct ss_buf buf;
	size_t sms_tpdu_len;
	size_t response_len;
	int rc;
	uint8_t malformed_concat[] = { 0x00, 0x02, 0x41, 0x02 };
	uint8_t invalid_seq[] = { 0x00, 0x03, 0x41, 0x02, 0x00 };
	uint8_t tp_ud[] = { 0x01 };

	printf("test ss_uicc_sms_rx concat malformed\n");
	ready_ctx(&ctx);

	sms_tpdu_len = make_sms_deliver_with_udhl(sms_tpdu, sizeof(sms_tpdu), tp_oa, 5, NULL, 0, NULL, 0);
	buf.data = sms_tpdu;
	buf.len = sms_tpdu_len;
	response_len = sizeof(response);
	rc = ss_uicc_sms_rx(&ctx, &buf, &response_len, response);
	assert(rc == SS_SW_ERR_WRONG_PARAM_INCORRECT_DATA);
	assert(response_len == 0);
	assert(ctx.proactive.sms_rx_state.reassembly_count == 0);

	expect_sms_rx_part(&ctx, tp_oa, malformed_concat, sizeof(malformed_concat), tp_ud, sizeof(tp_ud),
			   SS_SW_ERR_WRONG_PARAM_INCORRECT_DATA, 0);
	assert(ctx.proactive.sms_rx_state.reassembly_count == 0);

	expect_sms_rx_part(&ctx, tp_oa, invalid_seq, sizeof(invalid_seq), tp_ud, sizeof(tp_ud),
			   SS_SW_ERR_WRONG_PARAM_INCORRECT_DATA, 0);
	assert(ctx.proactive.sms_rx_state.reassembly_count == 0);
	ss_uicc_sms_rx_clear(&ctx);
}

int main(int argc, char **argv)
{
	ss_sms_hdr_decode_sms_deliver_test();
	ss_sms_hdr_decode_sms_status_report();
	ss_sms_hdr_decode_sms_submit_report();
	ss_sms_hdr_encode_test_sms_deliver_report();
	ss_sms_hdr_encode_test_sms_command();
	ss_sms_hdr_encode_test_sms_submit();
	ss_uicc_sms_tx_test_single();
	ss_uicc_sms_tx_test_multi();
	ss_uicc_sms_rx_concat_8bit_test();
	ss_uicc_sms_rx_concat_16bit_test();
	ss_uicc_sms_rx_concat_out_of_order_test();
	ss_uicc_sms_rx_concat_duplicate_test();
	ss_uicc_sms_rx_concat_conflicting_duplicate_test();
	ss_uicc_sms_rx_concat_interleaved_test();
	ss_uicc_sms_rx_concat_same_ref_different_originator_test();
	ss_uicc_sms_rx_concat_cpi_first_part_only_test();
	ss_uicc_sms_rx_concat_malformed_test();
	return 0;
}
