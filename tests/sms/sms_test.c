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
#include <onomondo/softsim/utils.h>
#include <onomondo/softsim/list.h>
#include "src/softsim/uicc/sms.h"
#include "src/softsim/uicc/uicc_sms_tx.h"
#include "src/softsim/uicc/context.h"

/* Clear a conetxt, clear its TX state, and set all the bits required for proactive SMS */
static void ready_ctx(struct ss_context *ctx)
{
	memset(ctx, 0, sizeof(*ctx));
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
	return 0;
}
