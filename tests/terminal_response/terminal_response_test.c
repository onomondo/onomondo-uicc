/*
 * Copyright (c) 2026 Onomondo ApS. All rights reserved.
 *
 * SPDX-License-Identifier: GPL-3.0-only
 */

#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <onomondo/softsim/softsim.h>
#include <onomondo/softsim/utils.h>
#include "src/softsim/uicc/context.h"
#include "src/softsim/uicc/fs.h"
#include "src/softsim/uicc/uicc_pin.h"
#include "src/softsim/uicc/sms.h"
#include "src/softsim/uicc/uicc_sms_tx.h"
extern uint32_t ss_log_mask;

/* TERMINAL RESPONSE results as the REFRESH and SEND SHORT MESSAGE tasks read them, per
 * ETSI TS 102 223, section 8.12: '0X'/'1X' performed, '2X' worth a retry, '3X' and up fail again. */

static uint16_t transact_hex_apdu(struct ss_context *ctx, const char *hex, uint8_t *resp, size_t resp_bufsize)
{
	uint8_t cmd[300];
	size_t cmd_len = ss_binary_from_hexstr(cmd, sizeof(cmd), hex);
	size_t resp_len = ss_application_apdu_transact(ctx, resp, resp_bufsize, cmd, &cmd_len);
	if (resp_len >= 2)
		return (uint16_t)((resp[resp_len - 2] << 8) | resp[resp_len - 1]);
	return 0;
}

static struct ss_context *proactive_ctx(void)
{
	struct ss_context *ctx;
	uint8_t resp[300];
	uint16_t sw;

	ss_log_mask = 0;
	ctx = ss_new_ctx();
	ss_reset(ctx);

	/* TERMINAL PROFILE claiming every facility, REFRESH and SEND SHORT MESSAGE included */
	sw = transact_hex_apdu(ctx, "8010000014ffffffffffffffffffffffffffffffffffffffff", resp, sizeof(resp));
	assert(sw == 0x9000);
	return ctx;
}

/* What an RFM script does to EF.FPLMN, on the reporting context the remote
 * command handler uses, so the change lands in the context's file list. */
static void rfm_clear_fplmn(struct ss_context *ctx)
{
	struct ss_context *rctx = ss_new_reporting_ctx(ctx->fs_chg_filelist);
	uint8_t out[260];
	size_t len;
	const char *cmds[] = { "00a4000c026f7b", "00d600000cffffffffffffffffffffffff" };
	size_t i;

	assert(rctx);
	ss_reset(rctx);
	ss_fs_select(&rctx->lchan.fs_path, 0x7ff0);
	rctx->lchan.pin_verfied[SS_PIN_ADM1] = true;
	for (i = 0; i < SS_ARRAY_SIZE(cmds); i++) {
		uint8_t cmd[64];
		size_t w;

		len = ss_binary_from_hexstr(cmd, sizeof(cmd), cmds[i]);
		w = ss_transact(rctx, out, sizeof(out), cmd, &len);
		assert(w == 2 && out[0] == 0x90 && out[1] == 0x00);
	}
	ss_free_ctx(rctx);
	assert(ctx->fs_chg_filelist[0] == 1);
}

/* STATUS after a poll: 91XX announces a pending REFRESH, 9000 none. */
static uint16_t poll_and_status(struct ss_context *ctx)
{
	uint8_t resp[300];

	ss_poll(ctx);
	return transact_hex_apdu(ctx, "80f2000c00", resp, sizeof(resp));
}

static void fetch_refresh(struct ss_context *ctx, uint16_t sw_pending)
{
	uint8_t resp[300];
	char hex[32];
	uint16_t sw;

	assert((sw_pending & 0xff00) == 0x9100);
	snprintf(hex, sizeof(hex), "80120000%02x", sw_pending & 0xff);
	sw = transact_hex_apdu(ctx, hex, resp, sizeof(resp));
	assert(sw == 0x9000);
	/* Command details: command number 1, type REFRESH */
	assert(resp[2] == 0x81 && resp[3] == 0x03 && resp[5] == 0x01);
}

/* TERMINAL RESPONSE to the REFRESH with the given RESULT value bytes */
static uint16_t terminal_response(struct ss_context *ctx, const char *result_hex)
{
	uint8_t resp[300];
	char hex[80];
	size_t result_len = strlen(result_hex) / 2;

	snprintf(hex, sizeof(hex), "80140000%02zx810301010182028281%s", 9 + result_len, result_hex);
	return transact_hex_apdu(ctx, hex, resp, sizeof(resp));
}

static void refresh_result_test(const char *name, const char *result_hex, int resends)
{
	struct ss_context *ctx = proactive_ctx();
	uint16_t sw;
	int i;

	rfm_clear_fplmn(ctx);
	sw = poll_and_status(ctx);
	printf("%s: STATUS after the file change: %04x\n", name, sw);
	fetch_refresh(ctx, sw);
	sw = terminal_response(ctx, result_hex);
	printf("%s: TERMINAL RESPONSE %s: %04x\n", name, result_hex, sw);
	assert(sw == 0x9000);

	for (i = 0; i < resends; i++) {
		sw = poll_and_status(ctx);
		printf("%s: STATUS, REFRESH sent again: %04x\n", name, sw);
		fetch_refresh(ctx, sw);
		sw = terminal_response(ctx, "830100");
		assert(sw == 0x9000);
	}
	sw = poll_and_status(ctx);
	printf("%s: STATUS, nothing pending: %04x\n", name, sw);
	assert(sw == 0x9000);

	ss_free_ctx(ctx);
}

static int sms_result = 1;

static void record_sms_result(struct ss_context *ctx, int rc)
{
	(void)ctx;
	sms_result = rc;
}

/* SEND SHORT MESSAGE answered "performed with partial comprehension" */
static void sms_partial_comprehension_test(void)
{
	struct ss_context *ctx = proactive_ctx();
	struct ss_sm_hdr sm_hdr;
	uint8_t tp_ud[] = { 0xc8, 0x22, 0x93, 0xf9, 0x64, 0x5d, 0x9f, 0x52, 0x26, 0x11 };
	uint8_t resp[300];
	char hex[32];
	uint16_t sw;
	int rc;

	memset(&sm_hdr, 0, sizeof(sm_hdr));
	sm_hdr.tp_mti = SMS_MTI_SUBMIT;
	sm_hdr.u.sms_submit.tp_da.extension = true;
	sm_hdr.u.sms_submit.tp_da.numbering_plan = 1;
	strcpy(sm_hdr.u.sms_submit.tp_da.digits, "23001");
	sm_hdr.u.sms_submit.tp_udl = sizeof(tp_ud) + 1;
	rc = ss_uicc_sms_tx(ctx, &sm_hdr, NULL, 0, tp_ud, sizeof(tp_ud), record_sms_result);
	assert(rc == 0);

	sw = transact_hex_apdu(ctx, "80f2000c00", resp, sizeof(resp));
	printf("sms: STATUS with the SEND SHORT MESSAGE pending: %04x\n", sw);
	assert((sw & 0xff00) == 0x9100);
	snprintf(hex, sizeof(hex), "80120000%02x", sw & 0xff);
	sw = transact_hex_apdu(ctx, hex, resp, sizeof(resp));
	assert(sw == 0x9000 && resp[5] == 0x13);

	sw = transact_hex_apdu(ctx, "801400000c810301130082028281830101", resp, sizeof(resp));
	printf("sms: TERMINAL RESPONSE 01: %04x, result reported to the sender: %d\n", sw, sms_result);
	assert(sw == 0x9000);
	assert(sms_result == 0);

	ss_free_ctx(ctx);
}

int main(void)
{
	refresh_result_test("additional EFs read", "830103", 0);
	refresh_result_test("terminal busy", "83022001", 1);
	refresh_result_test("beyond terminal capabilities", "830130", 0);
	sms_partial_comprehension_test();
	return 0;
}
