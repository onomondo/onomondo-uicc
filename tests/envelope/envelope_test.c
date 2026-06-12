/*
 * Copyright (c) 2024 Onomondo ApS. All rights reserved.
 *
 * SPDX-License-Identifier: GPL-3.0-only
 */

#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <onomondo/softsim/softsim.h>
#include <onomondo/softsim/utils.h>
extern uint32_t ss_log_mask;

static uint16_t transact_hex_apdu(struct ss_context *ctx, const char *hex, uint8_t *resp, size_t resp_bufsize,
				  size_t *out_resp_len)
{
	uint8_t cmd[300];
	size_t cmd_len = ss_binary_from_hexstr(cmd, sizeof(cmd), hex);
	size_t resp_len = ss_application_apdu_transact(ctx, resp, resp_bufsize, cmd, &cmd_len);
	if (out_resp_len)
		*out_resp_len = resp_len;
	if (resp_len >= 2)
		return (uint16_t)((resp[resp_len - 2] << 8) | resp[resp_len - 1]);
	return 0;
}

int main(void)
{
	struct ss_context *ctx;
	uint8_t resp[300];
	size_t resp_len;
	uint16_t sw;
	char *dump;

	ss_log_mask = 0;
	ctx = ss_new_ctx();
	ss_reset(ctx);
	ss_log_mask = 0;

	/* TERMINAL PROFILE — enable proactive SIM */
	sw = transact_hex_apdu(ctx, "8010000014ffffffffffffffffffffffffffffffffffffffff", resp, sizeof(resp),
			       &resp_len);
	printf("TERMINAL PROFILE: %04x\n", sw);
	assert(sw == 0x9000);

	/* ENVELOPE (SMS-PP download) — ss_application_apdu_transact handles the
	 * internal SW=61xx / GET RESPONSE loop; the proactive pending indicator
	 * SW=913F is returned after the loop, together with the OTA response. */
	sw = transact_hex_apdu(ctx,
			       "80c200005b"
			       "d15982028381860510426587f98b4c60039121437ff662408011"
			       "9342803d02700000381516393232b00011d5cbcbd7ad00edcae5"
			       "fb251618e04ed8502924dbad65b15be802a9d9e28267110d433c"
			       "06103268db6a2a9d618fe8ab74",
			       resp, sizeof(resp), &resp_len);
	dump = ss_hexdump(resp, resp_len >= 2 ? resp_len - 2 : 0);
	printf("ENVELOPE: %s %04x\n", dump, sw);
	assert(sw == 0x913f);

	/* FETCH — retrieve the proactive SEND SHORT MESSAGE command (63 bytes) */
	sw = transact_hex_apdu(ctx, "801200003f", resp, sizeof(resp), &resp_len);
	dump = ss_hexdump(resp, resp_len >= 2 ? resp_len - 2 : 0);
	printf("FETCH: %s %04x\n", dump, sw);
	assert(sw == 0x9000);

	/* TERMINAL RESPONSE — acknowledge successful SEND SHORT MESSAGE */
	sw = transact_hex_apdu(ctx, "801400000c810301130082028281830100", resp, sizeof(resp), &resp_len);
	printf("TERMINAL RESPONSE: %04x\n", sw);
	assert(sw == 0x9000);

	ss_free_ctx(ctx);
	return 0;
}
