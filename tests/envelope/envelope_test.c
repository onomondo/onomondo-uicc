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

/* The shipped TAR record mandates ciphering (MSL 0x06), which rejects an
 * unciphered command packet before the header is parsed. Relax it so the
 * cleartext header path becomes reachable. Patches the build-dir copy only. */
static void relax_tar_msl(void)
{
	FILE *f = fopen("files/3f00/a004", "r+");
	size_t written;
	int rc;

	assert(f);
	/* Records are stored as ASCII hex; MSL is byte 3 of struct tar_record.
	 * The seek and the write stay outside the asserts: NDEBUG drops the whole
	 * expression, and the patch has to happen for the test to mean anything. */
	rc = fseek(f, 6, SEEK_SET);
	assert(rc == 0);
	written = fwrite("00", 1, 2, f);
	assert(written == 2);
	fclose(f);
}

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

/* TERMINAL PROFILE (enable proactive SIM), then a valid single-part OTA
 * command packet through ENVELOPE, FETCH of the resulting proactive SEND
 * SHORT MESSAGE, and TERMINAL RESPONSE acknowledging it.
 * ss_application_apdu_transact handles the internal SW=61xx / GET RESPONSE
 * loop; the proactive pending indicator SW=913F is returned after the loop,
 * together with the OTA response. */
static void command_packet_test(void)
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

	sw = transact_hex_apdu(ctx, "8010000014ffffffffffffffffffffffffffffffffffffffff", resp, sizeof(resp),
			       &resp_len);
	printf("TERMINAL PROFILE: %04x\n", sw);
	assert(sw == 0x9000);

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
}

/* Unciphered command packet whose encrypted part is a single byte. The
 * CNTR/PCNTR header is 6 bytes, so it must be rejected on length before
 * anything reads it -- first under the shipped strict MSL, then again after
 * relax_tar_msl() makes the cleartext header path reachable. */
static void short_header_msl_test(void)
{
	struct ss_context *ctx;
	uint8_t resp[300];
	size_t resp_len;
	uint16_t sw;
	const char *short_hdr = "80c200002c"
				"d12a"
				"82028381"
				"860510426587f9"
				"8b1d"
				"60039121437ff6"
				"62408011934280"
				"0e"
				"027000"
				"00090d00010000b00011aa";

	ss_log_mask = 0;
	ctx = ss_new_ctx();
	ss_reset(ctx);
	ss_log_mask = 0;

	sw = transact_hex_apdu(ctx, short_hdr, resp, sizeof(resp), &resp_len);
	printf("ENVELOPE short header, strict MSL: %04x\n", sw);
	assert(sw == 0x6200);

	relax_tar_msl();
	sw = transact_hex_apdu(ctx, short_hdr, resp, sizeof(resp), &resp_len);
	printf("ENVELOPE short header, permissive MSL: %04x\n", sw);
	assert(sw == 0x6700);

	ss_free_ctx(ctx);
}

/* SMS-PP DOWNLOAD whose CAT template is nothing but 0xff padding. That
 * decodes to a valid but empty COMPREHENSION-TLV list, which is the case
 * ss_ctlv_free() used to return from without freeing the list head. The
 * status word is incidental; the point is that the sanitizer sees no leak. */
static void padding_only_template_test(void)
{
	struct ss_context *ctx;
	uint8_t resp[300];
	size_t resp_len;
	uint16_t sw;

	ss_log_mask = 0;
	ctx = ss_new_ctx();
	ss_reset(ctx);
	ss_log_mask = 0;

	sw = transact_hex_apdu(ctx, "80c2000005d103ffffff", resp, sizeof(resp), &resp_len);
	printf("ENVELOPE padding-only template: %04x\n", sw);
	assert(sw == 0x6a80);

	ss_free_ctx(ctx);
}

/* Same defect in ss_tlv8_free(): an SMS-DELIVER with TP-UDHI set and a
 * zero-length user data header decodes to a valid but empty TLV8 list. The
 * 6f00 is the dispatcher's mapping for the unknown IEIa=00 that follows; the
 * point is again that the sanitizer sees no leak. */
static void empty_user_data_header_test(void)
{
	struct ss_context *ctx;
	uint8_t resp[300];
	size_t resp_len;
	uint16_t sw;

	ss_log_mask = 0;
	ctx = ss_new_ctx();
	ss_reset(ctx);
	ss_log_mask = 0;

	sw = transact_hex_apdu(ctx,
			       "80c2000018" /* ENVELOPE, Lc=24 */
			       "d116" /* SMS-PP download CAT template */
			       "82028381" /* device identities: network -> UICC */
			       "8b10" /* SMS-TPDU IE, 16 bytes */
			       "60" /* SMS-DELIVER, TP-UDHI set */
			       "03912143" /* TP-OA */
			       "7ff6" /* TP-PID, TP-DCS */
			       "62408011934280" /* TP-SCTS */
			       "01" /* TP-UDL = 1 */
			       "00", /* TP-UD: UDHL = 0 */
			       resp, sizeof(resp), &resp_len);
	printf("ENVELOPE empty user data header: %04x\n", sw);
	assert(sw == 0x6f00);

	ss_free_ctx(ctx);
}

/* Part 1 of a concatenated SM without the CPI IE must be rejected
 * immediately, without buffering anything -- TS 23.048 puts the CPI IE only
 * on part 1 of a concatenation; uicc_sms_rx used to check whichever part
 * happened to complete reassembly instead. Doesn't need relax_tar_msl():
 * rejection happens before the message is ever reassembled, let alone
 * reaches crypto validation. */
static void concat_sm_missing_cpi_test(void)
{
	struct ss_context *ctx;
	uint8_t resp[300];
	size_t resp_len;
	uint16_t sw;

	ss_log_mask = 0;
	ctx = ss_new_ctx();
	ss_reset(ctx);
	ss_log_mask = 0;

	sw = transact_hex_apdu(ctx,
			       "80c2000029" /* ENVELOPE, Lc=41 */
			       "d127" /* SMS-PP download CAT template */
			       "82028381" /* device identities: network -> UICC */
			       "860510426587f9" /* address */
			       "8b1a" /* SMS-TPDU IE, 26 bytes */
			       "60" /* SMS-DELIVER, TP-UDHI set */
			       "03912143" /* TP-OA */
			       "7ff6" /* TP-PID, TP-DCS */
			       "62408011934280" /* TP-SCTS */
			       "0b" /* TP-UDL = 11 */
			       "05" /* TP-UD: UDHL = 5 */
			       "0003" "0602" "01" /* concat SM IE: ref=06, parts=2, part=1 -- no CPI IE */
			       "00090d0001", /* part 1 payload (5 of 11 bytes) */
			       resp, sizeof(resp), &resp_len);
	printf("ENVELOPE concatenated SM, part 1 without CPI: %04x\n", sw);
	assert(sw == 0x6a80);

	ss_free_ctx(ctx);
}

/* Part 1 with CPI, followed by part 2, must reassemble byte-for-byte and
 * reach the same crypto validation as the single-part short header case in
 * short_header_msl_test() (11 bytes, rejected on length before any
 * CNTR/crypto state is touched -- split across two SM parts here, so
 * resending it doesn't collide with anti-replay state). Relaxes the TAR MSL
 * itself (idempotent) so the completing part reaches the same
 * permissive-MSL validation (0x6700), independent of whether
 * short_header_msl_test() already ran. */
static void concat_sm_reassembly_test(void)
{
	struct ss_context *ctx;
	uint8_t resp[300];
	size_t resp_len;
	uint16_t sw;

	ss_log_mask = 0;
	ctx = ss_new_ctx();
	ss_reset(ctx);
	ss_log_mask = 0;

	relax_tar_msl();

	sw = transact_hex_apdu(ctx,
			       "80c200002b" /* ENVELOPE, Lc=43 */
			       "d129" /* SMS-PP download CAT template */
			       "82028381"
			       "860510426587f9"
			       "8b1c" /* SMS-TPDU IE, 28 bytes */
			       "60"
			       "03912143"
			       "7ff6"
			       "62408011934280"
			       "0d" /* TP-UDL = 13 */
			       "07" /* TP-UD: UDHL = 7 */
			       "7000" /* CPI IE, part 1 only */
			       "0003" "0502" "01" /* concat SM IE: ref=05, parts=2, part=1 */
			       "00090d0001", /* part 1 payload */
			       resp, sizeof(resp), &resp_len);
	printf("ENVELOPE concatenated SM, part 1 with CPI: %04x\n", sw);
	assert(sw == 0x9000);

	sw = transact_hex_apdu(ctx,
			       "80c200002a" /* ENVELOPE, Lc=42 */
			       "d128"
			       "82028381"
			       "860510426587f9"
			       "8b1b" /* SMS-TPDU IE, 27 bytes */
			       "60"
			       "03912143"
			       "7ff6"
			       "62408011934280"
			       "0c" /* TP-UDL = 12 */
			       "05" /* TP-UD: UDHL = 5 */
			       "0003" "0502" "02" /* concat SM IE: ref=05, parts=2, part=2 */
			       "0000b00011aa", /* part 2 payload, completes the message */
			       resp, sizeof(resp), &resp_len);
	printf("ENVELOPE concatenated SM, part 2 completes: %04x\n", sw);
	assert(sw == 0x6700);

	ss_free_ctx(ctx);
}

int main(void)
{
	command_packet_test();
	short_header_msl_test();
	padding_only_template_test();
	empty_user_data_header_test();
	concat_sm_missing_cpi_test();
	concat_sm_reassembly_test();

	return 0;
}
