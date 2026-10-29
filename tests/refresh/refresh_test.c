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
#include "src/softsim/uicc/proactive.h"
extern uint32_t ss_log_mask;

#define RFM_FPLMN "00a4000c026f7b00d600000c02f810ffffffffffffffffff"
#define RFM_LOCI "00a4000c026f7e00d600000bffffffffffffff0000ff01"
#define RFM_IMSI "00a4000c026f0700d6000009080910100000000010"
#define TR_REFRESH_OK "801400000c810301010182028281830100"
#define TR_REFRESH_BUSY "801400000d81030101018202828183022001"
#define TR_SEND_SM_OK "801400000c810301130082028281830100"
#define FETCHED_FPLMN "d0128103010101820281829207013f007fff6f7b"
#define FETCHED_LOCI "d0128103010101820281829207013f007fff6f7e"
#define FETCHED_UICC_RESET "d009810301010482028182"
#define TERMINAL_PROFILE "8010000014ffffffffffffffffffffffffffffffffffffffff"
#define TERMINAL_PROFILE_NO_REFRESH "8010000014ffff7fffffffffffffffffffffffffffffffffff"

/* The shipped TAR record mandates ciphering (MSL 0x06); relax it so the unciphered, unsigned packets below
 * are accepted. Patches the build-dir copy only; records are stored as ASCII hex and MSL is byte 3. */
static void relax_tar_msl(void)
{
	FILE *f = fopen("files/3f00/a004", "r+");
	size_t written;
	int rc;

	assert(f);
	rc = fseek(f, 6, SEEK_SET);
	assert(rc == 0);
	written = fwrite("00", 1, 2, f);
	assert(written == 2);
	fclose(f);
}

static uint16_t transact(struct ss_context *ctx, uint8_t *cmd, size_t cmd_len, uint8_t *resp, size_t *resp_len)
{
	size_t len = cmd_len;

	*resp_len = ss_application_apdu_transact(ctx, resp, 300, cmd, &len);
	assert(*resp_len >= 2);
	return (uint16_t)((resp[*resp_len - 2] << 8) | resp[*resp_len - 1]);
}

static uint16_t transact_hex(struct ss_context *ctx, const char *hex, uint8_t *resp, size_t *resp_len)
{
	uint8_t cmd[300];
	size_t cmd_len = ss_binary_from_hexstr(cmd, sizeof(cmd), hex);

	return transact(ctx, cmd, cmd_len, resp, resp_len);
}

/* FETCH the pending proactive command, sized from the 91xx status word */
static uint16_t fetch_quiet(struct ss_context *ctx, uint16_t sw_pending, uint8_t *resp, size_t *resp_len)
{
	uint8_t cmd[] = { 0x80, 0x12, 0x00, 0x00, sw_pending & 0xff };

	assert((sw_pending & 0xff00) == 0x9100);
	return transact(ctx, cmd, sizeof(cmd), resp, resp_len);
}

static void fetch(struct ss_context *ctx, uint16_t sw_pending, uint8_t *resp, size_t *resp_len)
{
	uint16_t sw = fetch_quiet(ctx, sw_pending, resp, resp_len);

	printf("FETCH: %s %04x\n", ss_hexdump(resp, *resp_len - 2), sw);
	assert(sw == 0x9000);
}

static void assert_fetched(const uint8_t *resp, size_t resp_len, const char *expected_hex)
{
	uint8_t expected[64];
	size_t expected_len = ss_binary_from_hexstr(expected, sizeof(expected), expected_hex);

	assert(resp_len == expected_len + 2);
	assert(memcmp(resp, expected, expected_len) == 0);
}

static uint16_t poll_and_status(struct ss_context *ctx, uint8_t *resp, size_t *resp_len)
{
	ss_poll(ctx);
	return transact_hex(ctx, "80f2000c00", resp, resp_len);
}

/* ENVELOPE (SMS-PP DOWNLOAD) with an unciphered, unsigned packet of compact C-APDUs for TAR B00011 (ADF.USIM).
 * SPI2 01 asks for the PoR in the reply, 21 by SMS-SUBMIT; part 1 or 2 is that half of a concatenated SMS. */
static size_t build_envelope_rfm(uint8_t *cmd, const char *apdus_hex, uint8_t spi2, int part)
{
	uint8_t apdus[128];
	size_t apdus_len = ss_binary_from_hexstr(apdus, sizeof(apdus), apdus_hex);
	uint8_t packet[160];
	size_t packet_len = 0, from = 0, to;
	size_t n = 0;
	const uint8_t tpdu_hdr[] = { 0x60, /* SMS-DELIVER, TP-UDHI set */
				     0x03, 0x91, 0x21, 0x43, /* TP-OA */
				     0x7f, 0xf6, /* TP-PID, TP-DCS */
				     0x62, 0x40, 0x80, 0x11, 0x93, 0x42, 0x80 /* TP-SCTS */ };
	const uint8_t udh_single[] = { 0x02, 0x70, 0x00 }; /* command packet identifier */
	const uint8_t udh_part1[] = { 0x07, 0x00, 0x03, 0x05, 0x02, 0x01, 0x70, 0x00 }; /* concat ref 5, 1 of 2 */
	const uint8_t udh_part2[] = { 0x05, 0x00, 0x03, 0x05, 0x02, 0x02 };
	const uint8_t *udh = part == 1 ? udh_part1 : part == 2 ? udh_part2 : udh_single;
	size_t udh_len = part == 1 ? sizeof(udh_part1) : part == 2 ? sizeof(udh_part2) : sizeof(udh_single);
	size_t cpl = 14 + apdus_len; /* CHL through PCNTR, then the commands */
	size_t ud_len, tpdu_len;

	/* The command packet: CPL, header, commands */
	packet[packet_len++] = cpl >> 8;
	packet[packet_len++] = cpl & 0xff;
	packet[packet_len++] = 0x0d; /* CHL */
	packet[packet_len++] = 0x00; /* SPI1: no security, counter ignored */
	packet[packet_len++] = spi2;
	packet[packet_len++] = 0x00; /* KIc */
	packet[packet_len++] = 0x00; /* KID */
	packet[packet_len++] = 0xb0; /* TAR: SIM file system, ADF.USIM preselected */
	packet[packet_len++] = 0x00;
	packet[packet_len++] = 0x11;
	memset(&packet[packet_len], 0, 5); /* CNTR */
	packet_len += 5;
	packet[packet_len++] = 0x00; /* PCNTR */
	memcpy(&packet[packet_len], apdus, apdus_len);
	packet_len += apdus_len;

	to = packet_len;
	if (part == 1)
		to = packet_len / 2;
	else if (part == 2)
		from = packet_len / 2;
	ud_len = udh_len + (to - from);
	tpdu_len = sizeof(tpdu_hdr) + 1 + ud_len;
	assert(tpdu_len + 8 < 0x80); /* single-byte lengths throughout */

	cmd[n++] = 0x80;
	cmd[n++] = 0xc2;
	cmd[n++] = 0x00;
	cmd[n++] = 0x00;
	cmd[n++] = 2 + 4 + 2 + tpdu_len; /* Lc */
	cmd[n++] = 0xd1; /* SMS-PP download CAT template */
	cmd[n++] = 4 + 2 + tpdu_len;
	cmd[n++] = 0x82; /* device identities: network -> UICC */
	cmd[n++] = 0x02;
	cmd[n++] = 0x83;
	cmd[n++] = 0x81;
	cmd[n++] = 0x8b; /* SMS-TPDU */
	cmd[n++] = tpdu_len;
	memcpy(&cmd[n], tpdu_hdr, sizeof(tpdu_hdr));
	n += sizeof(tpdu_hdr);
	cmd[n++] = ud_len; /* TP-UDL */
	memcpy(&cmd[n], udh, udh_len);
	n += udh_len;
	memcpy(&cmd[n], &packet[from], to - from);
	n += to - from;
	return n;
}

static uint16_t envelope_rfm(struct ss_context *ctx, const char *apdus_hex, uint8_t spi2, uint8_t *resp,
			     size_t *resp_len)
{
	uint8_t cmd[300];
	size_t n = build_envelope_rfm(cmd, apdus_hex, spi2, 0);

	return transact(ctx, cmd, n, resp, resp_len);
}

static struct ss_context *new_ctx_with_terminal_profile(const char *profile_hex)
{
	struct ss_context *ctx;
	uint8_t resp[300];
	size_t resp_len;
	uint16_t sw;

	ctx = ss_new_ctx();
	ss_reset(ctx);

	sw = transact_hex(ctx, profile_hex, resp, &resp_len);
	assert(sw == 0x9000);
	return ctx;
}

static struct ss_context *new_ctx_with_profile(void)
{
	return new_ctx_with_terminal_profile(TERMINAL_PROFILE);
}

/* A file the RFM updated is announced by a REFRESH File Change Notification in the very reply with the PoR,
 * from the UICC to the terminal (TS 102 223 clause 10), naming the file under the ADF as '3F007FFF' (8.18). */
static void file_change_test(void)
{
	struct ss_context *ctx = new_ctx_with_profile();
	uint8_t resp[300];
	size_t resp_len;
	uint16_t sw;

	sw = envelope_rfm(ctx, RFM_FPLMN, 0x01, resp, &resp_len);
	printf("ENVELOPE update EF.FPLMN: %04x\n", sw);
	assert(sw == 0x9114);

	fetch(ctx, sw, resp, &resp_len);
	assert_fetched(resp, resp_len, FETCHED_FPLMN);

	sw = transact_hex(ctx, TR_REFRESH_OK, resp, &resp_len);
	printf("TERMINAL RESPONSE: %04x\n", sw);
	assert(sw == 0x9000);

	ss_free_ctx(ctx);
}

/* A changed EF.IMSI is refreshed with a UICC Reset (TS 31.111 6.4.7.1), which
 * the terminal answers with a reset instead of a TERMINAL RESPONSE. */
static void imsi_change_test(void)
{
	struct ss_context *ctx = new_ctx_with_profile();
	uint8_t resp[300];
	size_t resp_len;
	uint16_t sw;

	sw = envelope_rfm(ctx, RFM_IMSI, 0x01, resp, &resp_len);
	printf("ENVELOPE update EF.IMSI: %04x\n", sw);
	assert(sw == 0x910b);

	fetch(ctx, sw, resp, &resp_len);
	assert_fetched(resp, resp_len, FETCHED_UICC_RESET);

	ss_free_ctx(ctx);
}

/* With the PoR sent by SMS-SUBMIT, the REFRESH follows the TERMINAL RESPONSE
 * that reports the PoR sent. */
static void por_by_sms_test(void)
{
	struct ss_context *ctx = new_ctx_with_profile();
	uint8_t resp[300];
	size_t resp_len;
	uint16_t sw;

	sw = envelope_rfm(ctx, RFM_FPLMN, 0x21, resp, &resp_len);
	printf("ENVELOPE update EF.FPLMN, PoR by SMS: %04x\n", sw);
	assert((sw & 0xff00) == 0x9100);

	fetch(ctx, sw, resp, &resp_len);
	assert(resp[5] == 0x13);

	sw = transact_hex(ctx, TR_SEND_SM_OK, resp, &resp_len);
	printf("TERMINAL RESPONSE (SEND SHORT MESSAGE): %04x\n", sw);
	assert(sw == 0x9114);

	fetch(ctx, sw, resp, &resp_len);
	assert_fetched(resp, resp_len, FETCHED_FPLMN);

	sw = transact_hex(ctx, TR_REFRESH_OK, resp, &resp_len);
	printf("TERMINAL RESPONSE (REFRESH): %04x\n", sw);
	assert(sw == 0x9000);

	ss_free_ctx(ctx);
}

/* A change list of n EFs under the ADF, as ss_fs_chg_add() records them:
 * the count, each path from the MF, and the 3F00 that ends the last one. */
static void synthetic_changes(struct ss_context *ctx, unsigned int n)
{
	uint8_t *p = ctx->fs_chg_filelist;
	unsigned int i;

	assert(n > 0 && n < 100);
	*p++ = n;
	for (i = 0; i < n; i++) {
		const uint8_t path[] = { 0x3f, 0x00, 0x7f, 0xff, 0x6f, 0x80 + i };

		memcpy(p, path, sizeof(path));
		p += sizeof(path);
	}
	*p++ = 0x3f;
	*p = 0x00;
}

/* A reset is also how the terminal answers a UICC Reset REFRESH, and it reads every file again afterwards:
 * changes still waiting behind a PoR SMS are not announced after it. */
static void reset_drops_pending_changes_test(void)
{
	struct ss_context *ctx = new_ctx_with_profile();
	uint8_t resp[300];
	size_t resp_len;
	uint16_t sw;

	sw = envelope_rfm(ctx, RFM_FPLMN, 0x21, resp, &resp_len);
	printf("ENVELOPE with the REFRESH deferred: %04x\n", sw);
	assert((sw & 0xff00) == 0x9100);

	ss_reset(ctx);
	sw = transact_hex(ctx, TERMINAL_PROFILE, resp, &resp_len);
	assert(sw == 0x9000);
	sw = poll_and_status(ctx, resp, &resp_len);
	printf("STATUS after a reset: %04x\n", sw);
	assert(sw == 0x9000);

	ss_free_ctx(ctx);
}

/* A File Change Notification names at most 39 files under the ADF within the 255 bytes a proactive command
 * may have; with more the terminal is told to read every file again (mode 00) instead of nothing at all. */
static void long_list_test(void)
{
	static const unsigned int counts[] = { 39, 40, 99 };
	uint8_t resp[300];
	size_t resp_len;
	uint16_t sw;
	size_t i, o;

	for (i = 0; i < SS_ARRAY_SIZE(counts); i++) {
		struct ss_context *ctx = new_ctx_with_profile();

		synthetic_changes(ctx, counts[i]);
		sw = poll_and_status(ctx, resp, &resp_len);
		sw = fetch_quiet(ctx, sw, resp, &resp_len);
		/* Command details follow the one- or two-byte BER-TLV length */
		o = resp[1] & 0x80 ? 3 : 2;
		assert(sw == 0x9000 && resp[o] == 0x81 && resp[o + 1] == 0x03 && resp[o + 3] == 0x01);
		printf("%u changed files: REFRESH mode %02x, %zu bytes\n", counts[i], resp[o + 4], resp_len - 2);
		if (counts[i] <= 39) {
			assert(resp[o + 4] == 0x01 && resp_len - 2 == 250);
			sw = transact_hex(ctx, TR_REFRESH_OK, resp, &resp_len);
		} else {
			assert_fetched(resp, resp_len, "d009810301010082028182");
			sw = transact_hex(ctx, "801400000c810301010082028281830100", resp, &resp_len);
		}
		assert(sw == 0x9000);
		sw = poll_and_status(ctx, resp, &resp_len);
		printf("STATUS after the REFRESH: %04x\n", sw);
		assert(sw == 0x9000);
		ss_free_ctx(ctx);
	}
}

/* A second RFM while the first REFRESH is still unfetched: the reply announces the pending command again
 * (TS 102 221, 7.4.2), and the second file follows in a REFRESH of its own once the first was answered. */
static void second_rfm_while_unfetched_test(void)
{
	struct ss_context *ctx = new_ctx_with_profile();
	uint8_t resp[300];
	size_t resp_len;
	uint16_t sw;

	sw = envelope_rfm(ctx, RFM_FPLMN, 0x01, resp, &resp_len);
	assert(sw == 0x9114);
	sw = envelope_rfm(ctx, RFM_LOCI, 0x01, resp, &resp_len);
	printf("second ENVELOPE with the first REFRESH unfetched: %04x\n", sw);
	assert(sw == 0x9114);

	fetch(ctx, sw, resp, &resp_len);
	assert_fetched(resp, resp_len, FETCHED_FPLMN);
	sw = transact_hex(ctx, TR_REFRESH_OK, resp, &resp_len);
	assert(sw == 0x9000);
	sw = poll_and_status(ctx, resp, &resp_len);
	printf("STATUS after the first REFRESH: %04x\n", sw);
	fetch(ctx, sw, resp, &resp_len);
	assert_fetched(resp, resp_len, FETCHED_LOCI);
	sw = transact_hex(ctx, TR_REFRESH_OK, resp, &resp_len);
	assert(sw == 0x9000);
	sw = poll_and_status(ctx, resp, &resp_len);
	assert(sw == 0x9000);

	ss_free_ctx(ctx);
}

/* A second RFM while the first REFRESH waits behind a PoR SMS: both files go out in the one REFRESH that
 * follows that SEND SHORT MESSAGE, and the second PoR SMS follows the REFRESH. */
static void second_rfm_while_deferred_test(void)
{
	struct ss_context *ctx = new_ctx_with_profile();
	uint8_t resp[300];
	size_t resp_len;
	uint16_t sw;

	sw = envelope_rfm(ctx, RFM_FPLMN, 0x21, resp, &resp_len);
	assert(sw == 0x9129);
	sw = envelope_rfm(ctx, RFM_LOCI, 0x21, resp, &resp_len);
	printf("second ENVELOPE with the REFRESH deferred: %04x\n", sw);
	assert(sw == 0x9129);

	fetch(ctx, sw, resp, &resp_len);
	assert(resp[5] == 0x13);
	sw = transact_hex(ctx, TR_SEND_SM_OK, resp, &resp_len);
	printf("TERMINAL RESPONSE (first PoR SMS): %04x\n", sw);
	assert(sw == 0x911a);
	fetch(ctx, sw, resp, &resp_len);
	assert_fetched(resp, resp_len, "d018810301010182028182920d023f007fff6f7b3f007fff6f7e");
	sw = transact_hex(ctx, TR_REFRESH_OK, resp, &resp_len);
	assert(sw == 0x9000);

	sw = poll_and_status(ctx, resp, &resp_len);
	printf("STATUS after the REFRESH: %04x\n", sw);
	assert(sw == 0x9129);
	fetch(ctx, sw, resp, &resp_len);
	assert(resp[5] == 0x13);
	sw = transact_hex(ctx, TR_SEND_SM_OK, resp, &resp_len);
	assert(sw == 0x9000);
	sw = poll_and_status(ctx, resp, &resp_len);
	assert(sw == 0x9000);

	ss_free_ctx(ctx);
}

/* STATUS announces a pending REFRESH until it is fetched and never again
 * afterwards (TS 102 221, 14.6.2). */
static void status_interleaved_test(void)
{
	struct ss_context *ctx = new_ctx_with_profile();
	uint8_t resp[300];
	size_t resp_len;
	uint16_t sw;

	sw = envelope_rfm(ctx, RFM_FPLMN, 0x01, resp, &resp_len);
	assert(sw == 0x9114);
	sw = transact_hex(ctx, "80f2000000", resp, &resp_len);
	printf("STATUS P2=00 with a REFRESH pending: %04x\n", sw);
	assert(sw == 0x9114);
	sw = transact_hex(ctx, "80f2000c00", resp, &resp_len);
	assert(sw == 0x9114);
	fetch(ctx, sw, resp, &resp_len);
	sw = transact_hex(ctx, "80f2000c00", resp, &resp_len);
	printf("STATUS with the REFRESH fetched: %04x\n", sw);
	assert(sw == 0x9000);
	sw = transact_hex(ctx, TR_REFRESH_OK, resp, &resp_len);
	assert(sw == 0x9000);
	sw = poll_and_status(ctx, resp, &resp_len);
	assert(sw == 0x9000);

	ss_free_ctx(ctx);
}

/* A concatenated RFM arriving while a REFRESH is unfetched: its parts are answered with the pending
 * announcement, the script runs when the second part completes it, and its file follows in the next REFRESH. */
static void concat_during_unfetched_test(void)
{
	struct ss_context *ctx = new_ctx_with_profile();
	uint8_t cmd[300];
	uint8_t resp[300];
	size_t resp_len, n;
	uint16_t sw;

	sw = envelope_rfm(ctx, RFM_FPLMN, 0x01, resp, &resp_len);
	assert(sw == 0x9114);
	n = build_envelope_rfm(cmd, RFM_LOCI, 0x01, 1);
	sw = transact(ctx, cmd, n, resp, &resp_len);
	printf("ENVELOPE concatenated part 1: %04x\n", sw);
	assert(sw == 0x9114);
	sw = transact_hex(ctx, "80f2000c00", resp, &resp_len);
	assert(sw == 0x9114);
	n = build_envelope_rfm(cmd, RFM_LOCI, 0x01, 2);
	sw = transact(ctx, cmd, n, resp, &resp_len);
	printf("ENVELOPE concatenated part 2: %04x\n", sw);
	assert(sw == 0x9114);

	fetch(ctx, sw, resp, &resp_len);
	assert_fetched(resp, resp_len, FETCHED_FPLMN);
	sw = transact_hex(ctx, TR_REFRESH_OK, resp, &resp_len);
	assert(sw == 0x9000);
	sw = poll_and_status(ctx, resp, &resp_len);
	fetch(ctx, sw, resp, &resp_len);
	assert_fetched(resp, resp_len, FETCHED_LOCI);
	sw = transact_hex(ctx, TR_REFRESH_OK, resp, &resp_len);
	assert(sw == 0x9000);

	ss_free_ctx(ctx);
}

/* An announced command the terminal never fetches is kept (the terminal
 * has to FETCH it, TS 102 223, 6.3); only a reset clears it. */
static void never_fetched_test(void)
{
	struct ss_context *ctx = new_ctx_with_profile();
	uint8_t resp[300];
	size_t resp_len;
	uint16_t sw;
	int i;

	sw = envelope_rfm(ctx, RFM_FPLMN, 0x01, resp, &resp_len);
	assert(sw == 0x9114);
	for (i = 0; i < 40; i++)
		ss_poll(ctx);
	sw = transact_hex(ctx, "80f2000c00", resp, &resp_len);
	printf("STATUS after 40 polls without a FETCH: %04x\n", sw);
	assert(sw == 0x9114);

	ss_reset(ctx);
	sw = transact_hex(ctx, TERMINAL_PROFILE, resp, &resp_len);
	assert(sw == 0x9000);
	sw = poll_and_status(ctx, resp, &resp_len);
	printf("STATUS after a reset: %04x\n", sw);
	assert(sw == 0x9000);

	ss_free_ctx(ctx);
}

/* A REFRESH whose TERMINAL RESPONSE is lost, busy or without a readable RESULT goes out three more times,
 * then the card gives up; the next RFM starts afresh with its own retries. */
static void retry_exhaustion_test(void)
{
	static const struct {
		const char *tr; /* NULL: the TERMINAL RESPONSE never comes */
		const char *what;
	} failures[] = {
		{ NULL, "a lost TERMINAL RESPONSE" },
		{ TR_REFRESH_BUSY, "busy response" },
		{ "8014000009810301010182028281", "a TERMINAL RESPONSE without RESULT" },
		{ "8014000003810301", "a truncated TERMINAL RESPONSE" },
	};
	struct ss_context *ctx = new_ctx_with_profile();
	uint8_t resp[300];
	size_t resp_len;
	uint16_t sw;
	size_t i;
	int k;

	sw = envelope_rfm(ctx, RFM_FPLMN, 0x01, resp, &resp_len);
	assert(sw == 0x9114);
	for (i = 0; i < SS_ARRAY_SIZE(failures); i++) {
		fetch_quiet(ctx, sw, resp, &resp_len);
		assert_fetched(resp, resp_len, FETCHED_FPLMN);
		if (failures[i].tr) {
			sw = transact_hex(ctx, failures[i].tr, resp, &resp_len);
			assert(sw == 0x9000);
		} else {
			/* the 31st poll gives up waiting, the next one queues the REFRESH again */
			for (k = 0; k < 31; k++)
				ss_poll(ctx);
		}
		sw = poll_and_status(ctx, resp, &resp_len);
		printf("STATUS after %s: %04x\n", failures[i].what, sw);
		assert(sw == (i < 3 ? 0x9114 : 0x9000));
	}

	sw = envelope_rfm(ctx, RFM_FPLMN, 0x01, resp, &resp_len);
	assert(sw == 0x9114);
	fetch_quiet(ctx, sw, resp, &resp_len);
	assert_fetched(resp, resp_len, FETCHED_FPLMN);
	sw = transact_hex(ctx, "801400000b8103010101820282818300", resp, &resp_len);
	assert(sw == 0x9000);
	sw = poll_and_status(ctx, resp, &resp_len);
	printf("STATUS, empty RESULT after a fresh RFM: %04x\n", sw);
	assert(sw == 0x9114);
	fetch_quiet(ctx, sw, resp, &resp_len);
	assert_fetched(resp, resp_len, FETCHED_FPLMN);
	sw = transact_hex(ctx, TR_REFRESH_OK, resp, &resp_len);
	assert(sw == 0x9000);
	sw = poll_and_status(ctx, resp, &resp_len);
	assert(sw == 0x9000);

	ss_free_ctx(ctx);
}

/* Without REFRESH in the TERMINAL PROFILE the changes are dropped (TS 102
 * 223, 6.2); without any TERMINAL PROFILE nothing is ever announced. */
static void no_refresh_support_test(void)
{
	struct ss_context *ctx = new_ctx_with_terminal_profile(TERMINAL_PROFILE_NO_REFRESH);
	uint8_t resp[300];
	size_t resp_len;
	uint16_t sw;

	sw = envelope_rfm(ctx, RFM_FPLMN, 0x01, resp, &resp_len);
	printf("ENVELOPE, TERMINAL PROFILE without REFRESH: %04x\n", sw);
	assert(sw == 0x9000 && ctx->fs_chg_filelist[0] == 0);
	sw = poll_and_status(ctx, resp, &resp_len);
	assert(sw == 0x9000);
	ss_free_ctx(ctx);

	ctx = ss_new_ctx();
	ss_reset(ctx);
	sw = envelope_rfm(ctx, RFM_FPLMN, 0x01, resp, &resp_len);
	printf("ENVELOPE without a TERMINAL PROFILE: %04x\n", sw);
	assert((sw & 0xff00) != 0x9100);
	sw = transact_hex(ctx, "80f2000c00", resp, &resp_len);
	printf("STATUS without a TERMINAL PROFILE: %04x\n", sw);
	assert((sw & 0xff00) != 0x9100);
	ss_free_ctx(ctx);
}

/* On the T=0 path the ENVELOPE reply with the PoR is announced with '61 XX'
 * and the pending REFRESH rides on the GET RESPONSE (TS 102 221, 7.3.1.1.5). */
static void t0_path_test(void)
{
	struct ss_context *ctx = new_ctx_with_profile();
	uint8_t cmd[300];
	uint8_t resp[300];
	size_t n, len;
	uint16_t sw;

	n = build_envelope_rfm(cmd, RFM_FPLMN, 0x01, 0);
	len = ss_transact(ctx, resp, 300, cmd, &n);
	sw = (resp[len - 2] << 8) | resp[len - 1];
	printf("ENVELOPE on T=0: %04x\n", sw);
	assert((sw & 0xff00) == 0x6100);

	n = ss_binary_from_hexstr(cmd, sizeof(cmd), "00c0000000");
	cmd[4] = sw & 0xff;
	len = ss_transact(ctx, resp, 300, cmd, &n);
	sw = (resp[len - 2] << 8) | resp[len - 1];
	printf("GET RESPONSE: %zu bytes, %04x\n", len - 2, sw);
	assert(sw == 0x9114 && len - 2 == cmd[4]);

	n = ss_binary_from_hexstr(cmd, sizeof(cmd), "8012000014");
	len = ss_transact(ctx, resp, 300, cmd, &n);
	assert_fetched(resp, len, FETCHED_FPLMN);
	n = ss_binary_from_hexstr(cmd, sizeof(cmd), TR_REFRESH_OK);
	len = ss_transact(ctx, resp, 300, cmd, &n);
	sw = (resp[len - 2] << 8) | resp[len - 1];
	printf("TERMINAL RESPONSE on T=0: %04x\n", sw);
	assert(sw == 0x9000);

	ss_free_ctx(ctx);
}

/* A reset while the REFRESH waits for its TERMINAL RESPONSE is that
 * response (TS 102 223, 6.4.7): nothing is left over. */
static void reset_while_fetched_test(void)
{
	struct ss_context *ctx = new_ctx_with_profile();
	uint8_t resp[300];
	size_t resp_len;
	uint16_t sw;

	sw = envelope_rfm(ctx, RFM_FPLMN, 0x01, resp, &resp_len);
	fetch_quiet(ctx, sw, resp, &resp_len);
	ss_reset(ctx);
	sw = transact_hex(ctx, TERMINAL_PROFILE, resp, &resp_len);
	sw = poll_and_status(ctx, resp, &resp_len);
	printf("STATUS after a reset with the REFRESH fetched: %04x\n", sw);
	assert(sw == 0x9000);
	assert(ctx->proactive.refresh_state.state == SS_REFRESH_READY &&
	       ctx->proactive.refresh_state.retry_counter == 0);

	ss_free_ctx(ctx);
}

/* One script writing a file twice lists it once, an MF-level file as
 * '3F00 2FXX'; a changed EF.IMSI turns the whole lot into a UICC Reset. */
static void many_files_test(void)
{
	struct ss_context *ctx = new_ctx_with_profile();
	uint8_t resp[300];
	size_t resp_len;
	uint16_t sw;

	sw = envelope_rfm(ctx,
			  "00a4000c026f7b00d600000cffffffffffffffffffffffff00d600000cffffffffffffffffffffffff"
			  "00a4000c023f0000a4000c022f0500d600000affffffffffffffffffff",
			  0x01, resp, &resp_len);
	printf("ENVELOPE updating EF.FPLMN twice and EF.PL: %04x\n", sw);
	assert(sw == 0x9118);
	fetch(ctx, sw, resp, &resp_len);
	assert_fetched(resp, resp_len, "d016810301010182028182920b023f007fff6f7b3f002f05");
	sw = transact_hex(ctx, TR_REFRESH_OK, resp, &resp_len);
	assert(sw == 0x9000);

	sw = envelope_rfm(ctx, "00a4000c026f7b00d600000cffffffffffffffffffffffff" RFM_IMSI, 0x01, resp, &resp_len);
	printf("ENVELOPE updating EF.FPLMN and EF.IMSI: %04x\n", sw);
	assert(sw == 0x910b);
	fetch(ctx, sw, resp, &resp_len);
	assert_fetched(resp, resp_len, FETCHED_UICC_RESET);

	ss_free_ctx(ctx);
}

/* Random RFM, STATUS, FETCH, TERMINAL RESPONSE, poll and reset steps from a
 * seed; every hundred steps the card must settle with nothing to announce. */
static uint32_t lcg(uint32_t *seed)
{
	*seed = *seed * 1103515245u + 12345u;
	return (*seed >> 8) & 0xffffff;
}

static void settle(struct ss_context *ctx)
{
	uint8_t resp[300];
	size_t resp_len;
	uint16_t sw;
	int quiet = 0, rounds = 0;

	/* A fetched command the terminal never answered times out after 30
	 * polls and comes back; only after that many quiet polls is the card done. */
	while (quiet < 32) {
		sw = poll_and_status(ctx, resp, &resp_len);
		if ((sw & 0xff00) == 0x9100) {
			fetch_quiet(ctx, sw, resp, &resp_len);
			sw = transact_hex(ctx, resp[5] == 0x13 ? TR_SEND_SM_OK : TR_REFRESH_OK, resp, &resp_len);
			quiet = 0;
		} else {
			quiet++;
		}
		assert(++rounds < 400);
	}
	assert(ctx->proactive.refresh_state.state == SS_REFRESH_READY);
	assert(ctx->proactive.refresh_state.retry_counter == 0);
	assert(ctx->fs_chg_filelist[0] == 0);
	assert(ss_proactive_rts(ctx));

	sw = envelope_rfm(ctx, RFM_FPLMN, 0x01, resp, &resp_len);
	assert(sw == 0x9114);
	fetch_quiet(ctx, sw, resp, &resp_len);
	assert_fetched(resp, resp_len, FETCHED_FPLMN);
	sw = transact_hex(ctx, TR_REFRESH_OK, resp, &resp_len);
	assert(sw == 0x9000);
	sw = poll_and_status(ctx, resp, &resp_len);
	assert(sw == 0x9000);
}

static void soak_test(uint32_t seed)
{
	struct ss_context *ctx = new_ctx_with_profile();
	const uint32_t start = seed;
	static const char *responses[] = { TR_REFRESH_OK, "801400000c810301010182028281830103", TR_REFRESH_BUSY,
					   "801400000c810301010182028281830130", "8014000009810301010182028281" };
	uint8_t resp[300];
	size_t resp_len;
	uint16_t sw;
	int i, k;

	for (i = 0; i < 1500; i++) {
		switch (lcg(&seed) % 10) {
		case 0:
			envelope_rfm(ctx, RFM_FPLMN, 0x01, resp, &resp_len);
			break;
		case 1:
			envelope_rfm(ctx, RFM_LOCI, 0x01, resp, &resp_len);
			break;
		case 2:
			envelope_rfm(ctx, RFM_FPLMN, 0x21, resp, &resp_len);
			break;
		case 3:
			transact_hex(ctx, "80f2000c00", resp, &resp_len);
			break;
		case 4:
			sw = transact_hex(ctx, "80f2000c00", resp, &resp_len);
			if ((sw & 0xff00) == 0x9100)
				fetch_quiet(ctx, sw, resp, &resp_len);
			break;
		case 5:
		case 6:
			transact_hex(ctx, responses[lcg(&seed) % SS_ARRAY_SIZE(responses)], resp, &resp_len);
			break;
		case 7:
		case 8:
			for (k = lcg(&seed) % 40; k >= 0; k--)
				ss_poll(ctx);
			break;
		case 9:
			ss_reset(ctx);
			sw = transact_hex(ctx, TERMINAL_PROFILE, resp, &resp_len);
			assert(sw == 0x9000);
			break;
		}
		if (i % 100 == 99)
			settle(ctx);
	}
	printf("soak with seed %u: %d steps, settled\n", start, i);

	ss_free_ctx(ctx);
}

int main(void)
{
	ss_log_mask = 0;
	setvbuf(stdout, NULL, _IONBF, 0); /* keep the transcript ahead of an assert */
	relax_tar_msl();
	file_change_test();
	imsi_change_test();
	por_by_sms_test();
	reset_drops_pending_changes_test();
	long_list_test();
	second_rfm_while_unfetched_test();
	second_rfm_while_deferred_test();
	status_interleaved_test();
	concat_during_unfetched_test();
	never_fetched_test();
	retry_exhaustion_test();
	no_refresh_support_test();
	t0_path_test();
	reset_while_fetched_test();
	many_files_test();
	soak_test(1);
	soak_test(7);

	return 0;
}
