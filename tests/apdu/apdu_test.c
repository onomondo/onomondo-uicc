/*
 * Copyright (c) 2024 Onomondo ApS. All rights reserved.
 *
 * SPDX-License-Identifier: GPL-3.0-only
 */

#include <stdint.h>
#include <stdio.h>
#include <stdbool.h>
#include "src/softsim/uicc/apdu.h"
#include <onomondo/softsim/mem.h>
#include <onomondo/softsim/utils.h>

void dump_apdu(struct ss_apdu *apdu)
{
	printf("cla: %02x, ins: %02x, p1: %02x, p2: %02x, p3: %02x, lc: %u, le: %u\n\n", apdu->hdr.cla, apdu->hdr.ins,
	       apdu->hdr.p1, apdu->hdr.p2, apdu->hdr.p3, apdu->lc, apdu->le);
}
/* See also RFC 4493, section 4, Example 1 */
void apdu_test_select_extended(void)
{
	fprintf(stderr, "apdu_test_select_extended\n");
	struct ss_apdu apdu = { 0 };
	uint8_t cmd[] = { 0x00, 0xa4, 0x08, 0x04, 0x00, 0x00, 0x02, 0x2f, 0x00, 0x01, 0x68 };
	ss_apdu_parse_exhaustive(&apdu, cmd, SS_ARRAY_SIZE(cmd));
	dump_apdu(&apdu);
}

void apdu_test_select(void)
{
	fprintf(stderr, "apdu_test_select\n");
	struct ss_apdu apdu = { 0 };
	uint8_t cmd[] = { 0x00, 0xa4, 0x08, 0x04, 0x02, 0x2f, 0x00, 0x68 };
	ss_apdu_parse_exhaustive(&apdu, cmd, SS_ARRAY_SIZE(cmd));
	dump_apdu(&apdu);
}

void apdu_test_select_extended_bad_le(void)
{
	fprintf(stderr, "apdu_test_select_extended_bad_le\n");
	struct ss_apdu apdu = { 0 };
	uint8_t cmd[] = { 0x00, 0xa4, 0x08, 0x04, 0x00, 0x00, 0x02, 0x2f, 0x68, 0x01 };
	ss_apdu_parse_exhaustive(&apdu, cmd, SS_ARRAY_SIZE(cmd));
	dump_apdu(&apdu);
}

void apdu_test_lc_too_large_extended(void)
{
	fprintf(stderr, "apdu_test_lc_too_large_extended\n");
	struct ss_apdu apdu = { 0 };
	uint8_t cmd[] = { 0x00, 0xa4, 0x08, 0x04, 0x00, 0x00, 0x0f, 0x2f, 0x00, 0x68, 0x01 };
	ss_apdu_parse_exhaustive(&apdu, cmd, SS_ARRAY_SIZE(cmd));
	dump_apdu(&apdu);
}

void apdu_test_lc_too_large(void)
{
	fprintf(stderr, "apdu_test_lc_too_large\n");
	struct ss_apdu apdu = { 0 };
	uint8_t cmd[] = { 0x00, 0xa4, 0x08, 0x04, 0x0f, 0x2f, 0x00, 0x68 };
	ss_apdu_parse_exhaustive(&apdu, cmd, SS_ARRAY_SIZE(cmd));
	dump_apdu(&apdu);
}

void apdu_test_read_record(void)
{
	fprintf(stderr, "apdu_test_read_record\n");
	struct ss_apdu apdu = { 0 };
	uint8_t cmd[] = { 0x00, 0xb2, 0x01, 0x04, 0x26 };
	ss_apdu_parse_exhaustive(&apdu, cmd, SS_ARRAY_SIZE(cmd));
	dump_apdu(&apdu);
}

void apdu_test_read_record_extended(void)
{
	fprintf(stderr, "apdu_test_read_record_extended\n");
	struct ss_apdu apdu = { 0 };
	uint8_t cmd[] = { 0x00, 0xb2, 0x01, 0x04, 0x00, 0x00, 0x26 };
	ss_apdu_parse_exhaustive(&apdu, cmd, SS_ARRAY_SIZE(cmd));
	dump_apdu(&apdu);
}
int main(int argc, char **argv)
{
	apdu_test_select_extended();
	apdu_test_select_extended_bad_le();
	apdu_test_select();
	apdu_test_read_record();
	apdu_test_read_record_extended();
	apdu_test_lc_too_large();
	apdu_test_lc_too_large_extended();
	return 0;
}
