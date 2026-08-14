/*
 * Copyright (c) 2026 Onomondo ApS. All rights reserved.
 *
 * SPDX-License-Identifier: GPL-3.0-only
 *
 * SELECT and STATUS, following the test procedures in ETSI TS 102 230-2
 * clauses 6.6.5, 6.6.6 and 6.9.1.1 to 6.9.1.2: the ways a file can be
 * addressed, the file control parameters that come back, and what STATUS
 * reports about the current directory and the active application.
 */

#include "tests/uicc_test.h"

#define AID "a0000000871002ffffffff8907090000"

#define MF_FCP                                                     \
	"62298202782183023f00a5098001f18701008801008a01058b032f06" \
	"0fc60c90012083010183018183010a"
#define ADF_FCP                                         \
	"62308202782183027ff08410" AID "8a01058b032f06" \
	"0fc60c90012083010183018183010a"
#define IMSI_FCP "62178202412183026f078a01058b036f060580020009880138"

int main(void)
{
	struct ss_context *ctx;

	ss_log_mask = 0;
	ctx = ss_new_ctx();
	ss_reset(ctx);

	/* 6.9.1.1.3 steps 4-7: selecting by file identifier returns the file
	 * control parameters, which name the file and its structure. */
	ut_step_data(ctx, "select MF by file id", "00a40004023f00", 0x9000, MF_FCP);
	ut_step_data(ctx, "select EF.ICCID by file id", "00a40004022fe2", 0x9000,
		     "62178202412183022fe28a01058b032f06038002000a880110");
	ut_step_data(ctx, "select EF.DIR by file id", "00a40004022f00", 0x9000,
		     "621a8205422100260283022f008a01058b032f06028002004c8801f0");

	/* 6.9.1.1.3 steps 10-11: P2 = '0C' asks for no response data. */
	ut_step_data(ctx, "select MF with no response data", "00a4000c023f00", 0x9000, "");

	/* 6.6.6.1.1: an application is selected by its DF name, and the '7FFF'
	 * alias reaches the same ADF. */
	ut_step_data(ctx, "select ADF USIM by AID", "00a4040410" AID, 0x9000, ADF_FCP);
	ut_step_data(ctx, "select ADF USIM by alias", "00a40004027fff", 0x9000, ADF_FCP);

	/* 6.6.5.2: selection by path, from the MF and from the current DF. */
	ss_reset(ctx);
	ut_step_data(ctx, "select EF.IMSI by path from MF", "00a40804047ff06f07", 0x9000, IMSI_FCP);
	ut_step(ctx, "select ADF USIM", "00a4040c10" AID, 0x9000);
	ut_step_data(ctx, "select EF.IMSI by path from current DF", "00a40904026f07", 0x9000, IMSI_FCP);

	/* P1 = '03' selects the parent of the current DF, which for an EF under
	 * the ADF is the MF. */
	ut_step(ctx, "select parent", "00a4030400", 0x9000);

	/* Le = '01' is short, so the card answers 6cXX with the length of the
	 * template and ss_application_apdu_transact re-issues the command with
	 * it. Le = '00' asks for 256 bytes, which no response can carry. */
	ut_step_data(ctx, "status reports the MF", "80f2000001", 0x9000, MF_FCP);

	/* 6.6.5.1: a file identifier that does not exist. */
	ut_step(ctx, "select a file that does not exist", "00a40004021234", 0x6a82);

	/* Clause 11.1.1.2 of TS 102 221 allows a right truncated AID in the
	 * data field. An AID that matches no application is not found. */
	ut_step(ctx, "select by an unknown AID", "00a4040408a000000087100200", 0x6a88);
	ut_step_data(ctx, "select by a right truncated AID", "00a4040407a0000000871002", 0x9000, ADF_FCP);

	/* 6.9.1.2: STATUS reports the current directory, and keeps reporting
	 * the application when an EF under it is selected. */
	ss_reset(ctx);
	ut_step_data(ctx, "status at the MF", "80f2000001", 0x9000, MF_FCP);
	ut_step(ctx, "select ADF USIM", "00a4040c10" AID, 0x9000);
	ut_step_data(ctx, "status in the ADF", "80f2000001", 0x9000, ADF_FCP);

	/* Clause 11.1.1.2 of TS 102 221 makes the MF the current directory when
	 * P1 = '00', P2 = '0C' and the data field is empty, which 6.9.1.1.3
	 * step 18 and 6.9.1.1.4 steps 3 to 6 require. The card reports 6f00 and
	 * stays in the ADF. */
	ut_step(ctx, "select with an empty data field", "00a4000c00", 0x6f00);
	ut_step_data(ctx, "status after the empty select", "80f2000001", 0x9000, ADF_FCP);

	ut_step(ctx, "select EF.IMSI", "00a4000c026f07", 0x9000);
	ut_step_data(ctx, "status with an EF selected", "80f2000001", 0x9000, ADF_FCP);

	/* P2 = '0C' asks for no response data here as well. */
	ut_step_data(ctx, "status with no response data", "80f2000c00", 0x9000, "");

	/* Table 11.9 of TS 102 221: P2 = '01' returns the DF name TLV of the
	 * active application, and P1 = '01' only indicates that the terminal
	 * initialized it. */
	ut_step_data(ctx, "status asking for the DF name", "80f2000112", 0x9000, "8410" AID);
	ut_step_data(ctx, "status with the application initialized", "80f2010001", 0x9000, ADF_FCP);

	/* 6.9.1.2.3 steps 7-8: with no application selected the DF name
	 * request is answered with an error. */
	ss_reset(ctx);
	ut_step(ctx, "status asking for the DF name with no application", "80f2000112", 0x6986);

	/* 6.6.6.1.1 steps 3-8: EF.DIR carries the application's AID in a '4F'
	 * data object, which is what a terminal selects the application by. */
	ut_step(ctx, "select EF.DIR", "00a4000c022f00", 0x9000);
	ut_step_data(ctx, "read the first record", "00b2010426", 0x9000,
		     "61194f10" AID "50055553696d31ffffffffffffffffffffff");

	ss_free_ctx(ctx);
	return 0;
}
