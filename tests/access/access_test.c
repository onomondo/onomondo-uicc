/*
 * Copyright (c) 2026 Onomondo ApS. All rights reserved.
 *
 * SPDX-License-Identifier: GPL-3.0-only
 */

#include <assert.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <onomondo/softsim/utils.h>
#include <onomondo/softsim/file.h>
#include <onomondo/softsim/list.h>
#include <onomondo/softsim/log.h>
#include <onomondo/softsim/mem.h>
#include "src/softsim/uicc/access.h"
#include "src/softsim/uicc/apdu.h"
#include "src/softsim/uicc/btlv.h"
#include "src/softsim/uicc/fcp.h"

extern uint32_t ss_log_mask;

/* A path whose first element is not the MF must be denied. While this was an
 * assert(), a -DNDEBUG build took the lifecycle byte of that unrelated file
 * instead and granted every access when it read < 4 (creation state).
 *
 * Checked with an if() rather than assert() so the check survives -DNDEBUG,
 * which is the build this guards. */
static int non_mf_root_denied_test(void)
{
	struct ss_lchan lchan;
	struct ss_apdu apdu;
	struct ss_file file;

	memset(&lchan, 0, sizeof(lchan));
	memset(&apdu, 0, sizeof(apdu));
	memset(&file, 0, sizeof(file));

	apdu.lchan = &lchan;
	ss_list_init(&lchan.fs_path);

	uint8_t fci_bytes[] = { TS_102_221_IEI_FCP_TMPL, 0x03, TS_102_221_IEI_FCP_LIFE_CYCLE_ST, 0x01, 0x01 };
	struct ss_buf fci = { .data = fci_bytes, .len = sizeof(fci_bytes) };

	file.fid = 0x7f10; /* DF.TELECOM, not the MF */
	file.fci = &fci;
	ss_list_put(&lchan.fs_path, &file.list);

	bool granted = ss_access_check_command(&apdu, SS_ACCESS_INTENTION_EF_READ);

	if (granted) {
		/* stderr, so ctest shows it: stdout goes to access_test.out */
		fprintf(stderr, "FAIL: access granted on a path not rooted at the MF\n");
		return 1;
	}
	printf("Non-MF root path rejection test passed\n");
	return 0;
}

/* Access rule evaluation tests */

/* An operational MF (LCSI 05) as the only, and thus selected, path element. */
#define FCI_MF_OPERATIONAL "62038a0105"

#define RD SS_ACCESS_INTENTION_EF_READ
#define UP SS_ACCESS_INTENTION_EF_UPDATE_ERASE

struct rule_case {
	const char *name;
	const char *rule_hex; /* raw rule, as ss_access_populate() stores it */
	enum ss_access_intention intention;
	bool expected_granted;
};

static const struct rule_case rule_cases[] = {
	/* name                          rule_hex                         intention  granted */

	/* regular rules */
	{ "read always: read", "8001019000ffff", RD, true },
	{ "read always: update", "8001019000ffff", UP, false }, /* no AM matched */
	{ "update never", "8001029700", UP, false },
	{ "next AM ends SC phase: read", "80010190008001029700", RD, true },
	{ "next AM ends SC phase: update", "80010190008001029700", UP, false },
	{ "two SCs, both always", "80010190009000", RD, true },
	{ "only padding", "ffffffffffffffff", RD, false },
	{ "empty", "", RD, false },

	/* invalid or unsupported rules */
	{ "starts with an SC", "90008001019000", RD, true },
	{ "AM with len != 1", "800201019000", RD, false },
	{ "no SC after the AM", "800101", RD, false },
	{ "OR template SC", "800101a000", RD, false },
	{ "SM template SC", "800101b400", RD, false },
	{ "SC byte (unimplemented)", "8001019e0101", RD, false },
	{ "neither AM nor SC", "800101c000", RD, false },
	{ "multi-byte tag", "8001019f2100", RD, false },

	/* A4 (CRT) contents */
	{ "A4 without 95", "800101a403830101", RD, false },
	{ "A4 with extra element", "800101a4088301019501089000", RD, false },
	{ "A4 with malformed inside", "800101a406830501950108", RD, false },
	{ "A4 with garbage after valid elements", "800101a40783010a95010812", RD, false },
	{ "A4 with 2 byte key ref", "800101a40783020001950108", RD, false },
	{ "A4 PIN1 not verified", "800101a406830101950108", RD, false }, /* no PIN file */
};

static void access_rule_test(void)
{
	size_t i;

	for (i = 0; i < SS_ARRAY_SIZE(rule_cases); i++) {
		const struct rule_case *c = &rule_cases[i];
		struct ss_buf *fci = ss_buf_from_hexstr(FCI_MF_OPERATIONAL);
		struct ss_buf *rule = ss_buf_from_hexstr((char *)c->rule_hex);
		struct ss_lchan lchan = { 0 };
		struct ss_apdu apdu = { 0 };
		struct ss_file mf = { 0 };
		bool granted;

		/* name the case up front, assert() itself only prints the failed expression */
		fprintf(stderr, "TEST: access_rule: %s\n", c->name);

		/* MF with the rule under test as the only path element */
		apdu.lchan = &lchan;
		ss_list_init(&lchan.fs_path);
		mf.fid = 0x3f00;
		mf.fci = fci;
		mf.access = ss_btlv_decode(rule->data, rule->len, NULL); /* as ss_access_populate() on master */
		ss_list_put(&lchan.fs_path, &mf.list);

		/* call function under test */
		granted = ss_access_check_command(&apdu, c->intention);

		/* check if the decision matches the expected one */
		assert(granted == c->expected_granted);

		ss_btlv_free(mf.access);
		ss_buf_free(rule);
		ss_buf_free(fci);
	}
}

int main(void)
{
	ss_log_mask = 0;
	access_rule_test();
	return non_mf_root_denied_test();
}
