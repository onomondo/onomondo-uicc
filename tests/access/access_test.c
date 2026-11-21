/*
 * Copyright (c) 2026 Onomondo ApS. All rights reserved.
 *
 * SPDX-License-Identifier: GPL-3.0-only
 */

#include <assert.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <onomondo/softsim/utils.h>
#include <onomondo/softsim/file.h>
#include <onomondo/softsim/storage.h>
#include <onomondo/softsim/list.h>
#include <onomondo/softsim/log.h>
#include <onomondo/softsim/mem.h>
#include "src/softsim/uicc/access.h"
#include "src/softsim/uicc/apdu.h"
#include "src/softsim/uicc/btlv.h"
#include "src/softsim/uicc/fcp.h"
#include "src/softsim/uicc/fs.h"

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
	{ "next AM ends SC phase: read", "80010190008001029700", RD, true },
	{ "two SCs, both always", "80010190009000", RD, true },
	{ "only padding", "ffffffffffffffff", RD, false },

	/* invalid or unsupported rules */
	{ "AM with len != 1", "800201019000", RD, false },
	{ "OR template SC", "800101a000", RD, false },
	{ "neither AM nor SC", "800101c000", RD, false },
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
		mf.access = rule;
		ss_list_put(&lchan.fs_path, &mf.list);

		/* call function under test */
		granted = ss_access_check_command(&apdu, c->intention);

		/* check if the decision matches the expected one */
		assert(granted == c->expected_granted);

		ss_buf_free(rule);
		ss_buf_free(fci);
	}
}

/* Access rule loading tests: ss_access_populate() against a generated tree in
 * its own storage root, so the tracked files/ stay untouched. The MF references record 1 of EF.ARR
 * 2F06 (linear fixed, 2 records of 16 bytes). Malformed records must not be
 * stored (access stays NULL, i.e. deny all); valid ones are stored raw,
 * padding included. */

/* Real MF definition from files/, rule reference changed to record 1 */
#define DEF_MF "621b8202782183023f00a5098001f18701008801008a01058b032f0601"
/* EF.ARR: linear fixed, record length 0x10, 2 records, size 0x20 */
#define DEF_EF_ARR "621a8205422100100283022f068a01058b032f060180020020880130"
#define RECORD_PADDING "ffffffffffffffffffffffffffffffff"

struct populate_case {
	const char *name;
	const char *record_hex; /* record 1 of EF.ARR, 16 bytes */
	bool expected_stored;
};

static const struct populate_case populate_cases[] = {
	/* name                       record_hex                           stored */
	{ "valid rule", "8001019000ffffffffffffffffffffff", true },
	{ "data after padding", "8001019000ff12ffffffffffffffffff", false },
};

static void write_text(const char *path, const char *text)
{
	FILE *f = fopen(path, "w");

	assert(f);
	fputs(text, f);
	fclose(f);
}

static void access_populate_test(void)
{
	char content[sizeof(RECORD_PADDING) * 2];
	size_t i;

	mkdir("access_test_files", 0755);
	mkdir("access_test_files/3f00", 0755);
	assert(ss_storage_set_path("./access_test_files") == 0);
	write_text("access_test_files/3f00.def", DEF_MF);
	write_text("access_test_files/3f00/2f06.def", DEF_EF_ARR);

	for (i = 0; i < SS_ARRAY_SIZE(populate_cases); i++) {
		const struct populate_case *c = &populate_cases[i];
		struct ss_lchan lchan = { 0 };
		struct ss_file *mf;

		fprintf(stderr, "TEST: access_populate: %s\n", c->name);

		/* record 1 under test, record 2 all padding */
		snprintf(content, sizeof(content), "%s%s", c->record_hex, RECORD_PADDING);
		write_text("access_test_files/3f00/2f06", content);

		ss_fs_init(&lchan.fs_path);
		mf = ss_get_file_from_path(&lchan.fs_path);
		assert(mf);

		/* call function under test */
		ss_access_populate(&lchan);

		/* stored (raw, byte for byte) or rejected as expected */
		assert((mf->access != NULL) == c->expected_stored);
		if (mf->access)
			assert(strcmp(ss_hexdump(mf->access->data, mf->access->len), c->record_hex) == 0);

		ss_path_reset(&lchan.fs_path);
	}
}

int main(void)
{
	ss_log_mask = 0;
	access_rule_test();
	access_populate_test();
	return non_mf_root_denied_test();
}
