/*
 * Copyright (c) 2026 Onomondo ApS. All rights reserved.
 *
 * SPDX-License-Identifier: GPL-3.0-only
 */

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

	uint8_t fci_bytes[] = { TS_102_221_IEI_FCP_TMPL, 0x03,
			TS_102_221_IEI_FCP_LIFE_CYCLE_ST, 0x01, 0x01 };
	struct ss_buf fci = { .data = fci_bytes, .len = sizeof(fci_bytes) };

	file.fid = 0x7f10; /* DF.TELECOM, not the MF */
	file.fci  = &fci;
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

int main(void)
{
	ss_log_mask = 0;
	return non_mf_root_denied_test();
}
