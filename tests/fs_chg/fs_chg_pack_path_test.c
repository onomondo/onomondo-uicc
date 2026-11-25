/*
 * Copyright (c) 2026 Onomondo ApS. All rights reserved.
 *
 * SPDX-License-Identifier: GPL-3.0-only
 */

#include <assert.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <onomondo/softsim/file.h>
#include <onomondo/softsim/list.h>
#include <onomondo/softsim/log.h>
#include <onomondo/softsim/utils.h>
#include "src/softsim/uicc/fs_chg.h"

/* Grow a path one FID at a time past what SS_FS_CHG_PATH_MAXLEN holds. Too
 * deep must be refused; the sanitizer builds catch a write past the buffer. */
int main(void)
{
	static const uint32_t fids[] = { 0x3f00, 0x7f10, 0x5f3a, 0x5f01, 0x5f02, 0x5f03,
					 0x5f04, 0x5f05, 0x5f06, 0x5f07, 0x6f07 };
	struct ss_file files[SS_ARRAY_SIZE(fids)] = { 0 };
	uint8_t *filelist = malloc(SS_FS_CHG_BUF_SIZE);
	struct ss_list path;
	size_t depth;
	int rc;

	assert(filelist);
	filelist[0] = 0;
	ss_list_init(&path);

	for (depth = 1; depth <= SS_ARRAY_SIZE(fids); depth++) {
		files[depth - 1].fid = fids[depth - 1];
		ss_list_put(&path, &files[depth - 1].list);
		rc = ss_fs_chg_add(filelist, &path);
		printf("depth %zu: rc=%d\n", depth, rc);
		/* two bytes per FID plus the two-byte terminator */
		assert(rc == (2 * depth + 2 <= SS_FS_CHG_PATH_MAXLEN ? 0 : -EINVAL));
	}

	free(filelist);
	return 0;
}
