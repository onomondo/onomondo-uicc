/*
 * Copyright (c) 2026 Onomondo ApS. All rights reserved.
 *
 * SPDX-License-Identifier: GPL-3.0-only
 */

#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <onomondo/softsim/file.h>
#include <onomondo/softsim/list.h>
#include <onomondo/softsim/log.h>
#include "src/softsim/uicc/fs_chg.h"

static int add(uint8_t *filelist, const uint32_t *fids, size_t n)
{
	struct ss_file files[4] = { 0 };
	struct ss_list path;
	size_t i;

	ss_list_init(&path);
	for (i = 0; i < n; i++) {
		files[i].fid = fids[i];
		ss_list_put(&path, &files[i].list);
	}
	return ss_fs_chg_add(filelist, &path);
}

/* Only an exact 3F00 ends a path, so a non-MF 3Fxx FID inside one must not
 * cut it short when the next path is appended or the list is dumped. */
int main(void)
{
	static const uint32_t ef_under_3f20[] = { 0x3f00, 0x3f20, 0x6f07 };
	static const uint32_t ef_iccid[] = { 0x3f00, 0x2fe2 };
	uint8_t *filelist = malloc(SS_FS_CHG_BUF_SIZE);
	int rc;
	int len;
	int i;

	assert(filelist);
	filelist[0] = 0;

	rc = add(filelist, ef_under_3f20, 3);
	assert(rc == 0);
	rc = add(filelist, ef_iccid, 2);
	assert(rc == 0);

	len = ss_fs_chg_len(filelist);
	printf("files=%u len=%d list=", filelist[0], len);
	for (i = 0; i < len; i++)
		printf("%02x", filelist[i]);
	printf("\n");
	fflush(stdout);

	ss_fs_chg_dump(filelist, 0, SREFRESH, LERROR);

	free(filelist);
	return 0;
}
