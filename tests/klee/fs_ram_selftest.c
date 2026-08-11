/*
 * Copyright (c) 2026 Onomondo ApS. All rights reserved.
 *
 * SPDX-License-Identifier: GPL-3.0-only
 *
 * Native check for the in-memory ss_f* backend (src/softsim/fs_ram.c). It runs
 * without KLEE -- an ordinary ctest -- so the backend is exercised on every
 * build, not only when someone runs the symbolic-execution job. It pins the
 * three behaviours storage.c depends on: reads return the embedded card image,
 * writes are copy-on-write, and ss_fs_ram_reset() discards them.
 */

#include <onomondo/softsim/fs.h>

#include <assert.h>
#include <stdio.h>
#include <string.h>

void ss_fs_ram_reset(void);

/* EF_IMSI content from utils/files-c-array/ss_static_files_hex.c, as ASCII hex
 * (9 bytes -> 18 characters). */
static const char imsi_hex[] = "080910100000000010";

int main(void)
{
	char imsi[] = "/3f00/7ff0/6f07";
	char missing[] = "/3f00/nope";
	char buf[64];
	ss_FILE fd;
	size_t n;

	ss_fs_ram_reset();

	/* Read: the backend serves the embedded image, in characters. */
	assert(ss_file_size(imsi) == (int)strlen(imsi_hex));
	fd = ss_fopen(imsi, "r");
	assert(fd);
	n = ss_fread(buf, 2, sizeof(buf) / 2, fd);
	ss_fclose(fd);
	assert(n * 2 == strlen(imsi_hex));
	assert(memcmp(buf, imsi_hex, strlen(imsi_hex)) == 0);

	/* Copy-on-write: overwrite the first byte's two hex chars via "r+". */
	fd = ss_fopen(imsi, "r+");
	assert(fd);
	assert(ss_fseek(fd, 0, SEEK_SET) == 0);
	assert(ss_fwrite("ab", 2, 1, fd) == 1);
	ss_fclose(fd);

	fd = ss_fopen(imsi, "r");
	n = ss_fread(buf, 2, sizeof(buf) / 2, fd);
	ss_fclose(fd);
	assert(n * 2 == strlen(imsi_hex));
	assert(memcmp(buf, "ab", 2) == 0);
	assert(memcmp(buf + 2, imsi_hex + 2, strlen(imsi_hex) - 2) == 0);

	/* Reset restores the pristine image; the write is gone. */
	ss_fs_ram_reset();
	fd = ss_fopen(imsi, "r");
	ss_fread(buf, 2, sizeof(buf) / 2, fd);
	ss_fclose(fd);
	assert(memcmp(buf, imsi_hex, strlen(imsi_hex)) == 0);

	/* A missing file does not open. */
	assert(ss_fopen(missing, "r") == NULL);

	printf("fs_ram_selftest OK\n");
	return 0;
}
