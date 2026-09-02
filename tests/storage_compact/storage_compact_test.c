/*
 * Copyright (c) 2026 Onomondo ApS. All rights reserved.
 *
 * SPDX-License-Identifier: GPL-3.0-only
 */

#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <onomondo/softsim/file.h>
#include <onomondo/softsim/list.h>
#include <onomondo/softsim/storage.h>
#include <onomondo/softsim/utils.h>

#define TEST_ROOT "./compact_fs"
#define CONTENT_LEN 16

static struct ss_list path;
static struct ss_file mf = { .fid = 0x3f00 };
static struct ss_file ef = { .fid = 0x2f06 };
static uint8_t content[CONTENT_LEN];

static void setup(void)
{
	FILE *f;
	size_t i;

	for (i = 0; i < CONTENT_LEN; i++)
		content[i] = (uint8_t)(0x10 + i);

	mkdir(TEST_ROOT, 0755);
	mkdir(TEST_ROOT "/3f00", 0755);
	f = fopen(TEST_ROOT "/3f00/2f06", "w");
	assert(f);
	assert(fwrite(content, 1, CONTENT_LEN, f) == CONTENT_LEN);
	assert(fclose(f) == 0);

	assert(ss_storage_set_path(TEST_ROOT) == 0);

	ss_list_init(&path);
	ss_list_put(&path, &mf.list);
	ss_list_put(&path, &ef.list);
}

static void test_read_whole(void)
{
	struct ss_buf *sb = ss_storage_read_file(&path, 0, CONTENT_LEN);

	assert(sb);
	assert(sb->len == CONTENT_LEN);
	assert(memcmp(sb->data, content, CONTENT_LEN) == 0);
	ss_buf_free(sb);
	printf("whole-file read returns the file content\n");
}

static void test_read_window(void)
{
	struct ss_buf *sb = ss_storage_read_file(&path, 4, 8);

	assert(sb);
	assert(sb->len == 8);
	assert(memcmp(sb->data, &content[4], 8) == 0);
	ss_buf_free(sb);
	printf("offset read returns the requested window\n");
}

static void test_read_past_eof(void)
{
	assert(ss_storage_read_file(&path, 8, CONTENT_LEN) == NULL);
	printf("read past end of file returns NULL\n");
}

static void test_read_missing_file(void)
{
	ef.fid = 0x2f07;
	assert(ss_storage_read_file(&path, 0, 1) == NULL);
	ef.fid = 0x2f06;
	printf("read of a missing file returns NULL\n");
}

int main(void)
{
	setup();
	test_read_whole();
	test_read_window();
	test_read_past_eof();
	test_read_missing_file();
	return 0;
}
