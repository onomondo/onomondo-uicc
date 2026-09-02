/*
 * Copyright (c) 2024 Onomondo ApS. All rights reserved.
 *
 * SPDX-License-Identifier: GPL-3.0-only
 * 
 * Author: Benjamin Bruun
 */

#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <sys/stat.h>
#include <onomondo/softsim/fs.h>
#include <onomondo/softsim/storage.h>
#include <onomondo/softsim/list.h>
#include "src/softsim/uicc/fs.h"
#include "src/softsim/uicc/fs_utils.h"

/* fs.c declares the storage entry points weak, so these stand in for three of
 * them: one cuts the first write of the chosen size short, the other two record
 * the order the core closes and deletes in. */
static size_t fail_write_size;
static int seq, close_seq, delete_seq;

size_t ss_fwrite(const void *ptr, size_t size, size_t count, ss_FILE f)
{
	if (size == fail_write_size) {
		fail_write_size = 0;
		return 0;
	}
	return fwrite(ptr, size, count, (FILE *)f);
}

int ss_fclose(ss_FILE f)
{
	close_seq = ++seq;
	return fclose((FILE *)f);
}

int ss_delete_file(const char *path)
{
	delete_seq = ++seq;
	remove(path);
	return 0; /* the content file may not exist yet; never fall through to ss_delete_dir */
}

void test_storage_path_default(void)
{
	const char *path = ss_storage_get_path();
	printf("Default storage path: %s\n", path);
	assert(strcmp(path, SS_STORAGE_PATH_DEFAULT) == 0);
	printf("Default path test passed\n");
}

void test_storage_path_set_valid(void)
{
	const char *new_path = "/tmp/test/files";
	int rc = ss_storage_set_path(new_path);
	assert(rc == 0);

	const char *path = ss_storage_get_path();
	assert(strcmp(path, new_path) == 0);
	printf("Set valid path test passed: %s\n", path);
}

void test_storage_path_set_null(void)
{
	int rc = ss_storage_set_path(NULL);
	assert(rc == -1);
	printf("Null path rejection test passed\n");
}

void test_storage_path_set_too_long(void)
{
	char long_path[SS_STORAGE_PATH_MAX + 10];
	memset(long_path, 'a', sizeof(long_path) - 1);
	long_path[sizeof(long_path) - 1] = '\0';

	int rc = ss_storage_set_path(long_path);
	assert(rc == -1);
	printf("Too long path rejection test passed\n");
}

void test_storage_path_set_max_length(void)
{
	char max_path[SS_STORAGE_PATH_MAX];
	memset(max_path, 'b', SS_STORAGE_PATH_MAX - 2);
	max_path[SS_STORAGE_PATH_MAX - 2] = '\0';

	int rc = ss_storage_set_path(max_path);
	assert(rc == 0);

	const char *path = ss_storage_get_path();
	assert(strcmp(path, max_path) == 0);
	printf("Max length path test passed (length: %zu)\n", strlen(path));
}

void test_storage_path_multiple_sets(void)
{
	const char *path1 = "/tmp/path1";
	const char *path2 = "/tmp/path2";
	const char *path3 = "/tmp/path3";

	ss_storage_set_path(path1);
	assert(strcmp(ss_storage_get_path(), path1) == 0);

	ss_storage_set_path(path2);
	assert(strcmp(ss_storage_get_path(), path2) == 0);

	ss_storage_set_path(path3);
	assert(strcmp(ss_storage_get_path(), path3) == 0);

	printf("Multiple path changes test passed\n");
}

void test_storage_path_special_chars(void)
{
	const char *special_path = "/tmp/path-with_special.chars/file$123";
	int rc = ss_storage_set_path(special_path);
	assert(rc == 0);
	assert(strcmp(ss_storage_get_path(), special_path) == 0);
	printf("Special characters in path test passed\n");
}

void test_storage_path_empty_string(void)
{
	const char *empty_path = "";
	int rc = ss_storage_set_path(empty_path);
	assert(rc == -1);
	/* When an empty path set is rejected, the storage path should remain unchanged */
	const char *path = ss_storage_get_path();
	assert(strcmp(path, "/tmp/path-with_special.chars/file$123") == 0);
	printf("Empty path rejection test passed\n");
}

/* ss_fs_utils_create_record_file() used to return 0 unconditionally, so a
 * caller could not tell that the internal lookup file it asked for was never
 * created. Point the storage root at a directory that does not exist, which
 * makes the create fail in the storage layer, and require that the failure
 * reaches the caller. */
void test_create_record_file_reports_failure(void)
{
	struct ss_list path;
	int rc;

	rc = ss_storage_set_path("/nonexistent-storage-root-for-test/files");
	assert(rc == 0);

	ss_list_init(&path);
	rc = ss_fs_utils_create_record_file(&path, 0x5F100001, 2, 0x1f);
	assert(rc < 0);
	ss_path_reset(&path);
	printf("Create record file failure propagation test passed\n");
}

/* A failed write must close the handle before the file is deleted: on a port
 * whose handle is the file's cache node, delete frees what close then uses. */
void test_failed_write_closes_before_delete(void)
{
	struct ss_list path;
	size_t sizes[] = { 2, 1 }; /* 2: definition hex pair, 1: content prefill byte */
	size_t i;
	int rc;

	mkdir("close_order_files", 0700);
	rc = ss_storage_set_path("./close_order_files");
	assert(rc == 0);

	for (i = 0; i < 2; i++) {
		seq = close_seq = delete_seq = 0;
		fail_write_size = sizes[i];
		ss_list_init(&path);
		rc = ss_fs_utils_create_record_file(&path, 0x5F100001, 2, 0x1f);
		ss_path_reset(&path);
		assert(rc < 0);
		assert(close_seq > 0 && delete_seq > 0);
		assert(close_seq < delete_seq);
	}
	printf("Failed write closes before delete test passed\n");
}

int main(void)
{
	test_storage_path_default();
	test_storage_path_set_valid();
	test_storage_path_set_null();
	test_storage_path_set_too_long();
	test_storage_path_set_max_length();
	test_storage_path_multiple_sets();
	test_storage_path_special_chars();
	test_storage_path_empty_string();
	test_create_record_file_reports_failure();
	test_failed_write_closes_before_delete();
	return 0;
}
