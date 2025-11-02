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
#include <onomondo/softsim/storage.h>

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
	return 0;
}
