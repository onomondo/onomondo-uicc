/*
 * Copyright (c) 2024 Onomondo ApS. All rights reserved.
 *
 * SPDX-License-Identifier: GPL-3.0-only
 */

#include <assert.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <onomondo/softsim/file.h>
#include <onomondo/softsim/fs.h>
#include <onomondo/softsim/list.h>
#include <onomondo/softsim/storage.h>
#include <onomondo/softsim/utils.h>

void *port_malloc(size_t size)
{
	return malloc(size);
}

void port_free(void *ptr)
{
	free(ptr);
}

char storage_path[SS_STORAGE_PATH_MAX] = SS_STORAGE_PATH_DEFAULT;

int ss_storage_set_path(const char *path)
{
	if (!path || strlen(path) == 0 || strlen(path) >= SS_STORAGE_PATH_MAX)
		return -1;
	strncpy(storage_path, path, SS_STORAGE_PATH_MAX - 1);
	storage_path[SS_STORAGE_PATH_MAX - 1] = '\0';
	return 0;
}

const char *ss_storage_get_path(void)
{
	return storage_path;
}

ss_FILE ss_fopen(char *path, char *mode)
{
	return (ss_FILE)fopen(path, mode);
}

int ss_fclose(ss_FILE f)
{
	return fclose((FILE *)f);
}

size_t ss_fread(void *ptr, size_t size, size_t nmemb, ss_FILE f)
{
	return fread(ptr, size, nmemb, (FILE *)f);
}

size_t ss_fwrite(const void *ptr, size_t size, size_t count, ss_FILE f)
{
	return fwrite(ptr, size, count, (FILE *)f);
}

int ss_file_size(char *path)
{
	FILE *f = fopen(path, "rb");
	long pos;
	if (!f)
		return -1;
	if (fseek(f, 0, SEEK_END) != 0) {
		fclose(f);
		return -1;
	}
	pos = ftell(f);
	fclose(f);
	if (pos < 0)
		return -1;
	return (int)pos;
}

int ss_delete_file(const char *path)
{
	return remove(path);
}

int ss_delete_dir(const char *path)
{
	char command[SS_STORAGE_PATH_MAX + 20];
	snprintf(command, sizeof(command), "rm -rf %s", path);
	return system(command);
}

int ss_fseek(ss_FILE f, long offset, int whence)
{
	return fseek((FILE *)f, offset, whence);
}

int ss_access(const char *path, int amode)
{
	return access(path, amode);
}

int ss_create_dir(const char *path, uint32_t mode)
{
	return mkdir(path, mode);
}

void ss_logp(uint32_t subsys, uint32_t level, const char *file, int line, const char *format, ...)
{
	(void)subsys;
	(void)level;
	(void)file;
	(void)line;
	(void)format;
}

struct test_path {
	struct ss_list list;
	struct ss_file elems[4];
	size_t len;
};

static void test_path_init(struct test_path *tp, const uint32_t *fids, size_t len)
{
	size_t i;

	memset(tp, 0, sizeof(*tp));
	ss_list_init(&tp->list);
	tp->len = len;

	for (i = 0; i < len; i++) {
		tp->elems[i].fid = fids[i];
		ss_list_put(&tp->list, &tp->elems[i].list);
	}
}

static void test_path_set_fci(struct test_path *tp, const uint8_t *data, size_t len)
{
	assert(tp->len > 0);
	tp->elems[tp->len - 1].fci = ss_buf_alloc_and_cpy(data, len);
}

static void test_path_free_fci(struct test_path *tp)
{
	if (tp->len == 0)
		return;
	if (tp->elems[tp->len - 1].fci)
		ss_buf_free(tp->elems[tp->len - 1].fci);
	tp->elems[tp->len - 1].fci = NULL;
}

static bool path_exists(const char *path)
{
	struct stat st;
	return stat(path, &st) == 0;
}

static void build_host_path(char *out, size_t out_len, const uint32_t *fids, size_t n, bool def)
{
	size_t i;
	size_t used;

	snprintf(out, out_len, "%s", ss_storage_get_path());
	for (i = 0; i < n; i++) {
		used = strlen(out);
		snprintf(out + used, out_len - used, fids[i] > 0xffff ? "/%08x" : "/%04x", fids[i]);
	}
	if (def) {
		used = strlen(out);
		snprintf(out + used, out_len - used, ".def");
	}
}

static void setup_tmp_root(char *tmp_root, size_t tmp_root_len)
{
	char template_path[] = "/tmp/storage_compact_test.XXXXXX";
	char *created = mkdtemp(template_path);
	assert(created != NULL);
	snprintf(tmp_root, tmp_root_len, "%s", created);
	assert(ss_storage_set_path(tmp_root) == 0);
}

static void teardown_tmp_root(const char *tmp_root)
{
	char command[SS_STORAGE_PATH_MAX + 20];
	snprintf(command, sizeof(command), "rm -rf %s", tmp_root);
	assert(system(command) == 0);
}

static void create_parent_dirs(const char *tmp_root)
{
	char p1[SS_STORAGE_PATH_MAX + 1];
	char p2[SS_STORAGE_PATH_MAX + 1];
	char p3[SS_STORAGE_PATH_MAX + 1];

	snprintf(p1, sizeof(p1), "%s/3f00", tmp_root);
	snprintf(p2, sizeof(p2), "%s/3f00/7f10", tmp_root);
	snprintf(p3, sizeof(p3), "%s/3f00/7f10/5f3a", tmp_root);

	assert(mkdir(p1, 0700) == 0);
	assert(mkdir(p2, 0700) == 0);
	assert(mkdir(p3, 0700) == 0);
}

static void test_get_file_def_success(void)
{
	char tmp_root[SS_STORAGE_PATH_MAX + 1];
	char def_path[SS_STORAGE_PATH_MAX + 1];
	uint32_t fids[] = { 0x3f00, 0x2f00 };
	uint8_t fci_data[] = { 0x62, 0x03, 0x82, 0x01, 0x21 };
	struct test_path tp;
	FILE *f;

	setup_tmp_root(tmp_root, sizeof(tmp_root));
	create_parent_dirs(tmp_root);
	build_host_path(def_path, sizeof(def_path), fids, 2, true);
	f = fopen(def_path, "wb");
	assert(f != NULL);
	assert(fwrite(fci_data, 1, sizeof(fci_data), f) == sizeof(fci_data));
	assert(fclose(f) == 0);

	test_path_init(&tp, fids, 2);
	assert(ss_storage_get_file_def(&tp.list) == 0);
	assert(tp.elems[1].fci != NULL);
	assert(tp.elems[1].fci->len == sizeof(fci_data));
	assert(memcmp(tp.elems[1].fci->data, fci_data, sizeof(fci_data)) == 0);

	test_path_free_fci(&tp);
	teardown_tmp_root(tmp_root);
	printf("test_get_file_def_success passed\n");
}

static void test_get_file_def_failure_missing_file(void)
{
	char tmp_root[SS_STORAGE_PATH_MAX + 1];
	uint32_t fids[] = { 0x3f00, 0x2f01 };
	struct test_path tp;

	setup_tmp_root(tmp_root, sizeof(tmp_root));
	create_parent_dirs(tmp_root);
	test_path_init(&tp, fids, 2);
	assert(ss_storage_get_file_def(&tp.list) == -22);
	teardown_tmp_root(tmp_root);
	printf("test_get_file_def_failure_missing_file passed\n");
}

static void test_create_file_read_write_len_delete(void)
{
	char tmp_root[SS_STORAGE_PATH_MAX + 1];
	char content_path[SS_STORAGE_PATH_MAX + 1];
	char def_path[SS_STORAGE_PATH_MAX + 1];
	uint32_t fids[] = { 0x3f00, 0x7f10, 0x6f3a };
	uint8_t fci_data[] = { 0x62, 0x02, 0x82, 0x01 };
	uint8_t write_data[] = { 0x11, 0x22, 0x33 };
	struct test_path tp;
	struct ss_buf *buf;
	size_t i;

	setup_tmp_root(tmp_root, sizeof(tmp_root));
	create_parent_dirs(tmp_root);
	test_path_init(&tp, fids, 3);
	test_path_set_fci(&tp, fci_data, sizeof(fci_data));

	assert(ss_storage_create_file(&tp.list, 8) == 0);
	assert(ss_storage_get_file_len(&tp.list) == 8);

	buf = ss_storage_read_file(&tp.list, 0, 8);
	assert(buf != NULL);
	assert(buf->len == 8);
	for (i = 0; i < buf->len; i++)
		assert(buf->data[i] == 0xff);
	ss_buf_free(buf);

	assert(ss_storage_write_file(&tp.list, write_data, 2, sizeof(write_data)) == 0);
	buf = ss_storage_read_file(&tp.list, 2, sizeof(write_data));
	assert(buf != NULL);
	assert(buf->len == sizeof(write_data));
	assert(memcmp(buf->data, write_data, sizeof(write_data)) == 0);
	ss_buf_free(buf);

	assert(ss_storage_read_file(&tp.list, 7, 2) == NULL);

	build_host_path(content_path, sizeof(content_path), fids, 3, false);
	build_host_path(def_path, sizeof(def_path), fids, 3, true);
	assert(path_exists(content_path));
	assert(path_exists(def_path));

	assert(ss_storage_delete(&tp.list) == 0);
	assert(!path_exists(content_path));
	assert(!path_exists(def_path));
	assert(ss_storage_delete(&tp.list) == -22);

	test_path_free_fci(&tp);
	teardown_tmp_root(tmp_root);
	printf("test_create_file_read_write_len_delete passed\n");
}

static void test_update_def_and_get_def_roundtrip(void)
{
	char tmp_root[SS_STORAGE_PATH_MAX + 1];
	char def_path[SS_STORAGE_PATH_MAX + 1];
	uint32_t fids[] = { 0x3f00, 0x7f10, 0x6f3b };
	uint8_t fci_data[] = { 0x62, 0x03, 0x84, 0x01, 0x00 };
	struct test_path tp;

	setup_tmp_root(tmp_root, sizeof(tmp_root));
	create_parent_dirs(tmp_root);
	test_path_init(&tp, fids, 3);

	assert(ss_storage_update_def(&tp.list) == -22);

	test_path_set_fci(&tp, fci_data, sizeof(fci_data));
	assert(ss_storage_update_def(&tp.list) == 0);
	build_host_path(def_path, sizeof(def_path), fids, 3, true);
	assert(path_exists(def_path));

	test_path_free_fci(&tp);
	assert(ss_storage_get_file_def(&tp.list) == 0);
	assert(tp.elems[2].fci != NULL);
	assert(tp.elems[2].fci->len == sizeof(fci_data));
	assert(memcmp(tp.elems[2].fci->data, fci_data, sizeof(fci_data)) == 0);

	test_path_free_fci(&tp);
	teardown_tmp_root(tmp_root);
	printf("test_update_def_and_get_def_roundtrip passed\n");
}

static void test_create_dir_and_delete(void)
{
	char tmp_root[SS_STORAGE_PATH_MAX + 1];
	char dir_path[SS_STORAGE_PATH_MAX + 1];
	char def_path[SS_STORAGE_PATH_MAX + 1];
	uint32_t fids[] = { 0x3f00, 0x7f10, 0x5f20 };
	uint8_t fci_data[] = { 0x62, 0x02, 0x82, 0x38 };
	struct test_path tp;

	setup_tmp_root(tmp_root, sizeof(tmp_root));
	create_parent_dirs(tmp_root);
	test_path_init(&tp, fids, 3);
	test_path_set_fci(&tp, fci_data, sizeof(fci_data));

	assert(ss_storage_create_dir(&tp.list) == 0);
	build_host_path(dir_path, sizeof(dir_path), fids, 3, false);
	build_host_path(def_path, sizeof(def_path), fids, 3, true);
	assert(path_exists(dir_path));
	assert(path_exists(def_path));

	assert(ss_storage_create_dir(&tp.list) == 0);
	assert(ss_storage_delete(&tp.list) == 0);
	assert(!path_exists(dir_path));
	assert(!path_exists(def_path));

	test_path_free_fci(&tp);
	teardown_tmp_root(tmp_root);
	printf("test_create_dir_and_delete passed\n");
}

static void test_empty_path_failures(void)
{
	struct ss_list empty;
	uint8_t data[] = { 0x01 };

	ss_list_init(&empty);
	assert(ss_storage_get_file_def(&empty) == -22);
	assert(ss_storage_read_file(&empty, 0, 1) == NULL);
	assert(ss_storage_write_file(&empty, data, 0, 1) == -22);
	assert(ss_storage_get_file_len(&empty) == 0);
	assert(ss_storage_delete(&empty) == -22);
	assert(ss_storage_update_def(&empty) == -22);
	assert(ss_storage_create_file(&empty, 1) == -22);
	assert(ss_storage_create_dir(&empty) == -22);
	printf("test_empty_path_failures passed\n");
}

int main(void)
{
	test_get_file_def_success();
	test_get_file_def_failure_missing_file();
	test_create_file_read_write_len_delete();
	test_update_def_and_get_def_roundtrip();
	test_create_dir_and_delete();
	test_empty_path_failures();
	return 0;
}
