/*
 * Copyright (c) 2026 Onomondo ApS. All rights reserved.
 *
 * SPDX-License-Identifier: GPL-3.0-only
 *
 * In-memory ss_f* storage backend: a drop-in replacement for fs.c, selected
 * with -DCONFIG_NO_DEFAULT_IMPL=y (which drops fs.c from the build). It serves
 * the card image straight out of the ss_static_files_hex.c embedding instead
 * of the host filesystem, so there are no fopen/fread/mkdir syscalls at all.
 *
 * Two callers want exactly this:
 *   - KLEE, where every real syscall would be an external call that concretises
 *     symbolic state, and where each forked path needs its own view of the
 *     filesystem. A mutable buffer is per-file and copy-on-write, so KLEE clones
 *     only the files a path actually writes.
 *   - the fuzzer, whose staged /tmp copy is shared between executions (see
 *     tests/fuzz/README.md "Known limits"); ss_fs_ram_reset() gives each input
 *     a pristine image with no disk involved.
 *
 * The files store ASCII hex: an N-byte EF is 2N characters. ss_fread/ss_fwrite
 * therefore move characters, and ss_fseek offsets and ss_file_size counts are
 * in characters -- the contract storage.c already relies on.
 */

#include <onomondo/softsim/fs.h>
#include <onomondo/softsim/storage.h>

#include "utils/files-c-array/ss_static_files_hex.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* 98 files are seeded today; the headroom covers files a run creates. */
#define RAM_MAX_FILES 160

struct ram_file {
	char name[SS_STORAGE_PATH_MAX]; /* "/3f00/7ff0/6f07" or the ".def" sibling */
	const char *ro; /* pristine hex from rodata, never written */
	char *rw; /* copy-on-write buffer, NULL until first write */
	size_t used; /* characters currently stored */
	size_t cap; /* capacity of rw */
	int present;
};

struct ram_fd {
	struct ram_file *file;
	size_t pos; /* character cursor */
	int writable;
};

static struct ram_file ram_files[RAM_MAX_FILES];

/* fs.c also owns these; a drop-in replacement must supply them. Default empty so
 * gen_abs_host_path() produces "/3f00/..." keys that match the embedded names. */
char storage_path[SS_STORAGE_PATH_MAX] = "";

int ss_storage_set_path(const char *path)
{
	if (!path || strlen(path) >= SS_STORAGE_PATH_MAX)
		return -1;
	strncpy(storage_path, path, SS_STORAGE_PATH_MAX - 1);
	storage_path[SS_STORAGE_PATH_MAX - 1] = '\0';
	return 0;
}

const char *ss_storage_get_path(void)
{
	return storage_path;
}

/*! (Re)seed the in-memory image from the static embedding, discarding every
 *  write made since the last reset. Call once before feeding a request. */
void ss_fs_ram_reset(void)
{
	uint32_t i;

	for (i = 0; i < RAM_MAX_FILES; i++) {
		free(ram_files[i].rw);
		ram_files[i].rw = NULL;
		ram_files[i].present = 0;
	}

	for (i = 0; i < ss_files_len && i < RAM_MAX_FILES; i++) {
		strncpy(ram_files[i].name, ss_files[i].name, SS_STORAGE_PATH_MAX - 1);
		ram_files[i].name[SS_STORAGE_PATH_MAX - 1] = '\0';
		ram_files[i].ro = ss_files[i].data;
		ram_files[i].used = ss_files[i].size;
		ram_files[i].cap = 0;
		ram_files[i].present = 1;
	}
}

static struct ram_file *find_file(const char *path)
{
	uint32_t i;

	for (i = 0; i < RAM_MAX_FILES; i++) {
		if (ram_files[i].present && strcmp(ram_files[i].name, path) == 0)
			return &ram_files[i];
	}
	return NULL;
}

static struct ram_file *create_file(const char *path)
{
	uint32_t i;

	for (i = 0; i < RAM_MAX_FILES; i++) {
		if (!ram_files[i].present) {
			strncpy(ram_files[i].name, path, SS_STORAGE_PATH_MAX - 1);
			ram_files[i].name[SS_STORAGE_PATH_MAX - 1] = '\0';
			ram_files[i].ro = NULL;
			free(ram_files[i].rw);
			ram_files[i].rw = NULL;
			ram_files[i].used = 0;
			ram_files[i].cap = 0;
			ram_files[i].present = 1;
			return &ram_files[i];
		}
	}
	return NULL;
}

static const char *read_src(const struct ram_file *f)
{
	return f->rw ? f->rw : f->ro;
}

/* Make f writable and guarantee room for `need` characters (copy-on-write). */
static int ensure_writable(struct ram_file *f, size_t need)
{
	size_t cap = need > f->used ? need : f->used;
	char *buf;

	if (f->rw && f->cap >= need)
		return 0;

	if (cap < 64)
		cap = 64;
	buf = realloc(f->rw, cap);
	if (!buf)
		return -1;
	if (!f->rw && f->ro)
		memcpy(buf, f->ro, f->used);
	f->rw = buf;
	f->cap = cap;
	return 0;
}

ss_FILE ss_fopen(char *path, char *mode)
{
	struct ram_file *f = find_file(path);
	struct ram_fd *fd;
	int writable = mode && (mode[0] == 'w' || mode[0] == 'a' || strchr(mode, '+'));

	if (mode && mode[0] == 'w') {
		/* "w" truncates or creates. */
		if (!f)
			f = create_file(path);
		if (!f)
			return NULL;
		if (ensure_writable(f, 0) != 0)
			return NULL;
		f->used = 0;
	} else if (!f) {
		return NULL; /* "r"/"r+" on a missing file */
	}

	fd = malloc(sizeof(*fd));
	if (!fd)
		return NULL;
	fd->file = f;
	fd->pos = 0;
	fd->writable = writable;
	return (ss_FILE)fd;
}

int ss_fclose(ss_FILE f)
{
	free(f);
	return 0;
}

size_t ss_fread(void *ptr, size_t size, size_t nmemb, ss_FILE fp)
{
	struct ram_fd *fd = (struct ram_fd *)fp;
	size_t avail, items;

	if (!fd || size == 0)
		return 0;

	avail = fd->file->used > fd->pos ? fd->file->used - fd->pos : 0;
	items = avail / size;
	if (items > nmemb)
		items = nmemb;

	memcpy(ptr, read_src(fd->file) + fd->pos, items * size);
	fd->pos += items * size;
	return items;
}

size_t ss_fwrite(const void *ptr, size_t size, size_t count, ss_FILE f)
{
	struct ram_fd *fd = (struct ram_fd *)f;
	size_t bytes = size * count;

	if (!fd || !fd->writable || bytes == 0)
		return 0;
	if (ensure_writable(fd->file, fd->pos + bytes) != 0)
		return 0;

	memcpy(fd->file->rw + fd->pos, ptr, bytes);
	fd->pos += bytes;
	if (fd->pos > fd->file->used)
		fd->file->used = fd->pos;
	return count;
}

int ss_fseek(ss_FILE fp, long offset, int whence)
{
	struct ram_fd *fd = (struct ram_fd *)fp;
	long base;

	if (!fd)
		return -1;
	switch (whence) {
	case SEEK_SET:
		base = 0;
		break;
	case SEEK_CUR:
		base = (long)fd->pos;
		break;
	case SEEK_END:
		base = (long)fd->file->used;
		break;
	default:
		return -1;
	}
	if (base + offset < 0)
		return -1;
	fd->pos = (size_t)(base + offset);
	return 0;
}

int ss_file_size(const char *path)
{
	struct ram_file *f = find_file(path);

	return f ? (int)f->used : -1;
}

int ss_access(const char *path, int amode)
{
	(void)amode;
	return find_file(path) ? 0 : -1;
}

int ss_delete_file(const char *path)
{
	struct ram_file *f = find_file(path);

	if (!f)
		return -1;
	free(f->rw);
	f->rw = NULL;
	f->present = 0;
	return 0;
}

/* Directories are implicit: keys carry the full path, so there is nothing to
 * create or remove. Report success so storage.c's create/delete paths proceed. */
int ss_delete_dir(const char *path)
{
	(void)path;
	return 0;
}

int ss_create_dir(const char *path, uint32_t mode)
{
	(void)path;
	(void)mode;
	return 0;
}
