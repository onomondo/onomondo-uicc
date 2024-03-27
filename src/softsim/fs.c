/*
 * Copyright (c) 2024 Onomondo ApS. All rights reserved.
 *
 * SPDX-License-Identifier: GPL-3.0-only
 *
 * Author: Onomondo ApS
 */
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/stat.h>
#include <onomondo/softsim/fs.h>
#include <onomondo/softsim/storage.h>

char storage_path[] = "./files";

ss_FILE ss_fopen(char *path, char *mode)
{
	FILE *f = fopen(path, mode);
	return (ss_FILE)f;
}
int ss_fclose(ss_FILE f)
{
	return fclose((FILE *)f);
}
size_t ss_fread(void *ptr, size_t size, size_t nmemb, ss_FILE f)
{
	return fread(ptr, size, nmemb, (FILE *)f);
}
size_t ss_fwrite(const void *prt, size_t size, size_t count, ss_FILE f)
{
	return fwrite(prt, size, count, (FILE *)f);
}
int ss_file_size(char *path)
{
	int rc;
	FILE *f;
	int file_size;

	f = fopen(path, "r");

	if (f == NULL) {
		return -1;
	}

	rc = fseek(f, 0, SEEK_END);
	if (rc != 0) {
		fclose(f);
		return -1;
	}

	file_size = ftell(f);
	fclose(f);

	return file_size;
}
int ss_delete_file(const char *path)
{
	return remove(path);
}

int ss_delete_dir(const char *path)
{
	char rm_command[10 + PATH_MAX + 1];

	snprintf(rm_command, sizeof(rm_command), "rm -rf %s", path);
	return system(rm_command);
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
