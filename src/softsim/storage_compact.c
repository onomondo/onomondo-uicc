/*
 * Copyright (c) 2024 Onomondo ApS. All rights reserved.
 *
 * SPDX-License-Identifier: GPL-3.0-only
 *
 * Author: Philipp Maier, Peter S. Bornerup
 */

#include <stdint.h>
#include <string.h>
#include <stdbool.h>
#include <errno.h>
#include <sys/types.h>
#include <unistd.h>
#include <onomondo/softsim/log.h>
#include <onomondo/softsim/list.h>
#include <onomondo/softsim/file.h>
#include <onomondo/softsim/utils.h>
#include <onomondo/softsim/mem.h>
#include <onomondo/softsim/storage.h>
#include <onomondo/softsim/fs.h>

/*! Generate a host filesystem path for a given file path.
 *  \param[in] def_path buffer to store the generated path. Must be at least SS_STORAGE_PATH_MAX bytes long.
 *  \param[in] path file path to generate the host filesystem path for.
 *  \param[in] def whether the generated path is for a definition file (true) or content file (false).
 *                 This is relevant for the handling of proprietary files (SEQ) identified by 0xa1xx,
 *                 which get the same FCP association but need to be stored in the same directory on the host file system.
 *                 If def, these files will be represented with 0xa100 in the generated path, otherwise their actual FID.
 * \param[in] division string to identify the calling function in log messages.
 * \returns 0 on success, -EINVAL on failure. */
static int gen_abs_host_path(char *def_path, const struct ss_list *path, bool def, const char *division)
{
	char host_fs_path[SS_STORAGE_PATH_MAX];
	char abs_host_fs_path[SS_STORAGE_PATH_MAX + 1];
	char *host_fs_path_ptr;
	struct ss_file *path_cursor;
	struct ss_file *path_last = NULL;
	int rc;

	if (ss_list_empty(path))
		return -EINVAL;

	memset(host_fs_path, 0, sizeof(host_fs_path));
	host_fs_path_ptr = host_fs_path;

	SS_LIST_FOR_EACH(path, path_cursor, struct ss_file, list) {
		size_t remaining = sizeof(host_fs_path) - (host_fs_path_ptr - host_fs_path);
		rc = snprintf(host_fs_path_ptr, remaining,
			      path_cursor->fid > 0xffff ? PATH_SEPARATOR "%08x" : PATH_SEPARATOR "%04x",
			      /* Proprietary files (SEQ) identified by 0xa1xx got the same FCP association. */
			      (path_cursor->fid & 0xff00) == 0xa100 && def ? 0xa100 : path_cursor->fid);
		if (rc < 0 || (size_t)rc >= remaining) {
			SS_LOGP(SSTORAGE, LERROR, "%s: host path buffer overflow while building path -- abort\n", division);
			return -EINVAL;
		}
		host_fs_path_ptr += rc;
		path_last = path_cursor;
	}
	if (def) {
		rc = snprintf(abs_host_fs_path, sizeof(abs_host_fs_path), "%s%s.def", storage_path, host_fs_path);

		SS_LOGP(SSTORAGE, LINFO, "%s: requested file definition for %04x on host file system : %s\n", division,
			path_last->fid, abs_host_fs_path);

	} else {
		rc = snprintf(abs_host_fs_path, sizeof(abs_host_fs_path), "%s%s", storage_path, host_fs_path);
		SS_LOGP(SSTORAGE, LINFO, "%s: requested file content for %04x on host file system: %s\n", division,
			path_last->fid, abs_host_fs_path);
	}
	if (rc < 0 || (size_t)rc >= sizeof(abs_host_fs_path)) {
		SS_LOGP(SSTORAGE, LERROR, "%s: resulting absolute host path was truncated -- abort\n", division);
		return -EINVAL;
	}
	if ((size_t)rc >= SS_STORAGE_PATH_MAX) {
		SS_LOGP(SSTORAGE, LERROR, "%s: destination path buffer too small -- abort\n", division);
		return -EINVAL;
	}

	memcpy(def_path, abs_host_fs_path, (size_t)rc + 1);

	return 0;
}

/* Read file definition from the host file system */
static int read_file_def(char *host_path, struct ss_file *file)
{
	ss_FILE fd;
	uint8_t line_buf[FCP_MAX_LEN];
	size_t rc;

	fd = ss_fopen(host_path, "r");
	if (!fd) {
		SS_LOGP(SSTORAGE, LDEBUG, "unable to open definition file: %s\n", host_path);
		return -EINVAL;
	}

	rc = ss_fread(line_buf, 1, sizeof(line_buf), fd);
	ss_fclose(fd);
	if (!rc) {
		SS_LOGP(SSTORAGE, LDEBUG, "unable to read definition file: %s\n", host_path);
		return -EINVAL;
	}
	if (rc >= sizeof(line_buf)) {
		SS_LOGP(SSTORAGE, LERROR, "definition file too large (truncated), aborting: %s\n", host_path);
		return -EINVAL;
	}

	file->fci = ss_buf_alloc_and_cpy(line_buf, rc);

	return 0;
}

int ss_storage_get_file_def(struct ss_list *path)
{
	/*! Note: This function will allocate memory in file to store the file
	 *  definition. The caller must take care of freeing. */
	char host_path[SS_STORAGE_PATH_MAX + 1];
	struct ss_file *file;
	int rc;

	rc = gen_abs_host_path(host_path, path, true, "get-def");
	if (rc < 0) {
		SS_LOGP(SSTORAGE, LERROR, "%s: unable to generate path to load file definition\n", "get-def");
		return -EINVAL;
	}

	file = ss_get_file_from_path(path);
	if (!file)
		return -EINVAL;

	return read_file_def(host_path, file);
}

struct ss_buf *ss_storage_read_file(const struct ss_list *path, size_t read_offset, size_t read_len)
{
	/*! Note: This function will allocate memory in file to store the file
	 *  contents. The caller must take care of freeing. */
	char host_path[SS_STORAGE_PATH_MAX + 1];
	int rc;
	ss_FILE fd;
	uint8_t *line_buf;
	size_t fgets_rc;
	struct ss_buf *result;

	rc = gen_abs_host_path(host_path, path, false, "read");
	if (rc < 0) {
		SS_LOGP(SSTORAGE, LERROR, "%s: unable to generate path to load file content\n", "read");
		return NULL;
	}

	line_buf = SS_ALLOC_N(read_len);
	if (!line_buf) {
		SS_LOGP(SSTORAGE, LERROR, "unable to allocate read buffer (read_len=%u) for file: %s\n",
			(unsigned int)read_len, host_path);
		return NULL;
	}
	memset(line_buf, 0, read_len);

	fd = ss_fopen(host_path, "r");
	if (!fd) {
		SS_LOGP(SSTORAGE, LERROR, "unable to open content file: %s\n", host_path);
		SS_FREE(line_buf);
		return NULL;
	}

	rc = ss_fseek(fd, read_offset, SEEK_SET);
	if (rc != 0) {
		SS_LOGP(SSTORAGE, LERROR, "unable to seek (read_offset=%u) requested data in content file: %s\n",
			(unsigned int)read_offset, host_path);
		SS_FREE(line_buf);
		ss_fclose(fd);
		return NULL;
	}

	fgets_rc = ss_fread(line_buf, 1, read_len, fd);
	if (fgets_rc != read_len) {
		SS_LOGP(SSTORAGE, LERROR,
			"unable to load content (read_offset=%u, read_len=%u) from file: "
			"%s\n",
			(unsigned int)read_offset, (unsigned int)read_len, host_path);
		SS_FREE(line_buf);
		ss_fclose(fd);
		return NULL;
	}

	ss_fclose(fd);

	result = ss_buf_alloc_and_cpy(line_buf, fgets_rc);
	SS_FREE(line_buf);
	if (!result) {
		SS_LOGP(SSTORAGE, LERROR, "unable to allocate result buffer (len=%u) for file: %s\n",
			(unsigned int)fgets_rc, host_path);
		return NULL;
	}
	return result;
}

int ss_storage_write_file(const struct ss_list *path, const uint8_t *data, size_t write_offset, size_t write_len)
{
	char host_path[SS_STORAGE_PATH_MAX + 1];
	int rc;
	ss_FILE fd;
	size_t fwrite_rc;

	rc = gen_abs_host_path(host_path, path, false, "write");
	if (rc < 0) {
		SS_LOGP(SSTORAGE, LERROR, "%s: unable to generate path to load file content\n", "write");
		return -EINVAL;
	}

	fd = ss_fopen(host_path, "r+");
	if (!fd) {
		SS_LOGP(SSTORAGE, LERROR, "unable to open content file: %s\n", host_path);
		return -EINVAL;
	}

	rc = ss_fseek(fd, write_offset, SEEK_SET);
	if (rc != 0) {
		SS_LOGP(SSTORAGE, LERROR, "unable to seek (write_offset=%u) data to content file: %s\n", (unsigned int)write_offset,
			host_path);
		ss_fclose(fd);
		return -EINVAL;
	}

	fwrite_rc = ss_fwrite(data, 1, write_len, fd);

	if (fwrite_rc != write_len) {
		SS_LOGP(SSTORAGE, LERROR, "unable to write (write_offset=%u, write_len=%u) data to content file: %s\n",
			(unsigned int)write_offset, (unsigned int)write_len, host_path);
		ss_fclose(fd);
		return -EINVAL;
	}
	ss_fclose(fd);

	return 0;
}

size_t ss_storage_get_file_len(const struct ss_list *path)
{
	char host_path[SS_STORAGE_PATH_MAX + 1];
	int rc;
	long file_size;

	rc = gen_abs_host_path(host_path, path, false, "file-len");
	if (rc < 0) {
		SS_LOGP(SSTORAGE, LERROR, "%s: unable to generate path to load file content\n", "file-len");
		return 0;
	}

	file_size = ss_file_size(host_path);
	if (file_size < 0) {
		SS_LOGP(SSTORAGE, LERROR, "unable to tell the size of the file: %s\n", host_path);
		return 0;
	}

	return file_size;
}

int ss_storage_delete(const struct ss_list *path)
{
	char host_path_def[SS_STORAGE_PATH_MAX + 1];
	char host_path_content[SS_STORAGE_PATH_MAX + 1];
	struct ss_file *file;
	int rc;

	file = ss_get_file_from_path(path);
	if (!file)
		return -EINVAL;

	rc = gen_abs_host_path(host_path_def, path, true, "delete");
	if (rc < 0) {
		SS_LOGP(SSTORAGE, LERROR, "%s: unable to generate path to load file definition\n", "delete");
		return -EINVAL;
	}
	rc = gen_abs_host_path(host_path_content, path, false, "delete");
	if (rc < 0) {
		SS_LOGP(SSTORAGE, LERROR, "%s: unable to generate path to load file content\n", "delete");
		return -EINVAL;
	}

	rc = ss_delete_file(host_path_def);
	if (rc < 0) {
		SS_LOGP(SSTORAGE, LERROR, "unable to remove definition file: %s\n", host_path_def);
		return -EINVAL;
	}

	rc = ss_delete_file(host_path_content);
	if (rc < 0) {
		rc = ss_delete_dir(host_path_content);
		if (rc < 0) {
			SS_LOGP(SSTORAGE, LERROR, "unable to remove content file: %s\n", host_path_content);
			return -EINVAL;
		}
	}

	return 0;
}

int ss_storage_update_def(const struct ss_list *path)
{
	char host_path[SS_STORAGE_PATH_MAX + 1];
	int rc;
	ss_FILE fd;
	struct ss_file *file;
	size_t fwrite_rc;

	file = ss_get_file_from_path(path);
	if (!file)
		return -EINVAL;

	if (!file->fci) {
		SS_LOGP(SSTORAGE, LERROR, "file (%04x) has no definition (FCP) set -- abort\n", file->fid);
		return -EINVAL;
	}

	/* Generate definition file */
	rc = gen_abs_host_path(host_path, path, true, "update-def");
	if (rc < 0) {
		SS_LOGP(SSTORAGE, LERROR, "%s: unable to generate path to load file definition\n", "update-def");
		return -EINVAL;
	}

	fd = ss_fopen(host_path, "w");
	if (!fd) {
		SS_LOGP(SSTORAGE, LERROR, "unable to create definition file: %s\n", host_path);
		return -EINVAL;
	}

	fwrite_rc = ss_fwrite(file->fci->data, file->fci->len, 1, fd);

	if (fwrite_rc != 1) {
		SS_LOGP(SSTORAGE, LERROR, "unable to write file definition: %s\n", host_path);
		ss_storage_delete(path);
		ss_fclose(fd);
		return -EINVAL;
	}
	ss_fclose(fd);
	return 0;
}

int ss_storage_create_file(const struct ss_list *path, size_t file_len)
{
	/*! Note: This function must not be called with pathes that point to a directory! */
	char host_path[SS_STORAGE_PATH_MAX + 1];
	int rc;
	ss_FILE fd;
	size_t i;

	/* Create definition file */
	rc = ss_storage_update_def(path);
	if (rc < 0)
		return -EINVAL;

	/* Generate (empty) content file */
	rc = gen_abs_host_path(host_path, path, false, "create-file");
	if (rc < 0) {
		SS_LOGP(SSTORAGE, LERROR, "%s: unable to generate path to load file content\n", "create-file");
		ss_storage_delete(path);
		return -EINVAL;
	}
	fd = ss_fopen(host_path, "w");
	if (!fd) {
		SS_LOGP(SSTORAGE, LERROR, "unable to create content file: %s\n", host_path);
		ss_storage_delete(path);
		return -EINVAL;
	}
	uint8_t f = 0xff;
	for (i = 0; i < file_len; i++) {
		if (ss_fwrite(&f, 1, 1, fd) != 1) {
			SS_LOGP(SSTORAGE, LERROR, "unable to prefill content file: %s\n", host_path);
			ss_storage_delete(path);
			ss_fclose(fd);
			return -EINVAL;
		}
	}
	ss_fclose(fd);

	return 0;
}

int ss_storage_create_dir(const struct ss_list *path)
{
	/*! Note: Creates a directory entry at the given path. The path's parent directory must already exist. */
	char host_path[SS_STORAGE_PATH_MAX + 1];
	int rc;

	/* Create definition file */
	rc = ss_storage_update_def(path);
	if (rc < 0)
		return -EINVAL;

	/* Create directory */
	rc = gen_abs_host_path(host_path, path, false, "create-dir");
	if (rc < 0) {
		SS_LOGP(SSTORAGE, LERROR, "%s: unable to generate path to load file content\n", "create-dir");
		ss_storage_delete(path);
		return -EINVAL;
	}

	if (ss_access(host_path, W_OK) == 0)
		return 0;
	rc = ss_create_dir(host_path, 0700);
	if (rc < 0) {
		SS_LOGP(SSTORAGE, LERROR, "unable to create directory: %s\n", host_path);
		ss_storage_delete(path);
		return -EINVAL;
	}

	return 0;
}
