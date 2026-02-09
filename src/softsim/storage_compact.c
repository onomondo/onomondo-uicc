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
#include <sys/stat.h>
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
	static char *host_fs_path_ptr;
	struct ss_file *path_cursor;
	struct ss_file *path_last = NULL;
	int rc;

	if (ss_list_empty(path))
		return -EINVAL;

	memset(host_fs_path, 0, sizeof(host_fs_path));
	host_fs_path_ptr = host_fs_path;

#ifdef CONFIG_ALT_FILE_SEPERATOR
	SS_LIST_FOR_EACH(path, path_cursor, struct ss_file, list) {
		rc = snprintf(host_fs_path_ptr, sizeof(host_fs_path) - (host_fs_path_ptr - host_fs_path),
			      path_cursor->fid > 0xffff ? "_%08x" : "_%04x",
			      /* Proprietary files (SEQ) identified by 0xa1xx got the same FCP association. */
			      (path_cursor->fid & 0xff00) == 0xa100 && def ? 0xa100 : path_cursor->fid);
		host_fs_path_ptr += rc;
		path_last = path_cursor;
	}
#else
	SS_LIST_FOR_EACH(path, path_cursor, struct ss_file, list) {
		rc = snprintf(host_fs_path_ptr, sizeof(host_fs_path) - (host_fs_path_ptr - host_fs_path),
			      path_cursor->fid > 0xffff ? "/%08x" : "/%04x",
			      /* Proprietary files (SEQ) identified by 0xa1xx got the same FCP association. */
			      (path_cursor->fid & 0xff00) == 0xa100 && def ? 0xa100 : path_cursor->fid);
		host_fs_path_ptr += rc;
		path_last = path_cursor;
	}
#endif
	if (def) {
		snprintf(abs_host_fs_path, sizeof(abs_host_fs_path), "%s%s.def", storage_path, host_fs_path);

		SS_LOGP(SSTORAGE, LINFO, "%s: requested file definition for %04x on host file system : %s\n", division,
			path_last->fid, abs_host_fs_path);

	} else {
		snprintf(abs_host_fs_path, sizeof(abs_host_fs_path), "%s%s", storage_path, host_fs_path);
		SS_LOGP(SSTORAGE, LINFO, "%s: requested file content for %04x on host file system: %s\n", division,
			path_last->fid, abs_host_fs_path);
	}

	strncpy(def_path, abs_host_fs_path, SS_STORAGE_PATH_MAX);

	return 0;
}

/* Read file definition from the host file system */
static int read_file_def(char *host_path, struct ss_file *file)
{
	ss_FILE fd;
	char line_buf[200]; /* maximum fcp length */
	char *rc;

	fd = ss_fopen(host_path, "r");
	if (!fd) {
		SS_LOGP(SSTORAGE, LERROR, "unable to open definition file: %s\n", host_path);
		return -EINVAL;
	}

	rc = ss_fread(line_buf, 1, sizeof(line_buf), fd);
	ss_fclose(fd);
	if (!rc) {
		SS_LOGP(SSTORAGE, LERROR, "unable to read definition file: %s\n", host_path);
		return -EINVAL;
	}

	file->fci = ss_buf_alloc_and_cpy(line_buf, rc);

	return 0;
}

/*! Get file definition for a file (tip of the path).
 *  \param[inout] path to the file for which the definition should be read.
 *  \returns 0 on success, -EINVAL on failure */
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

/*! Get content from a file (tip of the path).
 *  \param[in] path path to the file to be read.
 *  \param[in] read_offset offset to start reading the file at.
 *  \param[in] read_len length of data to read.
 *  \returns buffer with content data on success, NULL on failure. */
struct ss_buf *ss_storage_read_file(const struct ss_list *path, size_t read_offset, size_t read_len)
{
	/*! Note: This function will allocate memory in file to store the file
	 *  contents. The caller must take care of freeing. */
	char host_path[SS_STORAGE_PATH_MAX + 1];
	int rc;
	ss_FILE *fd;
	char *line_buf;
	size_t fgets_rc;
	struct ss_buf *result;

	rc = gen_abs_host_path(host_path, path, false, "read");
	if (rc < 0) {
		SS_LOGP(SSTORAGE, LERROR, "%s: unable to generate path to load file content\n", "read");
		return NULL;
	}

	line_buf = SS_ALLOC_N(read_len);
	memset(line_buf, 0, read_len);

	fd = ss_fopen(host_path, "r");
	if (!fd) {
		SS_LOGP(SSTORAGE, LERROR, "unable to open content file: %s\n", host_path);
		SS_FREE(line_buf);
		return NULL;
	}

	rc = ss_fseek(fd, read_offset, SEEK_SET);
	if (rc != 0) {
		SS_LOGP(SSTORAGE, LERROR, "unable to seek (read_offset=%zu) requested data in content file: %s\n",
			read_offset, host_path);
		SS_FREE(line_buf);
		ss_fclose(fd);
		return NULL;
	}

	fgets_rc = ss_fread(line_buf, 1, read_len, fd);
	if (fgets_rc != read_len) {
		SS_LOGP(SSTORAGE, LERROR,
			"unable to load content (read_offset=%zu, read_len=%zu) from file: "
			"%s\n",
			read_offset, read_len, host_path);
		SS_FREE(line_buf);
		ss_fclose(fd);
		return NULL;
	}

	ss_fclose(fd);

	result = ss_buf_alloc_and_cpy(line_buf, fgets_rc);
	SS_FREE(line_buf);
	return result;
}

/*! Write data to a file (tip of the path).
 *  \param[in] path path to the file to be written.
 *  \param[in] write_offset offset to start writing the file at.
 *  \param[in] write_len length of data to be written.
 *  \returns 0 on success, -EINVAL on failure. */
int ss_storage_write_file(const struct ss_list *path, const uint8_t *data, size_t write_offset, size_t write_len)
{
	char host_path[SS_STORAGE_PATH_MAX + 1];
	int rc;
	FILE *fd;
	size_t i = 0;
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
		SS_LOGP(SSTORAGE, LERROR, "unable to seek (write_offset=%zu) data to content file: %s\n", write_offset,
			host_path);
		ss_fclose(fd);
		return -EINVAL;
	}

	fwrite_rc = ss_fwrite(data, 1, write_len, fd);

	if (fwrite_rc != write_len) {
		SS_LOGP(SSTORAGE, LERROR, "unable to write (write_offset=%zu+%zu) data to content file: %s\n",
			write_offset, i, host_path);
		ss_fclose(fd);
		return -EINVAL;
	}
	ss_fclose(fd);

	return 0;
}

/*! Get the total size in bytes of a file.
 *  \param[in] path path to the file that gets selected.
 *  \returns size in bytes on success, 0 on failure. */
size_t ss_storage_get_file_len(const struct ss_list *path)
{
	char host_path[SS_STORAGE_PATH_MAX + 1];
	int rc;
	FILE *fd;
	long file_size;

	/* TODO: Check if the path really points to a file. If the path points
	 * to a directory, print an error and return a size of 0. (Normally this
	 * shouldn't happen because the FCP is always checked before calling
	 * this function.) */

	rc = gen_abs_host_path(host_path, path, false, "file-len");
	if (rc < 0) {
		SS_LOGP(SSTORAGE, LERROR, "%s: unable to generate path to load file content\n", "file-len");
		return 0;
	}

	fd = ss_fopen(host_path, "r");
	if (!fd) {
		SS_LOGP(SSTORAGE, LERROR, "unable to open content file: %s\n", host_path);
		return 0;
	}

	rc = ss_fseek(fd, 0, SEEK_END);
	if (rc != 0) {
		SS_LOGP(SSTORAGE, LERROR, "unable to seek requested data in content file: %s\n", host_path);
		ss_fclose(fd);
		return 0;
	}

	file_size = ss_ftell(fd);
	if (file_size < 0) {
		SS_LOGP(SSTORAGE, LERROR, "unable to tell the size of the file: %s\n", host_path);
		ss_fclose(fd);
		return 0;
	}

	ss_fclose(fd);

	return file_size;
}

/*! Delete a file or directory in the file system.
 *  \param[in] path path to the file or directory to delete.
 *  \returns 0 on success, -EINVAL on failure. */
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

	rc = ss_remove(host_path_def);
	if (rc < 0) {
		SS_LOGP(SSTORAGE, LERROR, "unable to remove definition file: %s\n", host_path_def);
		return -EINVAL;
	}

	rc = ss_rmdir(host_path_content);
	if (rc < 0) {
		SS_LOGP(SSTORAGE, LERROR, "unable to remove content file: %s\n", host_path_content);
		return -EINVAL;
	}

	return 0;
}

/*! Update the definition file in the file system.
 *  \param[in] path path to the file to update.
 *  \returns 0 on success, -EINVAL on failure. */
int ss_storage_update_def(const struct ss_list *path)
{
	char host_path[SS_STORAGE_PATH_MAX + 1];
	int rc;
	FILE *fd;
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

	if (fwrite_rc != file->fci->len) {
		SS_LOGP(SSTORAGE, LERROR, "unable to write file definition: %s\n", host_path);
		ss_storage_delete(path);
		ss_fclose(fd);
		return -EINVAL;
	}
	ss_fclose(fd);
	return 0;
}

/*! Create a file in the file system.
 *  \param[in] path path to the file that gets selected.
 *  \param[in] file_len length of the file to create (filled with 0xff).
 *  \returns 0 on success, -EINVAL on failure. */
int ss_storage_create_file(const struct ss_list *path, size_t file_len)
{
	/*! Note: This function must not be called with pathes that point to a directory! */
	char host_path[SS_STORAGE_PATH_MAX + 1];
	int rc;
	ss_FILE *fd;
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

/*! Create a directory in the file system.
 *  \param[in] path path to the directory to create.
 *  \returns 0 on success, -EINVAL on failure. */
int ss_storage_create_dir(const struct ss_list *path)
{
	/*! Note: This function must not be called with pathes that point to a directory! */
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
	rc = ss_mkdir(host_path, 0700);
	if (rc < 0) {
		SS_LOGP(SSTORAGE, LERROR, "unable to create directory: %s\n", host_path);
		ss_storage_delete(path);
		return -EINVAL;
	}

	return 0;
}
