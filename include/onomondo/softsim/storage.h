/*
 * Copyright (c) 2024 Onomondo ApS. All rights reserved.
 *
 * SPDX-License-Identifier: GPL-3.0-only
 */

#pragma once

#include <stdint.h>
#include <stddef.h>

struct ss_buf;
struct ss_list;

/* Default storage path if not configured */
#ifndef SS_STORAGE_PATH_DEFAULT
#define SS_STORAGE_PATH_DEFAULT "./files"
#endif

/* Maximum path length for storage operations. Setting the maximum path length prevents buffer overflows and ensures
consistent behavior across different storage backends. But a tradeoff is excess memory usage if the maximum path length is
set higher than necessary. */
#ifndef SS_STORAGE_PATH_MAX
#define SS_STORAGE_PATH_MAX 100
#endif

#ifdef CONFIG_ALT_FILE_SEPARATOR
#define PATH_SEPARATOR "_"
#else
#define PATH_SEPARATOR "/"
#endif

#ifdef CONFIG_COMPACT_STORAGE
#define FCP_MAX_LEN 200
#else
#define FCP_MAX_LEN 1024
#endif

extern char storage_path[SS_STORAGE_PATH_MAX];

/*! Set the SoftSIM filesystem storage path.
 *  \param[in] path New storage path. Must be non-NULL and non-empty, and shorter than SS_STORAGE_PATH_MAX.
 *  \returns 0 on success, -1 on failure (NULL, empty, or too long path). */
int ss_storage_set_path(const char *path);

/*! Get the current SoftSIM filesystem storage path.
 *  \returns Pointer to the current storage path. */
const char *ss_storage_get_path(void);

/*! Get file definition for file (tip of the path).
 *  \param[inout] path to the file for which the definition should be read.
 *  \returns 0 on success, -EINVAL on failure */
int ss_storage_get_file_def(struct ss_list *path);

/*! Get content from file (tip of the path).
 *  \param[in] path path to the file to be read.
 *  \param[in] read_offset offset to start reading the file at.
 *  \param[in] read_len length of data to read.
 *  \returns buffer with content data on success, NULL on failure. */
struct ss_buf *ss_storage_read_file(const struct ss_list *path, size_t read_offset, size_t read_len);

/*! Get the total size in bytes of a file.
 *  \param[in] path path to the file that gets selected.
 *  \returns size in bytes on success, 0 on failure. */
size_t ss_storage_get_file_len(const struct ss_list *path);

/*! Write data to a file (tip of the path).
 *  \param[in] path path to the file to be written.
 *  \param[in] write_offset offset to start writing the file at.
 *  \param[in] write_len length of data to be written.
 *  \returns 0 on success, -EINVAL on failure. */
int ss_storage_write_file(const struct ss_list *path, const uint8_t *data, size_t write_offset, size_t write_len);

/*! Delete file or directory in the file system.
 *  \param[in] path path to the file or directory to delete.
 *  \returns 0 on success, -EINVAL on failure. */
int ss_storage_delete(const struct ss_list *path);

/*! Update definition file in the file system.
 *  \param[in] path path to the file to update.
 *  \returns 0 on success, -EINVAL on failure */
int ss_storage_update_def(const struct ss_list *path);

/*! Create a file in the file system.
 *  \param[in] path path to the file that gets selected.
 *  \param[in] file_len length of the file to create (filled with 0xff).
 *  \returns 0 success, -EINVAL on failure */
int ss_storage_create_file(const struct ss_list *path, size_t file_len);

/*! Create a directory in the file system.
 *  \param[in] path path to the directory to create.
 *  \returns 0 on success, -EINVAL on failure */
int ss_storage_create_dir(const struct ss_list *path);
