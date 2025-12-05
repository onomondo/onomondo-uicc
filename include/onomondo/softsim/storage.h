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

extern char storage_path[SS_STORAGE_PATH_MAX];

/*! Set the SoftSIM filesystem storage path.
 *  \param[in] path New storage path. Must be non-NULL and non-empty, and shorter than SS_STORAGE_PATH_MAX.
 *  \returns 0 on success, -1 on failure (NULL, empty, or too long path). */
int ss_storage_set_path(const char *path);

/*! Get the current SoftSIM filesystem storage path.
 *  \returns Pointer to the current storage path. */
const char *ss_storage_get_path(void);

int ss_storage_get_file_def(struct ss_list *path);
struct ss_buf *ss_storage_read_file(const struct ss_list *path, size_t read_offset, size_t read_len);
size_t ss_storage_get_file_len(const struct ss_list *path);
int ss_storage_write_file(const struct ss_list *path, const uint8_t *data, size_t write_offset, size_t write_len);
int ss_storage_delete(const struct ss_list *path);
int ss_storage_update_def(const struct ss_list *path);
int ss_storage_create_file(const struct ss_list *path, size_t file_len);
int ss_storage_create_dir(const struct ss_list *path);
