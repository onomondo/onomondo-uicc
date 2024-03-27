/*
 * Copyright (c) 2024 Onomondo ApS. All rights reserved.
 *
 * SPDX-License-Identifier: GPL-3.0-only
 */

#pragma once

struct ss_buf;
struct ss_list;

// /* TODO #66: Make configurable (commandline option) */
extern char storage_path[];

#define PATH_MAX 100

int ss_storage_get_file_def(struct ss_list *path);
struct ss_buf *ss_storage_read_file(const struct ss_list *path, size_t read_offset, size_t read_len);
size_t ss_storage_get_file_len(const struct ss_list *path);
int ss_storage_write_file(const struct ss_list *path, const uint8_t *data, size_t write_offset, size_t write_len);
int ss_storage_delete(const struct ss_list *path);
int ss_storage_update_def(const struct ss_list *path);
int ss_storage_create_file(const struct ss_list *path, size_t file_len);
int ss_storage_create_dir(const struct ss_list *path);
