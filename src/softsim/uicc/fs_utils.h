/*
 * Copyright (c) 2024 Onomondo ApS. All rights reserved.
 * 
 * SPDX-License-Identifier: GPL-3.0-only 
 */

#pragma once

#include <stdbool.h>

char *ss_fs_utils_dump_path(const struct ss_list *path);
size_t ss_fs_utils_find_free_record(const struct ss_list *path);
size_t ss_fs_utils_find_record(const struct ss_list *path,
			       const uint8_t *template,
			       const uint8_t *mask, size_t len);
int ss_fs_utils_create_record_file(const struct ss_list *path, uint32_t fid,
				   uint16_t record_len,
				   uint8_t number_of_records);
int ss_fs_utils_path_clone(struct ss_list *path_copy, const struct ss_list *path);
int ss_fs_utils_path_select(struct ss_list *path_out, const struct ss_list *path);
bool ss_fs_utils_path_equals(const struct ss_list *path_a,
			     const struct ss_list *path_b);
struct ss_file *ss_fs_utils_get_current_df_from_path(const struct ss_list *path);
