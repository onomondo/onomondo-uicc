/*
 * Copyright (c) 2024 Onomondo ApS. All rights reserved.
 * 
 * SPDX-License-Identifier: GPL-3.0-only 
 */

#pragma once

struct ss_file;
struct ss_list;

int ss_fs_select(struct ss_list *path, uint32_t fid);
void ss_fs_init(struct ss_list *path);
struct ss_buf *ss_fs_read_file_record(const struct ss_list *path,
				      size_t record_no);
int ss_fs_write_file_record(const struct ss_list *path, size_t record_no,
			    const uint8_t *data, size_t len);
int ss_fs_create(struct ss_list *path, const uint8_t *fcp_data, size_t fcp_len);
int ss_fs_select_parent(const struct ss_list *fs_path);
void ss_path_reset(struct ss_list *path);
struct ss_buf *ss_fs_read_relative_file_record(const struct ss_list *path,
					       uint16_t file_id,
					       uint8_t record_number);
