/*
 * Copyright (c) 2024 Onomondo ApS. All rights reserved.
 * 
 * SPDX-License-Identifier: GPL-3.0-only 
 */

#pragma once
struct ss_list;

#define SS_FS_CHG_PATH_MAXLEN 20	/* bytes */
#define SS_FS_CHG_BUF_SIZE SS_FS_CHG_PATH_MAXLEN * 100	/* bytes */

int ss_fs_chg_add(uint8_t filelist[SS_FS_CHG_BUF_SIZE], const struct ss_list *path);
int ss_fs_chg_len(const uint8_t filelist[SS_FS_CHG_BUF_SIZE]);
void ss_fs_chg_dump(const uint8_t filelist[SS_FS_CHG_BUF_SIZE], uint8_t indent,
		    enum log_subsys subsys, enum log_level level);
