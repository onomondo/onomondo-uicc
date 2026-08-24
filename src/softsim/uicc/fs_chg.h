/*
 * Copyright (c) 2024 Onomondo ApS. All rights reserved.
 * 
 * SPDX-License-Identifier: GPL-3.0-only 
 */

#pragma once
struct ss_list;

/* Both overridable at build time. A packed path is 2 bytes per FID plus a
 * 2-byte 0x3F00 terminator, so the deepest standard path (MF/DF/DF/EF) packs
 * into 10 bytes; pack_path() requires an even SS_FS_CHG_PATH_MAXLEN. The
 * list is a byte budget holding variable-length paths, sized here for
 * SS_FS_CHG_MAX_FILES worst-case ones. It is allocated twice per SIM session
 * (standalone and inside the REFRESH state), so a port on a small heap may
 * want to shrink these. */
#ifndef SS_FS_CHG_PATH_MAXLEN
#define SS_FS_CHG_PATH_MAXLEN 20 /* bytes */
#endif
#ifndef SS_FS_CHG_MAX_FILES
#define SS_FS_CHG_MAX_FILES 100
#endif
#define SS_FS_CHG_BUF_SIZE (SS_FS_CHG_PATH_MAXLEN * SS_FS_CHG_MAX_FILES) /* bytes */

#if (SS_FS_CHG_PATH_MAXLEN % 2) || (SS_FS_CHG_PATH_MAXLEN < 10)
#error SS_FS_CHG_PATH_MAXLEN must be even and at least 10 (MF/DF/DF/EF plus terminator)
#endif

int ss_fs_chg_add(uint8_t filelist[SS_FS_CHG_BUF_SIZE], const struct ss_list *path);
int ss_fs_chg_len(const uint8_t filelist[SS_FS_CHG_BUF_SIZE]);
void ss_fs_chg_dump(const uint8_t filelist[SS_FS_CHG_BUF_SIZE], uint8_t indent, enum log_subsys subsys,
		    enum log_level level);
