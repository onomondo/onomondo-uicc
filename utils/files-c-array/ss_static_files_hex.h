/*
 * Copyright (c) 2024 Onomondo ApS. All rights reserved.
 *
 * SPDX-License-Identifier: GPL-3.0-only
 */

#ifndef _ONOMONDO_STATICFILES
#define _ONOMONDO_STATICFILES

#include <stdint.h>

typedef struct {
    const char *name; const char *data; const uint32_t size;
} ss_file_t;

typedef struct {
    const char *name;
} ss_dir_t;

extern const ss_file_t *ss_files;
extern const ss_dir_t *ss_dirs;
extern const uint32_t ss_files_len;
extern const uint32_t ss_dirs_len;

#endif
