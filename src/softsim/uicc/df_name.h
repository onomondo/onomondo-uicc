/*
 * Copyright (c) 2024 Onomondo ApS. All rights reserved.
 * 
 * SPDX-License-Identifier: GPL-3.0-only 
 */

#pragma once

struct ss_list;

int ss_df_name_update(struct ss_list *path);
int ss_df_name_resolve(struct ss_list *path, const uint8_t *df_name,
		       size_t df_name_len);
