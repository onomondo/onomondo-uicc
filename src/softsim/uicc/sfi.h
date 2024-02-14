/*
 * Copyright (c) 2024 Onomondo ApS. All rights reserved.
 * 
 * SPDX-License-Identifier: GPL-3.0-only 
 */

#pragma once

struct ss_list;

int ss_sfi_create(const struct ss_list *path);
int ss_sfi_update(const struct ss_list *path);
int ss_sfi_resolve(const struct ss_list *path, uint8_t sfi);
