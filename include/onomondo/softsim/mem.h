/*
 * Copyright (c) 2024 Onomondo ApS. All rights reserved.
 * 
 * SPDX-License-Identifier: GPL-3.0-only 
 */

#pragma once

#include <stdlib.h>

#define SS_ALLOC(obj) malloc(sizeof(obj))
#define SS_ALLOC_N(n) malloc(n)
#define SS_FREE(obj) free(obj)
