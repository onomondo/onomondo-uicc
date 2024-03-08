/*
 * Copyright (c) 2024 Onomondo ApS. All rights reserved.
 * 
 * SPDX-License-Identifier: GPL-3.0-only 
 */

#pragma once

#ifdef CONFIG_USE_SYSTEM_HEAP
#include <stdlib.h>

#define SS_ALLOC(obj) malloc(sizeof(obj))
#define SS_ALLOC_N(n) malloc(n)
#define SS_FREE(obj) free(obj)
#else  // DEFAULT
void *port_malloc(size_t);
void port_free(void *);
#define SS_ALLOC(obj) port_malloc(sizeof(obj));
#define SS_ALLOC_N(n) port_malloc(n);
#define SS_FREE(obj) port_free(obj);
#endif	// CONFIG_USE_SYSTEM_HEAP
