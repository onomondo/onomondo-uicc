/*
 * Copyright (c) 2026 Onomondo ApS. All rights reserved.
 *
 * SPDX-License-Identifier: GPL-3.0-only
 */

#pragma once

#include <stddef.h>

/* Private to the utils sources, not installed.
 *
 * utils is optional and stays self-contained, so it keeps its own copy of the
 * core's ss_memzero() rather than reaching into the uicc library. static inline,
 * so it adds no symbol that could clash with the core's. */

/*! Clear memory that held key material or PINs, in a way the compiler does not
 *  optimize away: the stores go through a volatile pointer, so they are kept
 *  even to storage the compiler can see is dead.
 *  \param[out] ptr memory to clear
 *  \param[in] len number of bytes */
static inline void ss_utils_memzero(void *ptr, size_t len)
{
	volatile unsigned char *p = (volatile unsigned char *)ptr;
	size_t i;

	for (i = 0; i < len; i++)
		p[i] = 0;
}
