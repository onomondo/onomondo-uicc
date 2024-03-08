/*
 * Copyright (c) 2024 Onomondo ApS. All rights reserved.
 * 
 * SPDX-License-Identifier: GPL-3.0-only 
 */

#pragma once

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <onomondo/softsim/mem.h>
#define MSG_DEBUG
#define wpa_hexdump(x, args...)
#define wpa_hexdump_key(x, args...)
#define wpa_printf(x, args...)

#define os_memcpy(x, y, z) memcpy(x, y, z)
#define os_memcmp(x, y, z) memcmp(x, y, z)
#define os_memcmp_const(x, y, z) memcmp(x, y, z)
#define os_memset(x, y, z) memset(x, y, z)
#define os_malloc(x) SS_ALLOC_N(x)
#define os_free(x) SS_FREE(x)

typedef uint8_t u8;
typedef uint32_t u32;

static inline u32 WPA_GET_BE32(const u8 *a)
{
	return ((u32) a[0] << 24) | (a[1] << 16) | (a[2] << 8) | a[3];
}

static inline void WPA_PUT_BE32(u8 *a, u32 val)
{
	a[0] = (val >> 24) & 0xff;
	a[1] = (val >> 16) & 0xff;
	a[2] = (val >> 8) & 0xff;
	a[3] = val & 0xff;
}
typedef uint64_t u64;

#define __must_check
