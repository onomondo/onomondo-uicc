/*
 * Copyright (c) 2024 Onomondo ApS. All rights reserved.
 * 
 * SPDX-License-Identifier: GPL-3.0-only 
 */

#pragma once

#include <assert.h>
#include <stdint.h>
#include <string.h>
#include "mem.h"

#define SS_ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))

char *ss_hexdump(const uint8_t *data, size_t len);
size_t ss_binary_from_hexstr(uint8_t *binary, size_t binary_len, const char *hexstr);


struct ss_buf {
	uint8_t *data;
	size_t len;
};

/*! Generate a hexdump string from an ss_buf object.
 *  \param[in] buf pointer to ss_buf object.
 *  \returns pointer to generated human readable string. */
static inline char *ss_buf_hexdump(const struct ss_buf *buf)
{
	if (!buf)
		return "(null)";
	return ss_hexdump(buf->data, buf->len);
}

/*! Allocate a new ss_buf object.
 *  \param[in] len number of bytes to allocate inside ss_buf.
 *  \returns pointer to newly allocated ss_buf object. */
static inline struct ss_buf *ss_buf_alloc(size_t len)
{
	struct ss_buf *sb = SS_ALLOC_N(sizeof(*sb) + len);
	assert(sb);

	sb->data = (uint8_t *) sb + sizeof(*sb);
	sb->len = len;

	return sb;
}

/*! Allocate a new ss_buf and copy from user provided memory.
 *  \param[in] in user provided memory to copy.
 *  \param[in] len amount of bytes to copy from user provided memory.
 *  \returns pointer to newly allocated ss_buf object. */
static inline struct ss_buf *ss_buf_alloc_and_cpy(const uint8_t *in, size_t len)
{
	struct ss_buf *sb = ss_buf_alloc(len);
	memcpy(sb->data, in, len);
	return sb;
}

/*! Allocate a new ss_buf and copy from another ss_buf object.
 *  \param[in] buf ss_buf object to copy from.
 *  \returns pointer to newly allocated ss_buf object. */
static inline struct ss_buf *ss_buf_dup(const struct ss_buf *buf)
{
	struct ss_buf *buf_dup = ss_buf_alloc(buf->len);
	memcpy(buf_dup->data, buf->data, buf->len);
	return buf_dup;
}

/*! Free an ss_buf object.
 *  \param[in] pointer to ss_buf object to free. */
static inline void ss_buf_free(struct ss_buf *buf)
{
	SS_FREE(buf);
}

struct ss_buf *ss_buf_from_hexstr(const char *hexstr);
uint32_t ss_uint32_from_array(const uint8_t *array, size_t len);
void ss_array_from_uint32(uint8_t *array, size_t len, uint32_t in);
uint64_t ss_uint64_from_array(const uint8_t *array, size_t len);
void ss_array_from_uint64(uint8_t *array, size_t len, uint64_t in);
size_t ss_optimal_len_for_uint32(uint32_t in);

uint64_t ss_uint64_load_from_be(const uint8_t *storage);
void ss_uint64_store_to_be(uint8_t *storage, uint64_t number);
size_t ss_strnlen(const char *s, size_t maxlen);
