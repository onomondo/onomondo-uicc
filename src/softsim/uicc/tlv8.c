/*
 * Copyright (c) 2024 Onomondo ApS. All rights reserved.
 *
 * SPDX-License-Identifier: GPL-3.0-only
 *
 * Author: Philipp Maier
 */

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <assert.h>
#include <onomondo/softsim/log.h>
#include <onomondo/softsim/list.h>
#include <onomondo/softsim/utils.h>
#include <onomondo/softsim/mem.h>
#include "tlv8.h"

/* Advance the bufer and check if we are still in bounds. The parameter "inc"
 * sets how many bytes the buffer pointer (enc) should be be advanced. The
 * parameter "bytes_ahead" sets the minimum valid bytes that the caller expects
 * to be available after the buffer pointer (enc) has been advanced. */
#define CHECK_AND_ADVANCE(inc, bytes_ahead)                                                                    \
	if (len < bytes_used + inc + bytes_ahead) {                                                            \
		SS_LOGP(STLV8, LDEBUG,                                                                         \
			"exceeding buffer bounds: len=%zu, inc=%zu, bytes_ahead=%zu, cannot decode IE\n", len, \
			(size_t)inc, (size_t)bytes_ahead);                                                     \
		return NULL;                                                                                   \
	}                                                                                                      \
	bytes_used += inc;                                                                                     \
	enc += inc

static struct tlv8_ie *decode_ie(size_t *used_len, const uint8_t *enc, size_t len)
{
	struct tlv8_ie ie;
	struct tlv8_ie *ie_ret;
	size_t bytes_used = 0;
	uint8_t ie_len = 0;
	const uint8_t *value;

	*used_len = 0;
	memset(&ie, 0, sizeof(ie));

	/* We expect at least 1 byte tag + 1 byte len */
	if (len < 2)
		return NULL;

	/* Decode tag */
	ie.tag = *enc;
	CHECK_AND_ADVANCE(1, 1);

	/* Decode length */
	ie_len = *enc;
	CHECK_AND_ADVANCE(1, ie_len);

	value = enc;
	CHECK_AND_ADVANCE(ie_len, 0);
	*used_len = bytes_used;

	/* Create output struct */
	ie_ret = SS_ALLOC(struct tlv8_ie);
	if (!ie_ret)
		return NULL;
	memcpy(ie_ret, &ie, sizeof(ie));

	/* Copy data part to the newly allocated item */
	ie_ret->value = ss_buf_alloc(ie_len);
	memcpy(ie_ret->value->data, value, ie_len);

	return ie_ret;
}

/*! Decode binary TLV8 encoded data.
 *  \param[in] enc pointer to buffer with encoded TLV8 data.
 *  \param[in] len length of the buffer that contains the TLV8 encoded data.
 *  \returns pointer to allocated linked list with TLV8 data (can be empty). */
struct ss_list *ss_tlv8_decode(const uint8_t *enc, size_t len)
{
	size_t i;
	struct tlv8_ie *ie;
	size_t used_len;
	size_t remaining_len = len;

	struct ss_list *list;

	list = SS_ALLOC(struct ss_list);
	ss_list_init(list);
	do {
		/* Decode IE and store it in the given list */
		ie = decode_ie(&used_len, enc, remaining_len);
		if (ie) {
			ss_list_put(list, &ie->list);
		} else if (remaining_len > 0) {
			for (i = used_len; i < used_len + remaining_len; ++i) {
				if (enc[i] != 0xff) {
					SS_LOGP(STLV8, LERROR, "Error decoding TLV8 (%s).\n",
						ss_hexdump(&enc[used_len], remaining_len));
					ss_tlv8_free(list);
					return NULL;
				}
			}
		}

		/* Go to the next IE */
		enc += used_len;
		remaining_len -= used_len;
	} while (ie != NULL);

	return list;
}

static void dump_ie(struct tlv8_ie *ie, uint8_t indent, enum log_subsys subsys, enum log_level level)
{
	char indent_str[256];
	char *value_str;
	size_t value_len;
	char delimiter;

	memset(indent_str, ' ', indent);
	indent_str[indent] = '\0';

	if (ie == NULL) {
		SS_LOGP(subsys, level, "%s(NULL)\n", indent_str);
		return;
	}

	if (ie->value) {
		value_str = ss_hexdump(ie->value->data, ie->value->len);
		value_len = ie->value->len;
		delimiter = ':';
	} else {
		value_str = "";
		value_len = 0;
		delimiter = ' ';
	}

	SS_LOGP(subsys, level, "%s(tag=0x%02x, len=%zu)%c %s\n", indent_str, ie->tag, value_len, delimiter, value_str);
}

/*! Dump decoded TLV8 data.
 *  \param[in] list linked list begin of the TLV8 list.
 *  \param[in] indent indentation level of the generated output.
 *  \param[in] log_subsys log subsystem to generate the output for.
 *  \param[in] log_level log level to generate the output for. */
void ss_tlv8_dump(const struct ss_list *list, uint8_t indent, enum log_subsys log_subsys, enum log_level log_level)
{
	struct tlv8_ie *ie;

	SS_LIST_FOR_EACH(list, ie, struct tlv8_ie, list) {
		dump_ie(ie, indent, log_subsys, log_level);
	}
}

static void free_ie(struct tlv8_ie *ie)
{
	if (ie == NULL)
		return;

	if (ie->value)
		ss_buf_free(ie->value);

	/* Make sure all data vanishes from memory */
	memset(ie, 0, sizeof(*ie));

	SS_FREE(ie);
}

/*! Free TLV8 data (including list begin).
 *  \param[in] list linked list begin of the TLV8 list. */
void ss_tlv8_free(struct ss_list *list)
{
	struct tlv8_ie *ie;
	struct tlv8_ie *ie_pre;

	if (!list)
		return;

	if (ss_list_empty(list))
		return;

	SS_LIST_FOR_EACH_SAVE(list, ie, ie_pre, struct tlv8_ie, list) {
		/* Unlink the element from the list and free it. */
		ss_list_remove(&ie->list);
		free_ie(ie);
	}

	/* Get rid of the list isself */
	SS_FREE(list);
}

/*! Allocate a new TLV8 IE.
 *  \param[out] list linked list parent of the TLV8 list.
 *  \param[in] tag TLV8 tag (encoded format).
 *  \param[in] cr TLV8 comprehension flag.
 *  \param[in] len TLV8 value length.
 *  \param[in] value pointer to TLV8 value (data is copied).
 *  \returns pointer to allocated IE struct. */
struct tlv8_ie *ss_tlv8_new_ie(struct ss_list *list, uint8_t tag, size_t len, const uint8_t *value)
{
	struct tlv8_ie *ie = SS_ALLOC(struct tlv8_ie);

	memset(ie, 0, sizeof(*ie));
	ie->tag = tag;

	if (value) {
		ie->value = ss_buf_alloc(len);
		memcpy(ie->value->data, value, len);
	} else {
		ie->value = ss_buf_alloc(0);
	}

	if (list)
		ss_list_put(list, &ie->list);
	return ie;
}

/*! Get an IE from the list by its tag (on the current level).
 *  \param[in] list linked list begin of the TLV8 tree.
 *  \param[in] tag TLV8 (encoded format) tag to look for.
 *  \returns pointer to IE struct on success, NULL if IE is not found. */
struct tlv8_ie *ss_tlv8_get_ie(const struct ss_list *list, uint8_t tag)
{
	struct tlv8_ie *ie;

	if (!list)
		return NULL;

	SS_LIST_FOR_EACH(list, ie, struct tlv8_ie, list) {
		if (ie->tag == tag)
			return ie;
	}

	return NULL;
}

/*! Get an IE from the list by its tag, ensure minimum length (on the current level).
 *  \param[in] list linked list begin of the TLV8 tree.
 *  \param[in] tag TLV8 tag to look for.
 *  \param[in] min_len minimum required length.
 *  \returns pointer to IE struct on success, NULL if IE is not found. */
struct tlv8_ie *ss_tlv8_get_ie_minlen(const struct ss_list *list, uint8_t tag, size_t min_len)
{
	struct tlv8_ie *ie = ss_tlv8_get_ie(list, tag);
	if (!ie)
		return NULL;
	if (ie->value->len < min_len)
		return NULL;
	return ie;
}

static size_t encode_ie(uint8_t *enc, size_t len, struct tlv8_ie *ie)
{
	size_t ie_len;

	ie_len = ie->value->len + 2;

	/* Do not encode anything when we are unable to determine the length
	 * or when the predicted length exceeds the buffer. */
	if (ie_len == 0 || ie_len > len) {
		SS_LOGP(STLV8, LERROR, "not enough buffer space to encode TLV string, aborting at IE %02x.\n", ie->tag);
		return 0;
	}

	/* Encode tag */
	*enc = ie->tag;
	enc++;

	/* Encode len */
	*enc = ie->value->len;
	enc++;

	/* Encode data */
	memcpy(enc, ie->value->data, ie->value->len);

	return ie_len;
}

/*! Encode linked list with TLV8 data to its binary encoded representation.
 *  \param[out] enc pointer to buffer to output the encoded TLV8 data.
 *  \param[in] len length of the buffer that will store the output.
 *  \param[in] list linked list with TLV8 data to encode.
 *  \returns number of encoed bytes. */
size_t ss_tlv8_encode(uint8_t *enc, size_t len, const struct ss_list *list)
{
	size_t bytes_remain = len;
	struct tlv8_ie *ie;
	size_t rc;

	/* clear output buffer (just to be sure) */
	memset(enc, 0, len);

	SS_LIST_FOR_EACH(list, ie, struct tlv8_ie, list) {
		rc = encode_ie(enc, bytes_remain, ie);
		if (rc == 0)
			return 0;
		bytes_remain -= rc;
		enc += rc;
	}

	return len - bytes_remain;
}

static size_t calc_tlv8_len(const struct ss_list *list)
{
	size_t bytes_needed = 0;
	struct tlv8_ie *ie;
	size_t rc;

	SS_LIST_FOR_EACH(list, ie, struct tlv8_ie, list) {
		rc = ie->value->len + 2;
		if (rc == 0)
			return 0;
		bytes_needed += rc;
	}

	return bytes_needed;
}

/*! Encode linked list with TLV8 data to its binary encoded representation (to ss_buf).
 *  \param[inout] list linked list with TLV8 data to encode.
 *  \returns ss_buf with encoded result. */
struct ss_buf *ss_tlv8_encode_to_ss_buf(const struct ss_list *list)
{
	size_t bytes_needed;
	struct ss_buf *buf;

	bytes_needed = calc_tlv8_len(list);
	buf = ss_buf_alloc(bytes_needed);
	ss_tlv8_encode(buf->data, buf->len, list);

	return buf;
}
