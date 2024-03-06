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
#include "ctlv.h"

/* Advance the bufer and check if we are still in bounds. The parameter "inc"
 * sets how many bytes the buffer pointer (enc) should be be advanced. The
 * parameter "bytes_ahead" sets the minimum valid bytes that the caller expects
 * to be available after the buffer pointer (enc) has been advanced. */
#define CHECK_AND_ADVANCE(inc, bytes_ahead)                                                                    \
	if (len < bytes_used + inc + bytes_ahead) {                                                            \
		SS_LOGP(SCTLV, LDEBUG,                                                                         \
			"exceeding buffer bounds: len=%zu, inc=%zu, bytes_ahead=%zu, cannot decode IE\n", len, \
			(size_t)inc, (size_t)bytes_ahead);                                                     \
		return NULL;                                                                                   \
	}                                                                                                      \
	bytes_used += inc;                                                                                     \
	enc += inc

static struct cmp_tlv_ie *decode_ie(size_t *used_len, const uint8_t *enc, size_t len)
{
	struct cmp_tlv_ie ie;
	struct cmp_tlv_ie *ie_ret;
	size_t bytes_used = 0;
	uint32_t ie_len = 0;
	const uint8_t *value;

	*used_len = 0;
	memset(&ie, 0, sizeof(ie));

	/* We expect at least 1 byte tag + 1 byte len */
	if (len < 2)
		return NULL;

	/* Not used */
	if (*enc == 0xFF || *enc == 0x00)
		return NULL;

	/* Reserved for future use */
	if (*enc == 0x80)
		return NULL;

	/* Decode tag */
	if (*enc == 0x7F) {
		CHECK_AND_ADVANCE(1, 1);
		if (*enc & 0x80)
			ie.cr = true;
		ie.tag = *enc << 8;
		CHECK_AND_ADVANCE(1, 1);
		ie.tag |= *enc;
		ie.tag &= 0x7FFF;
	} else {
		if (*enc & 0x80)
			ie.cr = true;
		ie.tag = *enc;
		ie.tag &= 0x007F;
	}
	CHECK_AND_ADVANCE(1, 1);

	/* Decode length */
	if (*enc <= 0x7F) {
		ie_len = *enc;
	} else if (*enc == 0x81) {
		CHECK_AND_ADVANCE(1, 1);
		ie_len = *enc;
	} else if (*enc == 0x82) {
		CHECK_AND_ADVANCE(1, 1);
		ie_len = *enc << 8;
		CHECK_AND_ADVANCE(1, 1);
		ie_len |= *enc;
	} else if (*enc == 0x83) {
		CHECK_AND_ADVANCE(1, 1);
		ie_len = *enc << 16;
		CHECK_AND_ADVANCE(1, 1);
		ie_len |= *enc << 8;
		CHECK_AND_ADVANCE(1, 1);
		ie_len |= *enc;
	}
	CHECK_AND_ADVANCE(1, ie_len);

	value = enc;
	CHECK_AND_ADVANCE(ie_len, 0);
	*used_len = bytes_used;

	/* Create output struct */
	ie_ret = SS_ALLOC(struct cmp_tlv_ie);
	if (!ie_ret)
		return NULL;
	memcpy(ie_ret, &ie, sizeof(ie));

	/* Copy data part to the newly allocated item */
	ie_ret->value = ss_buf_alloc(ie_len);
	memcpy(ie_ret->value->data, value, ie_len);

	return ie_ret;
}

/*! Decode binary COMPREHENSION-TLV encoded data.
 *  \param[in] enc pointer to buffer with encoded COMPREHENSION-TLV data.
 *  \param[in] len length of the buffer that contains the COMPREHENSION-TLV encoded data.
 *  \returns pointer to allocated linked list with COMPREHENSION-TLV data (can be empty). */
struct ss_list *ss_ctlv_decode(const uint8_t *enc, size_t len)
{
	size_t i;
	struct cmp_tlv_ie *ie;
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
					SS_LOGP(SCTLV, LERROR, "Error decoding COMPREHENSION-BTLV (%s).\n",
						ss_hexdump(&enc[used_len], remaining_len));
					ss_ctlv_free(list);
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

static void dump_ie(const struct cmp_tlv_ie *ie, uint8_t indent, enum log_subsys subsys, enum log_level level)
{
	char indent_str[256];
	char *value_str;
	size_t value_len;
	char delimiter;
	uint8_t tag_cr;

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

	tag_cr = ie->tag;
	if (ie->cr)
		tag_cr |= 0x80;

	SS_LOGP(subsys, level, "%s(tag=0x%02x(0x%02x), cr=%s, len=%zu)%c %s\n", indent_str, tag_cr, ie->tag,
		ie->cr ? "true" : "false", value_len, delimiter, value_str);
}

/*! Dump decoded COMPREHENSION-TLV data.
 *  \param[in] list linked list begin of the COMPREHENSION-TLV list.
 *  \param[in] indent indentation level of the generated output.
 *  \param[in] log_subsys log subsystem to generate the output for.
 *  \param[in] log_level log level to generate the output for. */
void ss_ctlv_dump(const struct ss_list *list, uint8_t indent, enum log_subsys log_subsys, enum log_level log_level)
{
	struct cmp_tlv_ie *ie;

	SS_LIST_FOR_EACH(list, ie, struct cmp_tlv_ie, list) {
		dump_ie(ie, indent, log_subsys, log_level);
	}
}

static void free_ie(struct cmp_tlv_ie *ie)
{
	if (ie == NULL)
		return;

	if (ie->value)
		ss_buf_free(ie->value);

	/* Make sure all data vanishes from memory */
	memset(ie, 0, sizeof(*ie));

	SS_FREE(ie);
}

/*! Free COMPREHENSION-TLV data (including list begin).
 *  \param[in] list linked list begin of the COMPREHENSION-TLV list. */
void ss_ctlv_free(struct ss_list *list)
{
	struct cmp_tlv_ie *ie;
	struct cmp_tlv_ie *ie_pre;

	if (!list)
		return;

	if (ss_list_empty(list))
		return;

	SS_LIST_FOR_EACH_SAVE(list, ie, ie_pre, struct cmp_tlv_ie, list) {
		/* Unlink the element from the list and free it. */
		ss_list_remove(&ie->list);
		free_ie(ie);
	}

	/* Get rid of the list isself */
	SS_FREE(list);
}

/*! Allocate a new COMPREHENSION-TLV IE.
 *  \param[out] list linked list parent of the COMPREHENSION-TLV list.
 *  \param[in] tag COMPREHENSION-TLV tag (encoded format).
 *  \param[in] cr COMPREHENSION-TLV comprehension flag.
 *  \param[in] len COMPREHENSION-TLV value length.
 *  \param[in] value pointer to COMPREHENSION-TLV value (data is copied).
 *  \returns pointer to allocated IE struct. */
struct cmp_tlv_ie *ss_ctlv_new_ie(struct ss_list *list, uint16_t tag, bool cr, size_t len, const uint8_t *value)
{
	struct cmp_tlv_ie *ie = SS_ALLOC(struct cmp_tlv_ie);

	memset(ie, 0, sizeof(*ie));

	ie->tag = tag;
	ie->cr = cr;

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
 *  \param[in] list linked list begin of the COMPREHENSION-TLV tree.
 *  \param[in] tag COMPREHENSION-TLV (encoded format) tag to look for.
 *  \returns pointer to IE struct on success, NULL if IE is not found. */
struct cmp_tlv_ie *ss_ctlv_get_ie(const struct ss_list *list, uint16_t tag)
{
	struct cmp_tlv_ie *ie;

	if (!list)
		return NULL;

	SS_LIST_FOR_EACH(list, ie, struct cmp_tlv_ie, list) {
		if (ie->tag == tag)
			return ie;
	}

	return NULL;
}

/*! Get an IE from the list by its tag, ensure minimum length (on the current level).
 *  \param[in] list linked list begin of the COMPREHENSION-TLV tree.
 *  \param[in] tag COMPREHENSION-TLV tag to look for.
 *  \param[in] min_len minimum required length.
 *  \returns pointer to IE struct on success, NULL if IE is not found. */
struct cmp_tlv_ie *ss_ctlv_get_ie_minlen(const struct ss_list *list, uint16_t tag, size_t min_len)
{
	struct cmp_tlv_ie *ie = ss_ctlv_get_ie(list, tag);
	if (!ie)
		return NULL;
	if (ie->value->len < min_len)
		return NULL;
	return ie;
}

static size_t calc_ie_len(const struct cmp_tlv_ie *ie)
{
	size_t len = 0;

	if (ie->tag == 0x7F || ie->tag > 0xFE)
		len += 3;
	else
		len++;

	if (ie->value->len <= 0x7F) {
		len++;
	} else if (ie->value->len <= 0xFF) {
		len += 2;
	} else if (ie->value->len <= 0xFFFF) {
		len += 3;
	} else if (ie->value->len <= 0xFFFFFF) {
		len += 4;
	} else {
		return 0;
	}

	len += ie->value->len;

	return len;
}

static size_t encode_ie(uint8_t *enc, size_t len, const struct cmp_tlv_ie *ie)
{
	size_t ie_len;
	uint16_t tag;

	ie_len = calc_ie_len(ie);

	/* Do not encode anything when we are unable to determine the length
	 * or when the predicted length exceeds the buffer. */
	if (ie_len == 0 || ie_len > len) {
		SS_LOGP(SCTLV, LERROR, "not enough buffer space to encode TLV string, aborting at IE %02x.\n", ie->tag);
		return 0;
	}

	/* Do not allow tag values that are not allowed. */
	if (ie->tag == 0x00 || ie->tag == 0xff || ie->tag == 0x80) {
		SS_LOGP(SCTLV, LERROR, "tag %02x is not allowed in COMPRENSION-TLV, aborting at IE\n", ie->tag);
		return 0;
	}

	/* Encode tag */
	tag = ie->tag;
	if (ie->tag == 0x7F || ie->tag > 0xFE) {
		if (ie->cr)
			tag |= 0x8000;
		*enc = 0x7F;
		enc++;
		*enc = (tag >> 8) & 0xFF;
		enc++;
		*enc = tag & 0xFF;
	} else {
		if (ie->cr)
			tag |= 0x80;
		*enc = tag;
	}
	enc++;

	/* Encode len */
	if (ie->value->len <= 0x7F) {
		*enc = ie->value->len;
	} else if (ie->value->len <= 0xFF) {
		*enc = 0x81;
		enc++;
		*enc = ie->value->len;
	} else if (ie->value->len <= 0xFFFF) {
		*enc = 0x82;
		enc++;
		*enc = (ie->value->len >> 8) & 0xFF;
		enc++;
		*enc = ie->value->len & 0xFF;
	} else if (ie->value->len <= 0xFFFFFF) {
		*enc = 0x83;
		enc++;
		*enc = (ie->value->len >> 16) & 0xFF;
		enc++;
		*enc = (ie->value->len >> 8) & 0xFF;
		enc++;
		*enc = ie->value->len & 0xFF;
	} else {
		SS_LOGP(SCTLV, LERROR, "Error encoding IE, length field too large (%zu), aborting at IE %02x\n",
			ie->value->len, ie->tag);
		return 0;
	}
	enc++;

	/* Encode data */
	memcpy(enc, ie->value->data, ie->value->len);

	return ie_len;
}

/*! Encode linked list with COMPREHENSION-TLV data to its binary encoded representation.
 *  \param[out] enc pointer to buffer to output the encoded COMPREHENSION-TLV data.
 *  \param[in] len length of the buffer that will store the output.
 *  \param[in] list linked list with COMPREHENSION-TLV data to encode.
 *  \returns number of encoed bytes. */
size_t ss_ctlv_encode(uint8_t *enc, size_t len, const struct ss_list *list)
{
	size_t bytes_remain = len;
	struct cmp_tlv_ie *ie;
	size_t rc;

	/* clear output buffer (just to be sure) */
	memset(enc, 0, len);

	SS_LIST_FOR_EACH(list, ie, struct cmp_tlv_ie, list) {
		rc = encode_ie(enc, bytes_remain, ie);
		if (rc == 0)
			return 0;
		bytes_remain -= rc;
		enc += rc;
	}

	return len - bytes_remain;
}

static size_t calc_ctlv_len(const struct ss_list *list)
{
	size_t bytes_needed = 0;
	struct cmp_tlv_ie *ie;
	size_t rc;

	SS_LIST_FOR_EACH(list, ie, struct cmp_tlv_ie, list) {
		rc = calc_ie_len(ie);
		if (rc == 0)
			return 0;
		bytes_needed += rc;
	}

	return bytes_needed;
}

/*! Encode linked list with COMPREHENSION-TLV data to its binary encoded representation (to ss_buf).
 *  \param[inout] list linked list with COMPREHENSION-TLV data to encode.
 *  \returns ss_buf with encoded result. */
struct ss_buf *ss_ctlv_encode_to_ss_buf(const struct ss_list *list)
{
	size_t bytes_needed;
	struct ss_buf *buf;

	bytes_needed = calc_ctlv_len(list);
	buf = ss_buf_alloc(bytes_needed);
	ss_ctlv_encode(buf->data, buf->len, list);

	return buf;
}
