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
#include "btlv.h"

/* Advance the bufer and check if we are still in bounds. The parameter "inc"
 * sets how many bytes the buffer pointer (enc) should be be advanced. The
 * parameter "bytes_ahead" sets the minimum valid bytes that the caller expects
 * to be available after the buffer pointer (enc) has been advanced. */
#define CHECK_AND_ADVANCE(inc, bytes_ahead)                                                                    \
	if (len < bytes_used + inc + bytes_ahead) {                                                            \
		SS_LOGP(SBTLV, LDEBUG,                                                                         \
			"exceeding buffer bounds: len=%zu, inc=%zu, bytes_ahead=%zu, cannot decode IE\n", len, \
			(size_t)inc, (size_t)bytes_ahead);                                                     \
		return NULL;                                                                                   \
	}                                                                                                      \
	bytes_used += inc;                                                                                     \
	enc += inc

/* Return one decoded information element */
static struct ber_tlv_ie *decode_ie(size_t *used_len, const uint8_t *enc, size_t len)
{
	struct ber_tlv_ie ie;
	struct ber_tlv_ie *ie_ret;
	uint8_t len_bytes;
	uint8_t i;
	size_t bytes_used = 0;
	const uint8_t *value;
	size_t ie_len;

	*used_len = 0;

	if (len == 0)
		return NULL;

	memset(&ie, 0, sizeof(ie));

	/* Header bits */
	ie.cls = (*enc >> 6) & 3;
	ie.constr = (*enc >> 5) & 1;

	/* Decode tag field */
	ie.tag_encoded = *enc;
	if ((*enc & 0x1f) == 0x1f) {
		CHECK_AND_ADVANCE(1, 1);
		ie.tag = *enc & 0x7f;
		ie.tag_encoded <<= 8;
		ie.tag_encoded |= *enc;
		if (*enc & 0x80) {
			ie.tag = ie.tag << 8;
			CHECK_AND_ADVANCE(1, 1);
			ie.tag |= *enc;
			ie.tag_encoded <<= 8;
			ie.tag_encoded |= *enc;
		}
	} else
		ie.tag = *enc & 0x1f;
	CHECK_AND_ADVANCE(1, 1);

	/* Decode length field */
	if (*enc < 0x7f) {
		ie_len = *enc;
	} else {
		len_bytes = *enc & 0x7f;

		/* Make sure the decoded length field length makes sense */
		if (len_bytes == 0 || len_bytes > SS_BERTLV_MAX_LEN_BYTES) {
			SS_LOGP(SBTLV, LDEBUG, "invalid ber-tlv length field length (tag = 0x%02x)\n", ie.tag);
			return NULL;
		}

		ie_len = 0;
		for (i = 0; i < len_bytes; i++) {
			ie_len <<= 8;
			CHECK_AND_ADVANCE(1, 1);
			ie_len |= *enc;
		}
	}
	CHECK_AND_ADVANCE(1, ie_len);
	value = enc;
	CHECK_AND_ADVANCE(ie_len, 0);
	*used_len = bytes_used;

	/* Create output struct */
	ie_ret = SS_ALLOC(struct ber_tlv_ie);
	if (!ie_ret)
		return NULL;
	memcpy(ie_ret, &ie, sizeof(ie));

	/* Copy data part to the newly allocated item */
	ie_ret->value = ss_buf_alloc(ie_len);
	memcpy(ie_ret->value->data, value, ie_len);

	return ie_ret;
}

/* Get a description for an IE with a specified tag that is assigned to a specified parent (id) */
static const struct ber_tlv_desc *get_ie_descr(const struct ber_tlv_desc *descr, uint32_t tag_encoded,
					       uint32_t id_parent)
{
	uint32_t i = 0;

	if (descr == NULL)
		return NULL;

	do {
		if (descr[i].id_parent == id_parent && descr[i].tag_encoded == tag_encoded) {
			return &descr[i];
		}
		i++;
	} while (descr[i].id != 0);

	return NULL;
}

/* Decode BER TLV encoded string recursively
 *
 * On decoding errors, this returns NULL. If any constructed elements could not
 * be decoded, that is tolerated; in that case, that element's .nested element
 * is NULL.
 *
 * Consecutive 0xFF bytes at the trailing end are tolerated.
 * */
static struct ss_list *btlv_decode(const uint8_t *enc, size_t len, const struct ber_tlv_desc *descr, uint32_t id_parent)
{
	struct ber_tlv_ie *ie;
	const struct ber_tlv_desc *ie_descr;
	size_t used_len;
	size_t remaining_len = len;
	int i = 0;

	struct ss_list *list;

	list = SS_ALLOC(struct ss_list);
	ss_list_init(list);

	do {
		/* Decode IE and store it in the given list */
		ie = decode_ie(&used_len, enc, remaining_len);
		if (ie) {
			ss_list_put(list, &ie->list);
			ie_descr = get_ie_descr(descr, ie->tag_encoded, id_parent);
			if (ie_descr && ie_descr->title) {
				ie->title = SS_ALLOC_N(strlen(ie_descr->title) + 1);
				strcpy(ie->title, ie_descr->title);
			}
		} else if (remaining_len > 0) {
			for (i = used_len; i < used_len + remaining_len; ++i) {
				if (enc[i] != 0xff) {
					SS_LOGP(SBTLV, LERROR, "Error decoding BTLV (%s).\n",
						ss_hexdump(&enc[used_len], remaining_len));
					ss_btlv_free(list);
					return NULL;
				}
			}
		}

		/* If we detect that we deal with a constructed IE, we call
		 * this function again recursively, but we use the nested
		 * list of the IE. */
		if (ie && ie->constr) {
			if (ie_descr) {
				ie->nested = btlv_decode(ie->value->data, ie->value->len, descr, ie_descr->id);
			} else {
				ie->nested = btlv_decode(ie->value->data, ie->value->len, NULL, 0);
			}
		}

		/* Go to the next IE */
		enc += used_len;
		remaining_len -= used_len;
	} while (ie != NULL);

	return list;
}

/*! Decode binary BER-TLV encoded data.
 *  \param[in] enc pointer to buffer with encoded BER-TLV data.
 *  \param[in] len length of the buffer that contains the BER-TLV encoded data.
 *  \param[in] descr decoded BER-TLV data that serves a description (titles).
 *  \returns pointer to allocated linked list with BER-TLV data (can be empty). */
struct ss_list *ss_btlv_decode(const uint8_t *enc, size_t len, const struct ber_tlv_desc *descr)
{
	return btlv_decode(enc, len, descr, 0);
}
