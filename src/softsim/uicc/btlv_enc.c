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

/* Compute how much length in bytes a specified length value will need when
 * it is encoded according BER-TLV rules */
static size_t len_len(size_t len)
{
	size_t len_sum = 1;
	size_t compare_val = 0;
	unsigned int i;

	/* A single byte is sufficient */
	if (len <= 127)
		return 1;

	/* Multiple bytes are needed */
	for (i = 0; i < SS_BERTLV_MAX_LEN_BYTES; i++) {
		compare_val = compare_val << 8;
		compare_val |= 0xff;
		len_sum++;

		if (compare_val >= len)
			break;
	}

	return len_sum;
}

/* Compute the length of the encoded header for a given IE */
static size_t ie_hdr_len(struct ber_tlv_ie *ie)
{
	size_t len_sum = 1;
	size_t ie_len = 0;

	/* Tag size */
	if (ie->tag > 0x1f)
		len_sum++;
	if (ie->tag > 0x7f)
		len_sum++;

	/* Len size */
	if (ie->value)
		ie_len = ie->value->len;
	len_sum += len_len(ie_len);

	return len_sum;
}

/* Go through the BER-TLV tree and compute the length for all constructed IEs */
static size_t compute_nested_len(struct ss_list *list)
{
	struct ber_tlv_ie *ie;
	size_t len_sum = 0;
	size_t len;

	if (!list)
		return 0;

	SS_LIST_FOR_EACH(list, ie, struct ber_tlv_ie, list) {
		if (ie->constr) {
			len = compute_nested_len(ie->nested);

			/* NOTE: we only have to store the len. Unfortunatlly
			 * the length field is inside an ss_buf struct. This
			 * means we have to carefully check if such a stuct
			 * is already present. This is normally the case when
			 * the input data originates from the btlv decoder
			 * (re-encoding). We will only take action when the
			 * field length changed or when no (encoded) value
			 * part is present at all. In those cases we will also
			 * make sure the data part of the ss_buf is set to
			 * zeroed out. Under no circumstances we may do
			 * ss_buf_alloc() and set ie->value->len to the length
			 * value we have computed above. This will render the
			 * btlv tree inconsistent! */
			if (!ie->value) {
				ie->value = ss_buf_alloc(len);
				memset(ie->value->data, 0, ie->value->len);
			} else if (ie->value && ie->value->len != len) {
				ss_buf_free(ie->value);
				ie->value = ss_buf_alloc(len);
				memset(ie->value->data, 0, ie->value->len);
			}
		}
		len_sum += ie->value->len;
		len_sum += ie_hdr_len(ie);
	}

	return len_sum;
}

/* Assemble BER-TLV encoded string */
static size_t gen_ber_tlv_header(uint8_t *enc, struct ber_tlv_ie *ie)
{
	size_t bytes_used = 1;
	size_t len_field_len;
	unsigned int i;

	/* Encode header bits */
	*enc = (ie->cls & 0x03) << 6;
	*enc |= (ie->constr & 0x01) << 5;

	/* Encode tag field */
	if (ie->tag < 0x1f) {
		*enc |= ie->tag;
	} else if (ie->tag <= 0x7f) {
		*enc |= 0x1f;
		bytes_used++;
		enc++;
		*enc = ie->tag;
	} else {
		*enc |= 0x1f;
		bytes_used++;
		enc++;
		*enc = 0x80;
		*enc |= ie->tag >> 8;
		*enc |= 0x80;
		bytes_used++;
		enc++;
		*enc |= ie->tag & 0xff;
	}

	/* Len size */
	len_field_len = len_len(ie->value->len);
	if (len_field_len == 1) {
		bytes_used++;
		enc++;
		*enc = ie->value->len;
	} else {
		bytes_used++;
		enc++;
		*enc = (len_field_len - 1) | 0x80;
		for (i = len_field_len - 1; i > 0; i--) {
			bytes_used++;
			enc++;
			*enc = ie->value->len >> ((i - 1) * 8);
		}
	}

	return bytes_used;
}

static size_t gen_ber_tlv_string(uint8_t **enc, const struct ss_list *list)
{
	struct ber_tlv_ie *ie;
	size_t bytes_used = 0;
	size_t bytes_used_ie;

	if (!list)
		return 0;

	SS_LIST_FOR_EACH(list, ie, struct ber_tlv_ie, list) {
		bytes_used_ie = gen_ber_tlv_header(*enc, ie);
		*enc += bytes_used_ie;

		if (ie->constr)
			bytes_used_ie += gen_ber_tlv_string(enc, ie->nested);
		else {
			memcpy(*enc, ie->value->data, ie->value->len);
			bytes_used_ie += ie->value->len;
			*enc += ie->value->len;
		}

		bytes_used += bytes_used_ie;
	}

	return bytes_used;
}

/*! Encode linked list with BER-TLV data to its binary encoded representation.
 *  \param[out] enc pointer to buffer to output the encoded BER-TLV data.
 *  \param[in] len length of the buffer that will store the output.
 *  \param[inout] list linked list with BER-TLV data to encode (will regenerate length of constructed IEs).
 *  \returns number of encoed bytes. */
size_t ss_btlv_encode(uint8_t *enc, size_t len, struct ss_list *list)
{
	size_t bytes_needed;

	/* clear output buffer (just to be sure) */
	memset(enc, 0, len);

	/* (re-)compute the length required for each of the nested fields. */
	bytes_needed = compute_nested_len(list);

	/* don't even start encoding pass when we detect that we do not have
	 * enough memory for the result */
	if (len < bytes_needed) {
		SS_LOGP(SBTLV, LDEBUG,
			"cannot encode BER-TLV string, buffer to small (bytes needed: %lu, bytes available: %lu\n",
			bytes_needed, len);
		return 0;
	}

	/* encode BER-TLV data */
	gen_ber_tlv_string(&enc, list);

	return bytes_needed;
}

/*! Encode linked list with BER-TLV data to its binary encoded representation (to ss_buf).
 *  \param[inout] list linked list with BER-TLV data to encode (will regenerate length of constructed IEs).
 *  \returns ss_buf with encoded result. */
struct ss_buf *ss_btlv_encode_to_ss_buf(struct ss_list *list)
{
	size_t bytes_needed;
	struct ss_buf *buf;
	uint8_t *data_ptr;

	/* (re-)compute the length required for each of the nested fields. */
	bytes_needed = compute_nested_len(list);

	buf = ss_buf_alloc(bytes_needed);

	/* encode BER-TLV data */
	data_ptr = buf->data;
	gen_ber_tlv_string(&data_ptr, list);

	return buf;
}
