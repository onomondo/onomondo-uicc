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
#include <errno.h>
#include <onomondo/softsim/log.h>
#include <onomondo/softsim/list.h>
#include <onomondo/softsim/utils.h>
#include <onomondo/softsim/mem.h>
#include "btlv.h"

#define SS_BERTLV_MAX_LEN_BYTES 4

/* Split an encoded tag into tag, constructed bit and class */
static int decode_tag(uint16_t *tag, enum ber_tlv_cls *cls, bool *constr, uint32_t tag_encoded)
{
	uint8_t enc[3] = { 0 };
	uint16_t tag_result;
	uint8_t cls_result;
	bool constr_result;

	if (tag_encoded <= 0xff)
		enc[0] = tag_encoded & 0xff;
	else if (tag_encoded <= 0xffff) {
		enc[0] = (tag_encoded >> 8) & 0xff;
		enc[1] = tag_encoded & 0xff;
	} else {
		enc[0] = (tag_encoded >> 16) & 0xff;
		enc[1] = (tag_encoded >> 8) & 0xff;
		enc[2] = tag_encoded & 0xff;
	}

	cls_result = (enc[0] >> 6) & 3;
	constr_result = (enc[0] >> 5) & 1;

	if ((enc[0] & 0x1f) == 0x1f) {
		tag_result = enc[1] & 0x7f;
		if (enc[1] & 0x80) {
			tag_result = tag_result << 8;
			tag_result |= enc[2];
		} else {
			if (enc[2] != 0x00)
				return -EINVAL;
		}
	} else {
		if (enc[1] != 0x00 && enc[2] != 0x00)
			return -EINVAL;
		tag_result = enc[0] & 0x1f;
	}

	if (tag)
		*tag = tag_result;
	if (cls)
		*cls = cls_result;
	if (constr)
		*constr = constr_result;
	return 0;
}

static void dump_ie(const struct ber_tlv_ie *ie, uint8_t indent, enum log_subsys subsys, enum log_level level)
{
	char indent_str[256];
	char *title_str, *value_str;
	size_t value_len;
	char delimiter;

	memset(indent_str, ' ', indent);
	indent_str[indent] = '\0';

	if (ie == NULL) {
		SS_LOGP(subsys, level, "%s(NULL)\n", indent_str);
		return;
	}

	if (ie->title)
		title_str = ie->title;
	else
		title_str = "unknown IE";

	if (ie->value) {
		value_str = ss_hexdump(ie->value->data, ie->value->len);
		value_len = ie->value->len;
		delimiter = ':';
	} else {
		value_str = "";
		value_len = 0;
		delimiter = ' ';
	}

	SS_LOGP(subsys, level, "%s%s(tag=0x%02x(0x%02x), cls=%x, constr=%s, len=%zu)%c %s\n", indent_str, title_str,
		ie->tag_encoded, ie->tag, ie->cls, ie->constr ? "true" : "false", value_len, delimiter, value_str);
}

/*! Dump decoded BER-TLV data.
 *  \param[in] list linked list begin of the BER-TLV tree.
 *  \param[in] indent indentation level of the generated output.
 *  \param[in] log_subsys log subsystem to generate the output for.
 *  \param[in] log_level log level to generate the output for. */
void ss_btlv_dump(const struct ss_list *list, uint8_t indent, enum log_subsys log_subsys, enum log_level log_level)
{
	struct ber_tlv_ie *ie;

	SS_LIST_FOR_EACH(list, ie, struct ber_tlv_ie, list) {
		dump_ie(ie, indent, log_subsys, log_level);
		if (ie->constr && ie->nested) {
			ss_btlv_dump(ie->nested, indent + 2, log_subsys, log_level);
		}
	}
}

static void free_ie(struct ber_tlv_ie *ie)
{
	if (ie == NULL)
		return;

	if (ie->title)
		SS_FREE(ie->title);
	if (ie->nested)
		SS_FREE(ie->nested);
	if (ie->value)
		ss_buf_free(ie->value);

	/* Make sure all data vanishes from memory */
	memset(ie, 0, sizeof(*ie));

	SS_FREE(ie);
}

static void btlv_free(struct ss_list *list)
{
	struct ber_tlv_ie *ie;
	struct ber_tlv_ie *ie_pre;

	if (!list)
		return;

	if (ss_list_empty(list))
		return;

	SS_LIST_FOR_EACH_SAVE(list, ie, ie_pre, struct ber_tlv_ie, list) {
		/* If it is a constructed element, we have to take care of the
		 * nested elements first */
		if (ie->constr && ie->nested)
			btlv_free(ie->nested);

		/* Unlink the element from the list and free it. */
		ss_list_remove(&ie->list);
		free_ie(ie);
	}
}

/*! Free BER-TLV data (including list begin).
 *  \param[in] list linked list begin of the BER-TLV tree. */
void ss_btlv_free(struct ss_list *list)
{
	if (!list)
		return;

	/* Free everything that is in the supplied list */
	btlv_free(list);

	/* Get rid of the list isself */
	SS_FREE(list);
}

/* Create a new BER-TLV IE with binary data */

/*! Allocate a new BER-TLV IE.
 *  \param[out] parent linked list parent of the BER-TLV tree.
 *  \param[in] title human readable title that serves as a description.
 *  \param[in] tag BER-TLV tag (encoded format).
 *  \param[in] len BER-TLV value length.
 *  \param[in] value pointer to BER-TLV value (data is copied).
 *  \returns pointer to allocated IE struct. */
struct ber_tlv_ie *ss_btlv_new_ie(struct ss_list *parent, const char *title, uint32_t tag, size_t len,
				  const uint8_t *value)
{
	int rc;
	struct ber_tlv_ie *ie = SS_ALLOC(struct ber_tlv_ie);
	bool constr;

	memset(ie, 0, sizeof(*ie));

	/* Make sure the supplied tag is correctly formatted and consistent */
	ie->tag_encoded = tag;
	rc = decode_tag(&ie->tag, &ie->cls, &constr, tag);
	if (rc < 0) {
		SS_LOGP(SBTLV, LERROR, "incorrect tag format (%02x), cannot create IE!\n", tag);
		SS_FREE(ie);
		return NULL;
	}
	if (constr != false) {
		SS_LOGP(SBTLV, LERROR, "tag does not describe a primitive ie (%02x), cannot create IE!\n", tag);
		SS_FREE(ie);
		return NULL;
	}

	if (title) {
		ie->title = SS_ALLOC_N(strlen(title) + 1);
		strcpy(ie->title, title);
	}
	ie->nested = NULL;
	if (value) {
		ie->value = ss_buf_alloc(len);
		memcpy(ie->value->data, value, len);
	}

	if (parent)
		ss_list_put(parent, &ie->list);
	return ie;
}

/*! Allocate a new constructed BER-TLV IE.
 *  \param[out] parent linked list parent of the BER-TLV tree.
 *  \param[in] title human readable title that serves as a description.
 *  \param[in] tag BER-TLV tag (encoded format).
 *  \returns pointer to allocated IE struct. */
struct ber_tlv_ie *ss_btlv_new_ie_constr(struct ss_list *parent, const char *title, uint32_t tag)
{
	int rc;
	struct ber_tlv_ie *ie = SS_ALLOC(struct ber_tlv_ie);
	bool constr;

	memset(ie, 0, sizeof(*ie));

	/* Make sure the supplied tag is correctly formatted and consistent */
	ie->tag_encoded = tag;
	rc = decode_tag(&ie->tag, &ie->cls, &constr, tag);
	if (rc < 0) {
		SS_LOGP(SBTLV, LERROR, "incorrect tag format (%02x), cannot create IE!\n", tag);
		SS_FREE(ie);
		return NULL;
	}
	if (constr != true) {
		SS_LOGP(SBTLV, LERROR, "tag does not describe a constructed ie (%02x), cannot create IE!\n", tag);
		SS_FREE(ie);
		return NULL;
	}

	if (title) {
		ie->title = SS_ALLOC_N(strlen(title) + 1);
		strcpy(ie->title, title);
	}
	ie->value = NULL;
	ie->constr = true;
	ie->nested = SS_ALLOC(struct ss_list);
	ss_list_init(ie->nested);

	if (parent)
		ss_list_put(parent, &ie->list);
	return ie;
}

/*! Get an IE from the list by its tag (on the current level).
 *  \param[in] list linked list begin of the BER-TLV tree.
 *  \param[in] tag BER-TLV (encoded format) tag to look for.
 *  \returns pointer to IE struct on success, NULL if IE is not found. */
struct ber_tlv_ie *ss_btlv_get_ie(const struct ss_list *list, uint32_t tag)
{
	struct ber_tlv_ie *ie;
	int rc;

	if (!list)
		return NULL;

	/* Make sure we search only for correctly formatted tags */
	rc = decode_tag(NULL, NULL, NULL, tag);
	if (rc < 0) {
		SS_LOGP(SBTLV, LERROR, "incorrect tag format (%02x), cannot search for IE!\n", tag);
		return NULL;
	}

	SS_LIST_FOR_EACH(list, ie, struct ber_tlv_ie, list) {
		if (ie->tag_encoded == tag)
			return ie;
	}

	return NULL;
}

/*! Get an IE from the list by its tag, ensure minimum length (on the current level).
 *  \param[in] list linked list begin of the BER-TLV tree.
 *  \param[in] tag BER-TLV tag to look for.
 *  \param[in] min_len minimum required length.
 *  \returns pointer to IE struct on success, NULL if IE is not found. */
struct ber_tlv_ie *ss_btlv_get_ie_minlen(const struct ss_list *list, uint16_t tag, size_t min_len)
{
	struct ber_tlv_ie *ie = ss_btlv_get_ie(list, tag);
	if (!ie)
		return NULL;
	if (ie->value->len < min_len)
		return NULL;
	return ie;
}

/*! Attach a BER-TLV tree to an existing IE.
 *  \param[inout] ie BER-TLV IE struct to which the BER-TLV tree shall be attached.
 *  \param[in] list linked list begin of the BER-TLV tree. */
void ss_btlv_attach_to_constr(struct ber_tlv_ie *ie, struct ss_list *list)
{
	/* Get rid of all current nested elements. Normally there should only
	 * be an empty list and nothing else. */
	ss_btlv_free(ie->nested);

	/* May exist when the btlv tree (list) is a parsed result. There is
	 * no replacement for this. The encoder will not use this field. */
	ss_buf_free(ie->value);
	ie->value = NULL;

	/* Attach given list as the new nested BTLV elements. */
	ie->nested = list;
}

/*! Split off a BER-TLV tree from an existing IE.
 *  \param[inout] ie BER-TLV IE struct to which the BER-TLV tree shall be splitted off.
 *  \returns linked list begin of the BER-TLV tree that is splitted off. */
struct ss_list *ss_btlv_split_off_from_constr(struct ber_tlv_ie *ie)
{
	struct ss_list *result;

	result = ie->nested;
	ie->nested = SS_ALLOC(struct ss_list);
	ss_list_init(ie->nested);
	return result;
}
