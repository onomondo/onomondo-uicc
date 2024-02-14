/*
 * Copyright (c) 2024 Onomondo ApS. All rights reserved.
 * 
 * SPDX-License-Identifier: GPL-3.0-only 
 */

#pragma once

#include <stdbool.h>
#include <stdint.h>
#include <onomondo/softsim/list.h>
#include <onomondo/softsim/log.h>

#define SS_BERTLV_MAX_LEN_BYTES 4

enum ber_tlv_cls {
	BER_TLV_UNIV_CLS,
	BER_TLV_APPL_CLS,
	BER_TLV_CONT_CLS,
	BER_TLV_PRIV_CLS,
};

struct ber_tlv_ie {
	struct ss_list list;

	/* Meta information */
	char *title;

	/* Tag information */
	enum ber_tlv_cls cls;
	bool constr;
	uint16_t tag;
	uint32_t tag_encoded;

	/* Value */
	struct ss_buf *value;
	struct ss_list *nested;
};

struct ber_tlv_desc {
	/* ID number of this IE description item
	 * (id = 0 marks table ending and must not be used.) */
	uint32_t id;

	/* ID number of the parent IE description item */
	uint32_t id_parent;

	/* Meta information */
	char *title;
	uint32_t tag_encoded;
};

struct ss_list *ss_btlv_decode(const uint8_t *enc, size_t len,
			       const struct ber_tlv_desc *descr);
void ss_btlv_dump(const struct ss_list *list, uint8_t indent,
		  enum log_subsys log_subsys, enum log_level log_level);
void ss_btlv_free(struct ss_list *list);

struct ber_tlv_ie *ss_btlv_new_ie(struct ss_list *parent, const char *title,
				  uint32_t tag, size_t len,
				  const uint8_t *value);
struct ber_tlv_ie *ss_btlv_new_ie_constr(struct ss_list *parent,
					 const char *title, uint32_t tag);
struct ber_tlv_ie *ss_btlv_get_ie(const struct ss_list *list, uint32_t tag);
struct ber_tlv_ie *ss_btlv_get_ie_minlen(const struct ss_list *list,
					 uint16_t tag, size_t min_len);
size_t ss_btlv_encode(uint8_t *enc, size_t len, struct ss_list *list);
struct ss_buf *ss_btlv_encode_to_ss_buf(struct ss_list *list);
void ss_btlv_attach_to_constr(struct ber_tlv_ie *ie, struct ss_list *list);
struct ss_list *ss_btlv_split_off_from_constr(struct ber_tlv_ie *ie);
