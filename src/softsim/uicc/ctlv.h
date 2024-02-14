/*
 * Copyright (c) 2024 Onomondo ApS. All rights reserved.
 * 
 * SPDX-License-Identifier: GPL-3.0-only 
 */

#pragma once

#include <stdint.h>
#include <stdbool.h>
#include <onomondo/softsim/list.h>
#include <onomondo/softsim/log.h>

struct cmp_tlv_ie {
	struct ss_list list;

	bool cr;
	uint16_t tag;
	struct ss_buf *value;
};

struct ss_list *ss_ctlv_decode(const uint8_t *enc, size_t len);
void ss_ctlv_dump(const struct ss_list *list, uint8_t indent,
		  enum log_subsys log_subsys, enum log_level log_level);
void ss_ctlv_free(struct ss_list *list);

struct cmp_tlv_ie *ss_ctlv_new_ie(struct ss_list *list, uint16_t tag, bool cr,
				  size_t len, const uint8_t *value);
struct cmp_tlv_ie *ss_ctlv_get_ie(const struct ss_list *list, uint16_t tag);
struct cmp_tlv_ie *ss_ctlv_get_ie_minlen(const struct ss_list *list,
					 uint16_t tag, size_t min_len);

size_t ss_ctlv_encode(uint8_t *enc, size_t len, const struct ss_list *list);
struct ss_buf *ss_ctlv_encode_to_ss_buf(const struct ss_list *list);
