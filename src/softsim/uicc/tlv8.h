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

struct tlv8_ie {
	struct ss_list list;
	uint8_t tag;
	struct ss_buf *value;
};

struct ss_list *ss_tlv8_decode(const uint8_t *enc, size_t len);
void ss_tlv8_dump(const struct ss_list *list, uint8_t indent,
		  enum log_subsys log_subsys, enum log_level log_level);
void ss_tlv8_free(struct ss_list *list);

struct tlv8_ie *ss_tlv8_new_ie(struct ss_list *list, uint8_t tag, size_t len,
			       const uint8_t *value);
struct tlv8_ie *ss_tlv8_get_ie(const struct ss_list *list, uint8_t tag);
struct tlv8_ie *ss_tlv8_get_ie_minlen(const struct ss_list *list, uint8_t tag,
				      size_t min_len);
size_t ss_tlv8_encode(uint8_t *enc, size_t len, const struct ss_list *list);
struct ss_buf *ss_tlv8_encode_to_ss_buf(const struct ss_list *list);
