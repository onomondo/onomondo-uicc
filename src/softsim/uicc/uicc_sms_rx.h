/*
 * Copyright (c) 2024 Onomondo ApS. All rights reserved.
 * 
 * SPDX-License-Identifier: GPL-3.0-only 
 */

#pragma once

#include "sms.h"

struct ss_uicc_sms_rx_sm {
	struct ss_list list;
	uint8_t msg_id;
	uint8_t msg_part_no;
	uint8_t tp_ud[SMS_MAX_SIZE];
	size_t tp_ud_len;
};

/* Note: It is expected that the contents of ss_uicc_sms_rx_state are set to
 * zero before carrying out any operation, including ss_uicc_sms_rx_clear() */
struct ss_uicc_sms_rx_state {
	uint8_t msg_id;
	uint8_t msg_parts;
	struct ss_list sm;
};

struct ss_buf;
struct ss_context;

void ss_uicc_sms_rx_clear(struct ss_context *ctx);
int ss_uicc_sms_rx(struct ss_context *ctx, struct ss_buf *sms_tpdu,
		   size_t *response_len, uint8_t response[*response_len]);
