/*
 * Copyright (c) 2024 Onomondo ApS. All rights reserved.
 * 
 * SPDX-License-Identifier: GPL-3.0-only 
 */

#pragma once

#include "sms.h"

struct ss_context;
typedef void (*sms_result_cb)(struct ss_context * ctx, int rc);

struct ss_uicc_sms_tx_sm {
	struct ss_list list;
	uint8_t msg[SMS_HDR_MAX_SIZE + SMS_MAX_SIZE];
	size_t msg_len;
	sms_result_cb sms_result_cb;
	bool last_msg;
	uint8_t msg_id;
};

/* Note: It is expected that the contents of ss_uicc_sms_rx_state are set to
 * zero before carrying out any operation, including ss_uicc_sms_tx_clear() */
struct ss_uicc_sms_tx_state {
	struct ss_list sm;
	sms_result_cb sms_result_cb;
	bool pending;
	bool last_msg;
	uint8_t msg_id;
};

void ss_uicc_sms_tx_clear(struct ss_context *ctx);
int ss_uicc_sms_tx(struct ss_context *ctx,
		   struct ss_sm_hdr *sm_hdr,
		   uint8_t *ud_hdr, size_t ud_hdr_len,
		   uint8_t *tp_ud, size_t tp_ud_len,
		   sms_result_cb sms_result_cb);
void ss_uicc_sms_tx_poll(struct ss_context *ctx);
