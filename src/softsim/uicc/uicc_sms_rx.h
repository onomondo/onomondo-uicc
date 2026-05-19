/*
 * Copyright (c) 2024 Onomondo ApS. All rights reserved.
 * 
 * SPDX-License-Identifier: GPL-3.0-only 
 */

#pragma once

#include <stddef.h>
#include <onomondo/softsim/list.h>
#include "sms.h"

/* Note: It is expected that the contents of ss_uicc_sms_rx_state are set to
 * zero before carrying out any operation, including ss_uicc_sms_rx_clear() */
struct ss_uicc_sms_rx_state {
	struct ss_list reassemblies;
	size_t reassembly_count;
};

struct ss_buf;
struct ss_context;

void ss_uicc_sms_rx_clear(struct ss_context *ctx);
int ss_uicc_sms_rx(struct ss_context *ctx, struct ss_buf *sms_tpdu,
		   size_t *response_len, uint8_t response[*response_len]);
