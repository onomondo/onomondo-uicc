/*
 * Copyright (c) 2024 Onomondo ApS. All rights reserved.
 * 
 * SPDX-License-Identifier: GPL-3.0-only 
 */

#pragma once

#include "fs_chg.h"

enum ss_uicc_refresh_states {
	SS_REFRESH_READY = 0x00,
	SS_REFRESH_PENDING = 0x01,
	SS_REFRESH_TRANSIT = 0x02,
};

struct ss_uicc_refresh_state {
	uint8_t filelist[SS_FS_CHG_BUF_SIZE];
	enum ss_uicc_refresh_states state;
	unsigned int retry_counter;
};

void ss_uicc_refresh_poll(struct ss_context *ctx);
