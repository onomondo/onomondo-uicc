/*
 * Copyright (c) 2024 Onomondo ApS. All rights reserved.
 * 
 * SPDX-License-Identifier: GPL-3.0-only 
 */

#pragma once

#include <stdbool.h>
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
	/* A remote command changed EF.IMSI: the location files are reset when
	 * the card session ends (TS 31.102 Annex A NOTE 1, TS 31.111 6.4.7.1) */
	bool loci_reset_pending;
};

void ss_uicc_refresh_poll(struct ss_context *ctx);
void ss_uicc_refresh_session_end(struct ss_context *ctx);
