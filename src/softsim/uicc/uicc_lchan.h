/*
 * Copyright (c) 2024 Onomondo ApS. All rights reserved.
 * 
 * SPDX-License-Identifier: GPL-3.0-only 
 */

#pragma once

#include <stdbool.h>
#include <stdint.h>
#include <onomondo/softsim/list.h>
#include "uicc_sms_rx.h"
struct ss_context;
struct ss_apdu;

/*! Logical channel through which we communicate with an external application */
struct ss_lchan {

	/* Number of the lchan */
	uint8_t nr;

	/* Note: This flag field must not be read accessed directly. In order to
	 * check PIN permission, the API functions in module uicc_pin.c must
	 * be used. It may be written to if a PIN is implicitly provided for an
	 * lchan, eg. in setup_ctx_from_tar. */
	bool pin_verfied[256];

	/* Currently selected file (can be an EF, DF or ADF) */
	struct ss_list fs_path;

	/* Current record, in case a record oriented file is currently
	 * selected. */
	uint8_t current_record;

	/* the last APDU in case a GET RESPONSE follows */
	struct ss_apdu *last_apdu;
	bool last_apdu_keep;

	/* Path to currently active (last selected) ADF */
	struct ss_list adf_path;
};

void ss_uicc_lchan_dump(const struct ss_lchan *lchan);
void ss_uicc_lchan_free(struct ss_context *ctx);
void ss_uicc_lchan_reset(struct ss_context *ctx);
struct ss_lchan *ss_uicc_lchan_get(struct ss_context *ctx, uint8_t cla);
int ss_uicc_lchan_cmd_manage_channel(struct ss_apdu *apdu);
