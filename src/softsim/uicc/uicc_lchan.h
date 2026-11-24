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

	/* Verified PINs, one bit for each of the 256 one-byte key references (TS 102 221 table 9.3).
	 * Access only through ss_uicc_lchan_pin_set()/ss_uicc_lchan_pin_bit() below. */
	uint8_t pin_verified[32];

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

/*! Mark key reference ref verified: bit ref % 8 of byte ref / 8. */
static inline void ss_uicc_lchan_pin_set(struct ss_lchan *lchan, uint8_t ref)
{
	lchan->pin_verified[ref / 8] |= 1 << (ref % 8);
}

/*! Raw bit of key reference ref; it ignores PIN enable state, so access checks use ss_uicc_pin_verified(). */
static inline bool ss_uicc_lchan_pin_bit(const struct ss_lchan *lchan, uint8_t ref)
{
	return (lchan->pin_verified[ref / 8] >> (ref % 8)) & 1;
}

void ss_uicc_lchan_dump(const struct ss_lchan *lchan);
void ss_uicc_lchan_free(struct ss_context *ctx);
void ss_uicc_lchan_reset(struct ss_context *ctx);
struct ss_lchan *ss_uicc_lchan_get(struct ss_context *ctx, uint8_t cla);
int ss_uicc_lchan_cmd_manage_channel(struct ss_apdu *apdu);
