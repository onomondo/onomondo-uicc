/*
 * Copyright (c) 2024 Onomondo ApS. All rights reserved.
 * 
 * SPDX-License-Identifier: GPL-3.0-only 
 */

#pragma once

#include <stdbool.h>
struct ss_lchan;

/* Indices match the key references of TS 102 221 V15.0.0 table 9.3. */
enum pin {
	SS_PIN_1 = 0x01,
	SS_PIN_2 = 0x81,
	SS_PIN_ADM1 = 0x0A,
};

int ss_uicc_pin_cmd_verify_pin(struct ss_apdu *apdu);
int ss_uicc_pin_cmd_change_pin(struct ss_apdu *apdu);
int ss_uicc_pin_cmd_disable_pin(struct ss_apdu *apdu);
int ss_uicc_pin_cmd_enable_pin(struct ss_apdu *apdu);
int ss_uicc_pin_cmd_unblock_pin(struct ss_apdu *apdu);

bool ss_uicc_pin_verified(enum pin pin_no, const struct ss_lchan *lchan);
int ss_uicc_pin_update_pst_do(struct ss_buf *pin_stat_templ);
struct ss_buf *ss_uicc_pin_gen_pst_do(void);
