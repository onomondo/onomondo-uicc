/*
 * Copyright (c) 2024 Onomondo ApS. All rights reserved.
 * 
 * SPDX-License-Identifier: GPL-3.0-only 
 */

#pragma once

int ss_uicc_cat_cmd_term_profile(struct ss_apdu *apdu);
int ss_uicc_cat_cmd_envelope(struct ss_apdu *apdu);
int ss_uicc_cat_cmd_fetch(struct ss_apdu *apdu);
int ss_uicc_cat_cmd_term_resp(struct ss_apdu *apdu);
