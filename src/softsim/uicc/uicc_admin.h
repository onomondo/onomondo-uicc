/*
 * Copyright (c) 2024 Onomondo ApS. All rights reserved.
 * 
 * SPDX-License-Identifier: GPL-3.0-only 
 */

#pragma once

int ss_uicc_admin_cmd_create_file(struct ss_apdu *apdu);
int ss_uicc_admin_cmd_delete_file(struct ss_apdu *apdu);
int ss_uicc_admin_cmd_activate_file(struct ss_apdu *apdu);
