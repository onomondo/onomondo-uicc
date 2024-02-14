/*
 * Copyright (c) 2024 Onomondo ApS. All rights reserved.
 * 
 * SPDX-License-Identifier: GPL-3.0-only 
 */

#pragma once

int ss_uicc_file_ops_cmd_status(struct ss_apdu *apdu);
int ss_uicc_file_ops_cmd_read_binary(struct ss_apdu *apdu);
int ss_uicc_file_ops_cmd_update_binary(struct ss_apdu *apdu);
int ss_uicc_file_ops_cmd_read_record(struct ss_apdu *apdu);
int ss_uicc_file_ops_cmd_update_record(struct ss_apdu *apdu);
int ss_uicc_file_ops_cmd_search_record(struct ss_apdu *apdu);
int ss_uicc_file_ops_cmd_select(struct ss_apdu *apdu);
