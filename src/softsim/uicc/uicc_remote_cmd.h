/*
 * Copyright (c) 2024 Onomondo ApS. All rights reserved.
 * 
 * SPDX-License-Identifier: GPL-3.0-only 
 */

#pragma once

#include <stdint.h>
#include <stddef.h>
#include <onomondo/softsim/utils.h>

int ss_uicc_remote_cmd_receive(size_t cmd_packet_len, uint8_t *cmd_packet,
			       size_t *response_len, uint8_t *response,
			       struct ss_buf **sms_response,
			       uint8_t *main_ctx_filelist);
