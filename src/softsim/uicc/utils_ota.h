/*
 * Copyright (c) 2024 Onomondo ApS. All rights reserved.
 *
 * SPDX-License-Identifier: GPL-3.0-only
 */

#pragma once

#include <onomondo/softsim/crypto.h>

#define OTA_KEY_LEN 16
#define OTA_INTEGRITY_LEN 8

uint8_t ss_utils_ota_calc_pcnt(enum enc_algorithm algorithm, size_t data_len);
