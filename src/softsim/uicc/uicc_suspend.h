/*
 * Copyright (c) 2024 Onomondo ApS. All rights reserved.
 *
 * SPDX-License-Identifier: GPL-3.0-only
 */

#pragma once

struct ss_apdu;

int ss_uicc_suspend_cmd(struct ss_apdu *apdu);
