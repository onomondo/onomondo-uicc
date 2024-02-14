/*
 * Copyright (c) 2024 Onomondo ApS. All rights reserved.
 * 
 * SPDX-License-Identifier: GPL-3.0-only 
 */

#include <stdbool.h>
#include <stdint.h>
#include "sw.h"

/*! Check if a status word refers to a successful outcome.
 *  \param[in] sw status word to check
 *  \returns true when SW refers to a successful outcome, false otherwise. */
bool ss_sw_is_successful(uint16_t sw)
{
	if (sw == SS_SW_NORMAL_ENDING)
		return true;
	sw = sw >> 8;
	if (sw == 0x91)
		/* 9000 and proactive data is pending */
		return true;
	if (sw >= 0x61 && sw <= 0x63)
		return true;
	return false;
}
