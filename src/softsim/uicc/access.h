/*
 * Copyright (c) 2024 Onomondo ApS. All rights reserved.
 * 
 * SPDX-License-Identifier: GPL-3.0-only 
 */

#pragma once

/** Access rule evaluation */

#include <onomondo/softsim/file.h>
#include "uicc_lchan.h"

/** Classification of an APDU for access control purposes
 *
 * Organization and values match ISO/IEC 7816-4:2005(E) tables 16-19; callers
 * of \ref ss_access_check_command need to find their access in the relevant tables.
 *
 * The value SS_ACCESS_INTENTION_OTHER must be selected if the access does not
 * fall in any of these categories.
 *
 * Regular intentions are always 1-bit values; thus, they can be easily
 * compared to the OR expressed in the AM byte by &-ing them.
 *
 * The current values allow for 1:1 comparison with the AM bytes; if this
 * implementation starts giving meaning to the proprietary bits, they could be
 * placed in the enum value's higher byte.
 */
enum ss_access_intention {
	SS_ACCESS_INTENTION_EF_READ = 0x01, /*< EF: READ BINARY, READ RECORD(s), SEARCH BINARY, SEARCH RECORDS */
	SS_ACCESS_INTENTION_EF_UPDATE_ERASE = 0x02, /*< EF: UPDATE BINARY, UPDATE RECORD, ERASE BINARY, ERASE RECORD(S) */
	SS_ACCESS_INTENTION_EF_WRITE = 0x04, /*< EF: WRITE BINARY, WRITE RECORD(S), APPEND RECORD */

	SS_ACCESS_INTENTION_DF_DELETE_FILE = 0x01, /*< DF: DELETE FILE (child) */
	SS_ACCESS_INTENTION_DF_CREATE_EF = 0x02, /*< DF: CREATE FILE (EF creation) */
	SS_ACCESS_INTENTION_DF_CREATE_DF = 0x04, /*< DF: CREATE FILE (DF creation) */

	SS_ACCESS_INTENTION_EFDF_DEACTIVATE_FILE = 0x08, /*< EF or DF: DEACTIVATE FILE */
	SS_ACCESS_INTENTION_EFDF_ACTIVATE_FILE = 0x10, /*< EF or DF: ACTIVATE FILE */
	SS_ACCESS_INTENTION_EFDF_TERMINATE_CARD_OR_DF = 0x20, /*< EF or DF: TERMINATE EF / TERMINATE CARD USAGE (MF), TERMINATE DF */
	SS_ACCESS_INTENTION_EFDF_DELETE_FILE_SELF = 0x40, /*< EF or DF: DELETE FILE / DELTE FILE (self) */

	SS_ACCESS_INTENTION_OTHER = 0,
};

void ss_access_populate(struct ss_lchan *lchan);

bool ss_access_check_command(struct ss_apdu *apdu, enum ss_access_intention intention);
