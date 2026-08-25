/*
 * Copyright (c) 2024 Onomondo ApS. All rights reserved.
 * 
 * SPDX-License-Identifier: GPL-3.0-only 
 */

#pragma once

#include "uicc_lchan.h"
#include "proactive.h"
#include "fs_chg.h"

/* The CONFIG_DISABLE_* opt-outs follow the reachability graph: OTA commands
 * arrive over SMS, and SMS as well as REFRESH run on the proactive machinery.
 * Catch impossible combinations here for builds that bypass CMakeLists.txt. */
#if defined(CONFIG_DISABLE_SMS) && !defined(CONFIG_DISABLE_OTA)
#error CONFIG_DISABLE_SMS requires CONFIG_DISABLE_OTA
#endif
#if defined(CONFIG_DISABLE_PROACTIVE) && !(defined(CONFIG_DISABLE_SMS) && defined(CONFIG_DISABLE_REFRESH))
#error CONFIG_DISABLE_PROACTIVE requires CONFIG_DISABLE_SMS and CONFIG_DISABLE_REFRESH
#endif

/* Context for one softsim instance. */
struct ss_context {
	/* context holding the state for the (one and only) logical channel */
	struct ss_lchan lchan;

#ifndef CONFIG_DISABLE_PROACTIVE
	/* context holding the state for proactive SIM commands */
	struct ss_proactive_ctx proactive;
#endif

	/* pointer to an array of size SS_FS_CHG_BUF_SIZE */
	uint8_t *fs_chg_filelist;

	/* File changes through this context are recorded in the associated
	 * file list */
	bool fs_chg_record;

	/* If true, then fs_chg_filelist is owned by a different context */
	bool fs_chg_is_borrowed;

	bool is_suspended;
};

struct ss_context *ss_new_reporting_ctx(uint8_t *fs_chg_filelist);
