/*
 * Copyright (c) 2024 Onomondo ApS. All rights reserved.
 *
 * SPDX-License-Identifier: GPL-3.0-only
 *
 * Author: Philipp Maier
 * 
 * TODO #61: Until now, there is no support planned for multiple channels. Only
 * one basic channel shall be supported. This file is a placeholder.
 */

#include <assert.h>
#include <string.h>
#include <onomondo/softsim/softsim.h>
#include <onomondo/softsim/log.h>
#include <onomondo/softsim/utils.h>
#include "access.h"
#include "uicc_lchan.h"
#include "fs.h"
#include "fs_utils.h"
#include "context.h"
#include "apdu.h"
#include "sw.h"
#include "fcp.h"

/*! Dump lchan status information.
 *  \param[in] lchan lchan to dump. */
void ss_uicc_lchan_dump(const struct ss_lchan *lchan)
{
	unsigned int i;
	struct ss_file *active_adf;
	struct ss_buf *active_adf_name = NULL;

	SS_LOGP(SLCHAN, LDEBUG, "lchan %u:\n", lchan->nr);
	for (i = 0; i < SS_ARRAY_SIZE(lchan->pin_verfied); i++) {
		if (lchan->pin_verfied[i])
			SS_LOGP(SLCHAN, LDEBUG, " pin %u verifed\n", i);
	}

	SS_LOGP(SLCHAN, LDEBUG, " selected file: %s\n", ss_fs_utils_dump_path(&lchan->fs_path));
	active_adf = ss_get_file_from_path(&lchan->adf_path);
	if (active_adf)
		active_adf_name = ss_fcp_get_df_name(active_adf->fcp_decoded);
	SS_LOGP(SLCHAN, LDEBUG, " active ADF: %s - %s\n", ss_fs_utils_dump_path(&lchan->adf_path),
		active_adf_name ? ss_hexdump(active_adf_name->data, active_adf_name->len) : "(no AID)");
	SS_LOGP(SLCHAN, LDEBUG, " current record: %u\n", lchan->current_record);
}

/*! Free all dynamically allocated data inside all lchans.
 *  \param[inout] ctx softsim context. */
void ss_uicc_lchan_free(struct ss_context *ctx)
{
	/* Make sure pathes are cleared */
	if (ctx->lchan.fs_path.next != NULL)
		ss_path_reset(&ctx->lchan.fs_path);
	if (ctx->lchan.adf_path.next != NULL)
		ss_path_reset(&ctx->lchan.adf_path);

	/* Get rid of last APDU */
	SS_FREE(ctx->lchan.last_apdu);

	/* Ensure all lchan memory is zeroed out */
	memset(&ctx->lchan, 0, sizeof(ctx->lchan));
}

/*! Reset (close) all lchans (called on UICC reset).
 *  \param[inout] ctx softsim context. */
void ss_uicc_lchan_reset(struct ss_context *ctx)
{
	/* Get rid of all dynamically allocated data */
	ss_uicc_lchan_free(ctx);

	/* Initialize lchan global pathes */
	ss_fs_init(&ctx->lchan.fs_path);
	ss_fs_init(&ctx->lchan.adf_path);

	/* Can be the case during commissioning, before the MF was created */
	if (ss_get_file_from_path(&ctx->lchan.fs_path) != NULL)
		ss_access_populate(&ctx->lchan);
}

/*! Get matching lchan for specified CLA byte.
 *  \param[inout] ctx softsim context.
 *  \param[out] cla byte (0x00 for basic channel).
 *  \returns lchan, NULL if lchan is not found. */
struct ss_lchan *ss_uicc_lchan_get(struct ss_context *ctx, uint8_t cla)
{
	/* See also: ISO 7816-4, section 5.1.1 */
	uint8_t lchan_nr = cla & 0x03;
	if (lchan_nr == 0)
		return &ctx->lchan;
	else {
		SS_LOGP(SLCHAN, LERROR, "lchan %u not found (cla=%02x)\n", lchan_nr, cla);
		return NULL;
	}
}

/*! MANAGE CHANNEL (TS 102 221 Section 11.1.17) */
int ss_uicc_lchan_cmd_manage_channel(struct ss_apdu *apdu)
{
	/* We only support the basic logical channel. Opening or closing
	 * logical cannels is not supported. */
	apdu->le = 0;
	return SS_SW_ERR_FUNCTION_IN_CLA_NOT_SUPP_LCHAN;
}
