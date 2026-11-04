/*
 * Copyright (c) 2026 Onomondo ApS. All rights reserved.
 *
 * SPDX-License-Identifier: GPL-3.0-only
 */

#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <onomondo/softsim/softsim.h>
#include "src/softsim/uicc/context.h"
#include "src/softsim/uicc/proactive.h"
extern uint32_t ss_log_mask;

/* '91 XX' caps a proactive command at 255 bytes (ETSI TS 102 221, 10.2.1.1); a longer one must be refused without
 * taking the slot, or later ones (SEND SHORT MESSAGE, REFRESH) wait for a TERMINAL RESPONSE that never comes. */
static void put(struct ss_context *ctx, size_t len, int expected_rc)
{
	uint8_t data[300];
	int rc;

	memset(data, 0x55, sizeof(data));
	rc = ss_proactive_put(ctx, NULL, data, len);
	printf("put %zu bytes: rc=%d data_len=%u ready=%d\n", len, rc, ctx->proactive.data_len, ss_proactive_rts(ctx));
	assert(rc == expected_rc);
}

int main(void)
{
	struct ss_context *ctx;

	ss_log_mask = 0;
	ctx = ss_new_ctx();
	ss_reset(ctx);

	/* 253 bytes of body encode to exactly 256 bytes: one too many */
	put(ctx, 253, -EINVAL);
	assert(ss_proactive_rts(ctx));
	put(ctx, 300, -EINVAL);
	assert(ss_proactive_rts(ctx));

	/* 252 bytes of body are the largest command that fits */
	put(ctx, 252, 0);
	assert(ctx->proactive.data_len == 255);
	assert(!ss_proactive_rts(ctx));
	put(ctx, 10, -EBUSY);

	ss_free_ctx(ctx);
	return 0;
}
