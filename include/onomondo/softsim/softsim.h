/*
 * Copyright (c) 2024 Onomondo ApS. All rights reserved.
 *
 * SPDX-License-Identifier: GPL-3.0-only
 */

#pragma once
#include <stdint.h>
#include <stddef.h>

#ifndef _CFG
#define _CFG
#include <onomondo/softsim/config.h>
#endif // !_CFG

struct ss_context;

struct ss_context *ss_new_ctx(void);
void ss_free_ctx(struct ss_context *ctx);
void ss_reset(struct ss_context *ctx);
void ss_poll(struct ss_context *ctx);
size_t ss_atr(struct ss_context *ctx, uint8_t *atr_buf, size_t atr_buf_len);
size_t ss_transact(struct ss_context *ctx, uint8_t *response_buf, size_t response_buf_len, uint8_t *request_buf,
		   size_t *request_len);
size_t ss_application_apdu_transact(struct ss_context *ctx, uint8_t *response_buf, size_t response_buf_len,
				    uint8_t *request_buf, size_t *request_len);

uint8_t ss_is_suspended(struct ss_context *ctx);
