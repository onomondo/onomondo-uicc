/*
 * Copyright (c) 2024 Onomondo ApS. All rights reserved.
 *
 * SPDX-License-Identifier: GPL-3.0-only
 */

#include <stdlib.h>
#include <string.h>
#include <onomondo/utils/ss_crypto_extension.h>

/* IMPL some sensible default */

void ss_load_key_external(const uint8_t *key_id, size_t in_len, uint8_t *key, size_t *key_len)
{
	memcpy(key, key_id, in_len);
	*key_len = in_len;
}
