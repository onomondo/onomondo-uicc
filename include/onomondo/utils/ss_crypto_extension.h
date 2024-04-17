/*
 * Copyright (c) 2024 Onomondo ApS. All rights reserved.
 *
 * SPDX-License-Identifier: GPL-3.0-only
 */
#pragma once

/*
 * Motivation here is to provide a simple mechanism for importing keys from
 * different locations than the file-system. Some platforms are very limited
 * w.r.t. security and crypto engines.
 *
 * By doing this we can with relative ease enable the use of
 * dedicated secure zones. Those zones however aren't suitable for storing all
 * SoftSIM internal data. This is _a_ compromise that allows some sense of secure key storage.
 *
 * This mechanism is completely optional. By storing the key identifiers instead of keys in the
 * A00X files we can use the key ID to fetch the correct key from secure storage. The keys will still
 * live in potential non-secure RAM while in use. Immediately after use the keys are zeroed out.
 *
 * At all times where a dedicated crypto engine or other secure implementations exist (i.e. ARM TrustZone)
 * the CONFIG_EXTERNAL_CRYPTO_IMPL should be used.
 *
 * This function is called immediately before the block encryption/decryption is carried out.
 */

#ifdef CONFIG_EXTERNAL_KEY_LOAD

#include <stddef.h>
#include <stdint.h>
#include <string.h>
/*!
 * \brief Load a key from an external source
 *
 * This function is called when the SoftSIM needs to load a key from an external
 * source. The key is loaded into the buffer provided.
 *
 * \param key_id buffer with the key ID.
 * \param key buffer with the resolved key. The key is loaded into this buffer.
 * \param in_len Length of the key_id buffer
 * \param key_len Length of the key_buffer. After loading the key this should hold the length of the key.
 */
void ss_load_key_external(const uint8_t *key_id, size_t in_len, uint8_t *key, size_t *key_len) __attribute__((weak));
#endif /* ifdef CONFIG_EXTERNAL_KEY_LOAD */
