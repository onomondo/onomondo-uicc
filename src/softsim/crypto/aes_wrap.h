/*
 * AES-based functions
 *
 * - AES-128 single block encryption
 *
 * Copyright (c) 2003-2012, Jouni Malinen <j@w1.fi>
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#ifndef AES_WRAP_H
#define AES_WRAP_H

int __must_check aes_128_encrypt_block(const u8 *key, const u8 *in, u8 *out);

#endif /* AES_WRAP_H */
