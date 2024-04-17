/*
 * Copyright (c) 2024 Onomondo ApS. All rights reserved.
 *
 * SPDX-License-Identifier: GPL-3.0-only
 *
 * Author: Philipp Maier
 */

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdbool.h>
#include <onomondo/softsim/utils.h>

/*! Generate a hexdump string from the input data.
 *  \param[in] data pointer to binary data.
 *  \param[in] len length of binary data.
 *  \returns pointer to generated human readable string. */
#define SS_HEXDUMP_MAX 4
#define SS_HEXDUMP_BUFSIZE 1024
char *ss_hexdump(const uint8_t *data, size_t len)
{
	static char out[SS_HEXDUMP_MAX][SS_HEXDUMP_BUFSIZE];
	static uint8_t idx = 0;
	char *out_ptr;
	size_t i;

	idx++;
	idx = idx % SS_HEXDUMP_MAX;
	out_ptr = out[idx];

	if (!data)
		return ("(null)");

	for (i = 0; i < len; i++) {
		sprintf(out_ptr, "%02x", data[i]);
		out_ptr += 2;

		/* put three dots and exit early in case we are running out of
		 * space */
		if (i > SS_HEXDUMP_BUFSIZE / 2 - 4) {
			sprintf(out_ptr, "...");
			return out[idx];
		}
	}

	*out_ptr = '\0';
	return out[idx];
}

static bool is_hex(char hex_digit)
{
	switch (hex_digit) {
	case 'A':
	case 'B':
	case 'C':
	case 'D':
	case 'E':
	case 'F':
	case 'a':
	case 'b':
	case 'c':
	case 'd':
	case 'e':
	case 'f':
	case '1':
	case '2':
	case '3':
	case '4':
	case '5':
	case '6':
	case '7':
	case '8':
	case '9':
	case '0':
		return true;
	}

	return false;
}

/*! Convert a human readable hex string to its binary representation.
 *  \param[in] binary pointer to binary data.
 *  \param[in] binary_len length of binary data.
 *  \param[in] hexstr string with human readable representation.
 *  \returns number resulting bytes. */
size_t ss_binary_from_hexstr(uint8_t *binary, size_t binary_len, const char *hexstr)
{
	unsigned int i;
	size_t hexstr_len;
	char hex_digit[3];
	unsigned int hex_digit_bin;
	size_t binary_count = 0;
	int rc;

	hexstr_len = strlen(hexstr);

	memset(binary, 0, binary_len);

	for (i = 0; i < hexstr_len / 2; i++) {
		hex_digit[0] = hexstr[0];
		hex_digit[1] = hexstr[1];
		hex_digit[2] = '\0';
		hexstr += 2;

		if (!is_hex(hex_digit[0]) || !is_hex(hex_digit[1]))
			hex_digit_bin = 0xff;
		else {
			rc = sscanf(hex_digit, "%02x", &hex_digit_bin);
			if (rc != 1)
				hex_digit_bin = 0xff;
		}

		binary[binary_count] = (uint8_t)hex_digit_bin & 0xff;
		binary_count++;

		if (binary_count >= binary_len)
			break;
	}

	return binary_count;
}

/*! Allocate a new ss_buf and fill it with data from given hexstring.
 *  \param[in] hexstr pointer to human readable hexstring.
 *  \returns pointer to newly allocated ss_buf object. */
struct ss_buf *ss_buf_from_hexstr(const char *hexstr)
{
	int bin_len = strlen(hexstr) / 2;
	struct ss_buf *sb = ss_buf_alloc(bin_len);

	ss_binary_from_hexstr(sb->data, sb->len, hexstr);

	return sb;
}

/*! Convert an array of up to 4 bytes to an uint32_t.
 *  \param[in] array user provided memory with bytes to convert.
 *  \param[in] len length of the array.
 *  \returns converted value as uint32_t. */
uint32_t ss_uint32_from_array(const uint8_t *array, size_t len)
{
	uint32_t rc = 0;
	size_t i;
	uint32_t byte;

	if (len > 4)
		len = 4;

	for (i = 0; i < len; i++) {
		byte = array[len - i - 1];
		rc |= (byte << i * 8);
	}

	return rc;
}

/*! Convert an array of up to 8 bytes to an uint64_t.
 *  \param[in] array user provided memory with bytes to convert.
 *  \param[in] len length of the array.
 *  \returns converted value as uint64_t. */
uint64_t ss_uint64_from_array(const uint8_t *array, size_t len)
{
	uint64_t rc = 0;
	size_t i;
	uint64_t byte;

	if (len > 8)
		len = 8;

	for (i = 0; i < len; i++) {
		byte = array[len - i - 1];
		rc |= (byte << i * 8);
	}

	return rc;
}

/*! Convert an uint32_t value into an array of up to 4 bytes.
 *  \param[in] array user provided memory to store the result.
 *  \param[in] len length of the array (1-4).
 *  \param[in] in uint32_t value to convert. */
void ss_array_from_uint32(uint8_t *array, size_t len, uint32_t in)
{
	size_t i;

	if (len > 4)
		len = 4;

	for (i = 0; i < len; i++)
		array[len - i - 1] = (in >> i * 8) & 0xff;
}

/*! Convert an uint64_t value into an array of up to 8 bytes.
 *  \param[in] array user provided memory to store the result.
 *  \param[in] len length of the array (1-8).
 *  \param[in] in uint32_t value to convert. */
void ss_array_from_uint64(uint8_t *array, size_t len, uint64_t in)
{
	size_t i;

	if (len > 8)
		len = 8;

	for (i = 0; i < len; i++)
		array[len - i - 1] = (in >> i * 8) & 0xff;
}

/*! Find the optimal array length to store an uint32_t.
 *  \returns number of bytes required. */
size_t ss_optimal_len_for_uint32(uint32_t in)
{
	if (in > 0xffffff)
		return 4;
	if (in > 0xffff)
		return 3;
	if (in > 0xff)
		return 2;
	return 1;
}

/* If we had htobe64 etc. around, we could copy data into a union type and let
 * type punning and htobe64 do the work. As we don't have functionas around
 * that give data in reversed endianness, we do everything in a fully in a
 * platform independent way rather than by looking at the endianness, trusting
 * that the compiler will recognize that a byte swap or plain copy will do as
 * well. */

/*! Load an uint64_t value from a storage location (8 bytes, BE).
 *  \param[in] storage user provided memory where the the uint64_t shall be loaded from.
 *  \returns converted value as uint64_t. */
uint64_t ss_uint64_load_from_be(const uint8_t *storage)
{
	return ((uint64_t)storage[0] << (7 * 8)) | ((uint64_t)storage[1] << (6 * 8)) |
	       ((uint64_t)storage[2] << (5 * 8)) | ((uint64_t)storage[3] << (4 * 8)) |
	       ((uint64_t)storage[4] << (3 * 8)) | ((uint64_t)storage[5] << (2 * 8)) |
	       ((uint64_t)storage[6] << (1 * 8)) | ((uint64_t)storage[7] << (0 * 8));
}

/*! Store an uint64_t value to a storage location (8 bytes, BE).
 *  \param[out] storage user provided memory where the the uint64_t shall be stored to.
 *  \param[in] number uint64_t value to store. */
void ss_uint64_store_to_be(uint8_t *storage, uint64_t number)
{
	storage[0] = number >> (7 * 8);
	storage[1] = number >> (6 * 8);
	storage[2] = number >> (5 * 8);
	storage[3] = number >> (4 * 8);
	storage[4] = number >> (3 * 8);
	storage[5] = number >> (2 * 8);
	storage[6] = number >> (1 * 8);
	storage[7] = number >> (0 * 8);
}

/*! An alternative to strnlen(), which is not present in c99.
 *  \param[in] s string to evaluate.
 *  \param[in] maxlen maximum length of the buffer that contains the string. */
size_t ss_strnlen(const char *s, size_t maxlen)
{
	size_t i;
	bool digits_str_valid = false;

	if (maxlen <= 1)
		return 0;

	/* Make sure that the string is valid */
	if (s[maxlen - 1] != '\0') {
		for (i = 0; i < maxlen; i++) {
			if (s[i] == '\0')
				digits_str_valid = true;
		}
	} else
		digits_str_valid = true;

	if (!digits_str_valid)
		return 0;

	return strlen(s);
}

/** Like memzero, but go through a volatile pointer to ensure
 * that zeroing memory on the stack before a function return
 * does not get optimized away.
 *
 * This serves the same purpose as memset_s, explizit_bzero or
 * SecureZeroMemory as available on different platforms */
void ss_memzero(void *ptr, size_t len)
{
	int i = 0;
	volatile char *clear_this = (volatile char *)ptr;
	for (i = 0; i < len; i++)
		clear_this[i] = 0;
}
