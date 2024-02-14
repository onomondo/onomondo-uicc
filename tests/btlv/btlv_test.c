/*
 * Copyright (c) 2024 Onomondo ApS. All rights reserved.
 *
 * SPDX-License-Identifier: GPL-3.0-only
 *
 * Author: Philipp Maier
 */

#include <stdio.h>
#include <string.h>
#include <onomondo/softsim/log.h>
#include <onomondo/softsim/mem.h>
#include <onomondo/softsim/utils.h>
#include "src/softsim/uicc/btlv.h"
#include "src/softsim/uicc/fcp.h"

const struct ber_tlv_desc bertlv_tree_descr[] = {
	{
		.id = 1,
		.id_parent = 0,
		.title = "envelope",
		.tag_encoded = TS_102_221_IEI_FCP_TMPL,
	},
	{
		.id = 2,
		.id_parent = 1,
		.title = "one",
		.tag_encoded = 0x82,
	},
	{
		.id = 3,
		.id_parent = 1,
		.title = "two",
		.tag_encoded = 0x84,
	},
	{
		.id = 4,
		.id_parent = 1,
		.title = "nested-envelope",
		.tag_encoded = 0xa5,
	},
	{
		.id = 5,
		.id_parent = 4,
		.title = "three",
		.tag_encoded = 0x80,
	},
	{
		.id = 6,
		.id_parent = 4,
		.title = "four",
		.tag_encoded = 0x83,
	},
	{
		.id = 7,
		.id_parent = 1,
		.title = "five",
		.tag_encoded = 0x8a,
	},
	{
		.id = 8,
		.id_parent = 1,
		.title = "six",
		.tag_encoded = 0x8c,
	},
	{
		.id = 9,
		.id_parent = 1,
		.title = "eight",
		.tag_encoded = 0xc6,
	},
	{
		.id = 0,
	},
};

const struct ber_tlv_desc bertlv_tree_descr_misfit[] = {
	{
		.id = 1,
		.id_parent = 0,
		.title = "envelope",
		.tag_encoded = TS_102_221_IEI_FCP_TMPL,
	},
	{
		.id = 2,
		.id_parent = 1,
		.title = "one",
		.tag_encoded = 0x82,
	},
	{
		.id = 3,
		.id_parent = 1,
		.title = "two",
		.tag_encoded = 0x84,
	},
	{
		.id = 4,
		.id_parent = 1,
		.title = "nested-envelope",
		.tag_encoded = 0xa5,
	},
	{
		.id = 5,
		.id_parent = 4,
		.title = "three",
		.tag_encoded = 0x80,
	},
	{
		.id = 6,
		.id_parent = 1,
		.title = "five",
		.tag_encoded = 0x8a,
	},
	{
		.id = 7,
		.id_parent = 1,
		.title = "six",
		.tag_encoded = 0x8c,
	},
	{
		.id = 8,
		.id_parent = 1,
		.title = "nested_envelope2",
		.tag_encoded = 0xa5,
	},
	{
		.id = 9,
		.id_parent = 8,
		.title = "twentyone",
		.tag_encoded = 0xaa,
	},
	{
		.id = 0,
	},
};

/* Decode a select response that has been sampled from a real usim-card */
static void ss_btlv_decode_test_realistic(void)
{
	uint8_t encoded[] = { 0x62, 0x38, 0x82, 0x02, 0x78, 0x21, 0x84, 0x10,
		0xa0, 0x00, 0x00, 0x00, 0x87, 0x10, 0x02, 0xff,
		0xff, 0xff, 0xff, 0x89, 0x07, 0x09, 0x00, 0x00,
		0xa5, 0x09, 0x80, 0x01, 0x71, 0x83, 0x04, 0x00,
		0x01, 0x8d, 0x08, 0x8a, 0x01, 0x05, 0x8c, 0x01,
		0x00, 0xc6, 0x0f, 0x90, 0x01, 0x70, 0x83, 0x01,
		0x01, 0x83, 0x01, 0x81, 0x83, 0x01, 0x0a, 0x83,
		0x01, 0x0b
	};
	struct ss_list *decoded;

	fprintf(stderr, "\nTEST: decode a BER-TLV encoded string\n");
	fprintf(stderr, "encoded input:  %s\n", ss_hexdump(encoded, sizeof(encoded)));

	/* Without description */
	fprintf(stderr, "decoded without description:\n");
	decoded = ss_btlv_decode(encoded, sizeof(encoded), NULL);
	ss_btlv_dump(decoded, 0, SBTLV, LDEBUG);
	ss_btlv_free(decoded);

	/* With complete description */
	fprintf(stderr, "decoded with complete description:\n");
	decoded = ss_btlv_decode(encoded, sizeof(encoded), bertlv_tree_descr);
	ss_btlv_dump(decoded, 0, SBTLV, LDEBUG);
	ss_btlv_free(decoded);

	/* With not quite fitting description */
	fprintf(stderr, "decoded with non fitting description:\n");
	decoded = ss_btlv_decode(encoded, sizeof(encoded), bertlv_tree_descr_misfit);
	ss_btlv_dump(decoded, 0, SBTLV, LDEBUG);
	ss_btlv_free(decoded);
}

/* Build up a BER-TLV linked list tree and encode it. The encoded result must
 * match a sample that has been taken from a real usim-card. */
static void ss_btlv_encode_test_realistic(void)
{
	struct ss_list *decoded;
	struct ber_tlv_ie *ie_envelope;
	struct ber_tlv_ie *ie_nested_envelope;
	uint8_t encoded[1024];
	int rc;

	uint8_t encoded_expected[] =
	    { 0x62, 0x38, 0x82, 0x02, 0x78, 0x21, 0x84, 0x10,
		0xa0, 0x00, 0x00, 0x00, 0x87, 0x10, 0x02, 0xff,
		0xff, 0xff, 0xff, 0x89, 0x07, 0x09, 0x00, 0x00,
		0xa5, 0x09, 0x80, 0x01, 0x71, 0x83, 0x04, 0x00,
		0x01, 0x8d, 0x08, 0x8a, 0x01, 0x05, 0x8c, 0x01,
		0x00, 0xc6, 0x0f, 0x90, 0x01, 0x70, 0x83, 0x01,
		0x01, 0x83, 0x01, 0x81, 0x83, 0x01, 0x0a, 0x83,
		0x01, 0x0b
	};

	/* Set up BER-TLV tree */
	decoded = SS_ALLOC(struct ss_list);
	ss_list_init(decoded);
	ie_envelope = ss_btlv_new_ie_constr(decoded, "envelope", TS_102_221_IEI_FCP_TMPL);
	ss_btlv_new_ie(ie_envelope->nested, "one", 0x82, 2,
		       (uint8_t *) "\x78\x21");
	ss_btlv_new_ie(ie_envelope->nested, "two", 0x84, 16, (uint8_t *)
		       "\xa0\x00\x00\x00\x87\x10\x02\xff\xff\xff\xff\x89\x07\x09\x00\x00");
	ie_nested_envelope =
	    ss_btlv_new_ie_constr(ie_envelope->nested, "nested-envelope", 0xa5);
	ss_btlv_new_ie(ie_nested_envelope->nested, "three", 0x80, 1,
		       (uint8_t *) "\x71");
	ss_btlv_new_ie(ie_nested_envelope->nested, "four", 0x83, 4,
		       (uint8_t *) "\x00\x01\x8d\x08");
	ss_btlv_new_ie(ie_envelope->nested, "five", 0x8a, 1,
		       (uint8_t *) "\x05");
	ss_btlv_new_ie(ie_envelope->nested, "six", 0x8c, 1,
		       (uint8_t *) "\x00");
	ss_btlv_new_ie(ie_envelope->nested, "eight", 0xc6, 15, (uint8_t *)
		       "\x90\x01\x70\x83\x01\x01\x83\x01\x81\x83\x01\x0a\x83\x01\x0b");

	fprintf(stderr, "\nTEST: encode a binary BER-TLV encoded string from decoded list\n");
	fprintf(stderr, "BER-TLV data to be encoded:\n");
	ss_btlv_dump(decoded, 2, SBTLV, LDEBUG);
	rc = ss_btlv_encode(encoded, sizeof(encoded), decoded);
	fprintf(stderr, "expected result: %s\n", ss_hexdump(encoded_expected, sizeof(encoded_expected)));
	fprintf(stderr, "encoded result:  %s\n", ss_hexdump(encoded, rc));
	ss_btlv_free(decoded);
}

const struct ber_tlv_desc decode_encode_test_descr[] = {
	{
		.id = 1,
		.id_parent = 0,
		.title = "single-byte-tag",
		.tag_encoded = 0x0a,
	},
	{
		.id = 2,
		.id_parent = 0,
		.title = "two-byte-tag",
		.tag_encoded = 0xdf55,
	},
	{
		.id = 3,
		.id_parent = 0,
		.title = "three-byte-tag",
		.tag_encoded = 0xdfaaaa,
	},
	{
		.id = 4,
		.id_parent = 0,
		.title = "one-byte-len",
		.tag_encoded = 0x01,
	},
	{
		.id = 5,
		.id_parent = 0,
		.title = "two-byte-len",
		.tag_encoded = 0x02,
	},
	{
		.id = 6,
		.id_parent = 0,
		.title = "three-byte-len",
		.tag_encoded = 0x03,
	},
	{
		.id = 0,
	}
};

/* BER-TLV offers flexible header and tag length. This tests different header
 * and tag length formats against its own implementation. */
static void ss_btlv_encode_decode_test(void)
{
	struct ss_list *decoded;
	struct ss_list *decoded_from_encoded;
	uint8_t encoded[80000];
	size_t bytes_encoded;

	uint8_t buf_one_byte_len[126];
	uint8_t buf_two_byte_len[255];
	uint8_t buf_three_byte_len[65535];

	memset(buf_one_byte_len, 0xaa, sizeof(buf_one_byte_len));
	memset(buf_two_byte_len, 0xbb, sizeof(buf_two_byte_len));
	memset(buf_three_byte_len, 0xcc, sizeof(buf_three_byte_len));

	/* Set up BER-TLV tree */
	decoded = SS_ALLOC(struct ss_list);
	ss_list_init(decoded);

	/* Try all possible TAG lengths */
	ss_btlv_new_ie(decoded, "single-byte-tag", 0x0a, 1,
		       (uint8_t *) "\xff");
	ss_btlv_new_ie(decoded, "two-byte-tag", 0xdf55, 1, (uint8_t *) "\xff");
	ss_btlv_new_ie(decoded, "three-byte-tag", 0xdfaaaa, 1,
		       (uint8_t *) "\xff");

	/* Try up to three byte length field length */
	ss_btlv_new_ie(decoded, "one-byte-len", 0x01,
		       sizeof(buf_one_byte_len), buf_one_byte_len);
	ss_btlv_new_ie(decoded, "two-byte-len", 0x02,
		       sizeof(buf_two_byte_len), buf_two_byte_len);
	ss_btlv_new_ie(decoded, "three-byte-len", 0x03,
		       sizeof(buf_three_byte_len), buf_three_byte_len);

	fprintf(stderr, "\nTEST: encode a binary BER-TLV encoded string with multi byte header fields\n");
	fprintf(stderr, "BER-TLV data to be encoded: (encoder test)\n");
	ss_btlv_dump(decoded, 2, SBTLV, LDEBUG);
	bytes_encoded = ss_btlv_encode(encoded, sizeof(encoded), decoded);
	fprintf(stderr, "bytes encoded: %lu\n", bytes_encoded);
	fprintf(stderr, "encoded result:  %s\n", ss_hexdump(encoded, bytes_encoded));

	fprintf(stderr, "decoded encoded result: (decoder test)\n");
	decoded_from_encoded = ss_btlv_decode(encoded, bytes_encoded, decode_encode_test_descr);
	ss_btlv_dump(decoded_from_encoded, 2, SBTLV, LDEBUG);

	ss_btlv_free(decoded);
	ss_btlv_free(decoded_from_encoded);
}

/* Test what happens when some invalid data is fed into the decoder. This is
 * not supposed to crash. */
static void ss_btlv_decode_noise_test(void)
{
	struct ss_list *decoded;
	uint8_t encoded[] = {
		0x63, 0x06, 0x20, 0x3a, 0x7c, 0x12, 0xc5, 0xb9,
		0x6b, 0x7e, 0xa6, 0x96, 0x61, 0x4f, 0xe0, 0xa6,
		0x12, 0xfa, 0x37, 0x03, 0x97, 0x26, 0xc6, 0x0d,
		0xd0, 0x9f, 0xed, 0xa6, 0x10, 0x00, 0x2e, 0x00,
		0x4c, 0xd4, 0xdb, 0x07, 0x21, 0x5e, 0xb1, 0x38,
		0xa1, 0xdb, 0x63, 0x0c, 0x3c, 0xf8, 0x22, 0xf5,
		0x20, 0x98, 0x43, 0x58, 0x59, 0x0b, 0xc7, 0x51,
		0xea, 0x01, 0x70, 0xb1, 0x16, 0xef, 0x83, 0x1c,
		0xb8, 0x57, 0xdc, 0x9b, 0xf1, 0x49, 0x6e, 0x97,
	};
	fprintf(stderr, "\nTEST: decode a BER-TLV encoded string\n");
	fprintf(stderr, "encoded input:  %s\n", ss_hexdump(encoded, sizeof(encoded)));
	decoded = ss_btlv_decode(encoded, sizeof(encoded), NULL);
	ss_btlv_free(decoded);
}

int main(int argc, char **argv)
{
	ss_btlv_decode_test_realistic();
	ss_btlv_encode_test_realistic();
	ss_btlv_encode_decode_test();
	ss_btlv_decode_noise_test();
	return 0;
}
