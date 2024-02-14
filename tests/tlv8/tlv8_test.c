/*
 * Author: Philipp Maier
 *
 */

#include <stdio.h>
#include <string.h>
#include <onomondo/softsim/log.h>
#include <onomondo/softsim/mem.h>
#include <onomondo/softsim/utils.h>
#include "src/softsim/uicc/tlv8.h"

static void ss_tlv8_decode_test(void)
{
	uint8_t encoded[] =
	    { 0x81, 0x03, 0x01, 0x21, 0x00, 0x82, 0x02, 0x81, 0x02,
		0x8d, 0x0c, 0x04, 'H', 'E', 'L', 'L', 'O', ',', 'W', 'O', 'R',
		'L', 'D',
		0xc8, 0x04, 0x01, 0x02, 0x03, 0x04
	};

	struct ss_list *decoded;

	fprintf(stderr, "\nTEST: decode a TLV8 encoded string\n");
	fprintf(stderr, "encoded input:  %s\n",
		ss_hexdump(encoded, sizeof(encoded)));

	fprintf(stderr, "decoded output:\n");
	decoded = ss_tlv8_decode(encoded, sizeof(encoded));
	ss_tlv8_dump(decoded, 0, STLV8, LDEBUG);
	ss_tlv8_free(decoded);
}

static void ss_tlv8_encode_test(void)
{
	struct ss_list *decoded;
	uint8_t encoded[1024];
	int rc;

	uint8_t encoded_expected[] =
	    { 0x81, 0x03, 0x01, 0x21, 0x00, 0x82, 0x02, 0x81, 0x02,
		0x8d, 0x0c, 0x04, 'H', 'E', 'L', 'L', 'O', ',', 'W', 'O', 'R',
		'L', 'D',
		0xc8, 0x04, 0x01, 0x02, 0x03, 0x04
	};

	/* Set up BER-TLV tree */
	decoded = SS_ALLOC(struct ss_list);
	ss_list_init(decoded);

	ss_tlv8_new_ie(decoded, 0x81, 3, (uint8_t *) "\x01\x21\x00");
	ss_tlv8_new_ie(decoded, 0x82, 2, (uint8_t *) "\x81\x02");
	ss_tlv8_new_ie(decoded, 0x8d, 12, (uint8_t *)
		       "\x04\x48\x45\x4c\x4c\x4f\x2c\x57\x4f\x52\x4c\x44");
	ss_tlv8_new_ie(decoded, 0xc8, 4, (uint8_t *) "\x01\x02\x03\x04");

	fprintf(stderr,
		"\nTEST: encode a binary TLV8 encoded string from decoded list\n");
	fprintf(stderr, "TLV8 data to be encoded:\n");
	ss_tlv8_dump(decoded, 2, STLV8, LDEBUG);
	rc = ss_tlv8_encode(encoded, sizeof(encoded), decoded);
	fprintf(stderr, "expected result: %s\n",
		ss_hexdump(encoded_expected, sizeof(encoded_expected)));
	fprintf(stderr, "encoded result:  %s\n", ss_hexdump(encoded, rc));
	ss_tlv8_free(decoded);
}

int main(int argc, char **argv)
{
	ss_tlv8_decode_test();
	ss_tlv8_encode_test();
	return 0;
}
