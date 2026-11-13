/*
 * Copyright (c) 2024 Onomondo ApS. All rights reserved.
 *
 * SPDX-License-Identifier: GPL-3.0-only
 *
 * Author: Philipp Maier
 */

#include <stdio.h>
#include <stdbool.h>
#include <errno.h>
#include <onomondo/softsim/utils.h>
#include "src/softsim/uicc/btlv.h"
#include "src/softsim/uicc/fcp.h"
#include "onomondo/softsim/file.h"

static void dump_fd(struct ss_fcp_file_descr *fd)
{
	printf("fd.shareable = %u\n", fd->shareable);
	printf("fd.type = %u\n", fd->type);
	printf("fd.structure = %u\n", fd->structure);
	if (fd->structure == SS_FCP_LINEAR_FIXED || fd->structure == SS_FCP_CYCLIC) {
		printf("fd.record_len = %u\n", fd->record_len);
		printf("fd.number_of_records = %u\n", fd->number_of_records);
	}
}

struct ss_buf *get_fd_from_hexstr(char *hexstr)
{
	struct ss_buf *fcp_bin;
	struct ss_list *fcp_decoded;
	struct ber_tlv_ie *fcp_decoded_envelope;
	struct ber_tlv_ie *fcp_decoded_file_descr;
	struct ss_buf *encoded_fd_buf;

	fcp_bin = ss_buf_from_hexstr(hexstr);
	fcp_decoded = ss_fcp_decode(fcp_bin);
	fcp_decoded_envelope = ss_btlv_get_ie(fcp_decoded, TS_102_221_IEI_FCP_TMPL);
	fcp_decoded_file_descr = ss_btlv_get_ie(fcp_decoded_envelope->nested, 0x82);
	encoded_fd_buf = ss_buf_dup(fcp_decoded_file_descr->value);

	ss_buf_free(fcp_bin);
	ss_btlv_free(fcp_decoded);

	return encoded_fd_buf;
}

void ss_fcp_get_file_descr_test(void)
{
	char fcp_mf[] =
		"622d8202782183023f00a509800171830400018d088a01058c04261a0000c60f90017083010183018183010a83010b";
	char fcp_ef_iccid[] = "621f8202412183022fe2a506d00120d201058a01058b032f06028002000a880110";
	char fcp_adf_usim[] =
		"6238820278218410a0000000871002ffffffff8907090000a509800171830400018d088a01058c0100c60f90017083010183018183010a83010b";
	char fcp_ef_dir[] = "622282054221002b0883022f00a506d00120d2010b8a01058b032f0604800201588801f0";
	struct ss_fcp_file_descr fd;
	struct ss_buf *encoded_fd_buf;
	int rc;

	encoded_fd_buf = get_fd_from_hexstr(fcp_mf);
	printf("FCP MF: %s\n", fcp_mf);
	rc = ss_fcp_dec_file_descr(&fd, encoded_fd_buf);
	printf("rc=%i\n", rc);
	dump_fd(&fd);
	ss_buf_free(encoded_fd_buf);

	encoded_fd_buf = get_fd_from_hexstr(fcp_ef_iccid);
	printf("FCP EF.ICCID: %s\n", fcp_ef_iccid);
	rc = ss_fcp_dec_file_descr(&fd, encoded_fd_buf);
	printf("rc=%i\n", rc);
	dump_fd(&fd);
	ss_buf_free(encoded_fd_buf);

	encoded_fd_buf = get_fd_from_hexstr(fcp_adf_usim);
	printf("FCP ADF.USIM: %s\n", fcp_adf_usim);
	rc = ss_fcp_dec_file_descr(&fd, encoded_fd_buf);
	printf("rc=%i\n", rc);
	dump_fd(&fd);
	ss_buf_free(encoded_fd_buf);

	encoded_fd_buf = get_fd_from_hexstr(fcp_ef_dir);
	printf("FCP EF.DIR: %s\n", fcp_ef_dir);
	rc = ss_fcp_dec_file_descr(&fd, encoded_fd_buf);
	printf("rc=%i\n", rc);
	dump_fd(&fd);
	ss_buf_free(encoded_fd_buf);
}

void ss_fcp_gen_file_descr_test(void)
{
	struct ss_fcp_file_descr fd;
	struct ss_buf *buf;

	/* record oriented file */
	fd.shareable = true;
	fd.type = SS_FCP_WORKING_EF;
	fd.structure = SS_FCP_LINEAR_FIXED;
	fd.record_len = 8;
	fd.number_of_records = 5;
	buf = ss_fcp_gen_file_descr(&fd);
	printf("generated FD for a record oriented file: %s\n", ss_hexdump(buf->data, buf->len));
	ss_buf_free(buf);

	/* transparent file */
	fd.shareable = true;
	fd.type = SS_FCP_WORKING_EF;
	fd.structure = SS_FCP_TRANSPARENT;
	buf = ss_fcp_gen_file_descr(&fd);
	printf("generated FD for a transparent file: %s\n", ss_hexdump(buf->data, buf->len));
	ss_buf_free(buf);
}

void ss_fcp_gen_test(void)
{
	struct ss_fcp_file_descr fd;
	struct ss_buf *fcp;

	/* record oriented file */
	fd.shareable = true;
	fd.type = SS_FCP_WORKING_EF;
	fd.structure = SS_FCP_LINEAR_FIXED;
	fd.record_len = 8;
	fd.number_of_records = 5;
	fcp = ss_fcp_gen(&fd, 0x1aaaa, 0);
	printf("generated FCP for a record oriented file: %s\n", ss_hexdump(fcp->data, fcp->len));
	ss_buf_free(fcp);

	/* transparent file */
	fd.shareable = true;
	fd.type = SS_FCP_WORKING_EF;
	fd.structure = SS_FCP_TRANSPARENT;

	fcp = ss_fcp_gen(&fd, 0x1cccc, 255);
	printf("generated FCP for a transparent file: %s\n", ss_hexdump(fcp->data, fcp->len));
	ss_buf_free(fcp);
}

/* Real definitions from files/ (without C6) */
#define FCI_ICCID "62178202412183022fe28a01058b032f06038002000a880110"
#define FCI_MF "621b8202782183023f00a5098001f18701008801008a01058b032f060f"
#define FCI_ADF_USIM "62228202782183027ff08410a0000000871002ffffffff89070900008a01058b032f060f"

struct tag_lookup_case {
	const char *name;
	const char *fci_hex;
	uint8_t tag;
	size_t min_len;
	int expected_rc;
	const char *expected_value_hex;
};

static const struct tag_lookup_case tag_lookup_cases[] = {
	/* name                              fci_hex               tag   min  rc       value */

	/* position in the template */
	{ "first child", FCI_ICCID, 0x82, 2, 0, "4121" },
	{ "middle child", FCI_ICCID, 0x8a, 1, 0, "05" },
	{ "last child", FCI_ICCID, 0x88, 1, 0, "10" },
	{ "tag missing", FCI_ICCID, 0x84, 1, -ENOENT, NULL },

	/* min_len boundaries */
	{ "len == min_len", FCI_ICCID, 0x83, 2, 0, "2fe2" },
	{ "len == min_len - 1", FCI_ICCID, 0x83, 3, -ENOENT, NULL },
	{ "zero-length IE, min 0", "6206820241218800", 0x88, 0, 0, "" },
	{ "zero-length IE, min 1", "6206820241218800", 0x88, 1, -ENOENT, NULL },

	/* lookup semantics */
	{ "duplicate tag: first wins", "62068a01058a0107", 0x8a, 1, 0, "05" },
	{ "tag only inside A5: top level", FCI_MF, 0x80, 0, -ENOENT, NULL },
	{ "constructed child itself", FCI_MF, 0xa5, 0, 0, "8001f1870100880100" },
	{ "DF name (16 B)", FCI_ADF_USIM, 0x84, 1, 0, "a0000000871002ffffffff8907090000" },
	{ "multi-byte tag 5F20 != 0x20", "62068a01055f2000", 0x20, 0, -ENOENT, NULL },
	{ "found after multi-byte tag", "62065f20008a0105", 0x8a, 1, 0, "05" },

	/* envelope */
	{ "outer tag not 62", "6f038a0105", 0x8a, 0, -EINVAL, NULL },
	{ "empty template", "6200", 0x82, 0, -ENOENT, NULL },
	{ "62 long form length", "6281038a0105", 0x8a, 1, 0, "05" },
	{ "62 length exceeds buffer", "62058a0105", 0x8a, 1, -EINVAL, NULL },
	{ "bytes after 62 are ignored", "62038a01059000", 0x8a, 1, 0, "05" },

	/* padding and validation */
	{ "FF padding at end", "62058a0105ffff", 0x8a, 1, 0, "05" },
	{ "padding then garbage", "62058a0105ff01", 0x8a, 1, -EINVAL, NULL },
	{ "malformed child after match", "62058a01058205", 0x8a, 1, -EINVAL, NULL },
};

static void ss_fcp_get_tag_test(void)
{
	size_t i;

	for (i = 0; i < SS_ARRAY_SIZE(tag_lookup_cases); i++) {
		const struct tag_lookup_case *c = &tag_lookup_cases[i];
		struct ss_buf *fci = ss_buf_from_hexstr((char *)c->fci_hex);
		struct ss_buf tag;
		int rc;

		// name the case up front, assert() itself only prints the failed expression
		fprintf(stderr, "TEST: tag_lookup: %s\n", c->name);

		// call function under test
		rc = ss_fcp_get_tag_min_len(fci, c->tag, c->min_len, &tag);

		// check if function result matches the expected rc
		assert(rc == c->expected_rc);

		if (rc == 0) {
			// correct rc, check tag and length values
			assert(strcmp(ss_hexdump(tag.data, tag.len), c->expected_value_hex) == 0);
			assert(tag.data >= fci->data);
			assert(tag.data + tag.len <= fci->data + fci->len);
		} else {
			assert(tag.data == NULL);
			assert(tag.len == 0);
		}

		ss_buf_free(fci);
	}
}

static void ss_fcp_get_tag_null_args_test(void)
{
	uint8_t junk = 0xaa;
	struct ss_buf *fci = ss_buf_from_hexstr(FCI_ICCID);
	struct ss_buf no_data = { .data = NULL, .len = 5 };
	struct ss_buf out;

	fprintf(stderr, "TEST: tag_lookup: NULL fci\n");
	out = (struct ss_buf){ .data = &junk, .len = 1 };
	assert(ss_fcp_get_tag_min_len(NULL, 0x8a, 1, &out) == -EINVAL);
	assert(out.data == NULL && out.len == 0);

	fprintf(stderr, "TEST: tag_lookup: NULL fci->data\n");
	out = (struct ss_buf){ .data = &junk, .len = 1 };
	assert(ss_fcp_get_tag_min_len(&no_data, 0x8a, 1, &out) == -EINVAL);
	assert(out.data == NULL && out.len == 0);

	fprintf(stderr, "TEST: tag_lookup: NULL out\n");
	assert(ss_fcp_get_tag_min_len(fci, 0x8a, 1, NULL) == -EINVAL); /* must not crash */

	ss_buf_free(fci);
}

static void ss_fcp_get_tag_inplace_write_test(void)
{
	struct ss_buf *fci = ss_buf_from_hexstr(FCI_ICCID);
	struct ss_buf lcsi;

	fprintf(stderr, "TEST: tag_lookup: write through view\n");
	assert(ss_fcp_get_tag_min_len(fci, 0x8a, 1, &lcsi) == 0);
	assert(lcsi.data[0] == 0x05);

	lcsi.data[0] = 0x04;
	assert(strcmp(ss_hexdump(fci->data, fci->len), "62178202412183022fe28a01048b032f06038002000a880110") == 0);

	ss_buf_free(fci);
}

// FCP add ie Tests
#define PST "90010083010183018183010a" /* fixed C6 value, so the test needs no PIN storage */

struct add_ie_case {
	const char *name;
	const char *fci_hex;
	uint32_t tag;
	const char *value_hex;
	int expected_rc;
	const char *expected_fci_hex; /* rc == 0 only; on error the fci must be unchanged */
};

static const struct add_ie_case add_ie_cases[] = {
	/* real FCIs: the SELECT path */
	{ "MF + C6", FCI_MF, 0xc6, PST, 0,
	  "62298202782183023f00a5098001f18701008801008a01058b032f060f"
	  "c60c" PST },
	{ "ADF.USIM + C6", FCI_ADF_USIM, 0xc6, PST, 0,
	  "62308202782183027ff08410a0000000871002ffffffff89070900008a01058b032f060f"
	  "c60c" PST },

	/* edge cases of the template */
	{ "empty template", "6200", 0xc6, PST, 0,
	  "620e"
	  "c60c" PST },
	{ "empty value", "62038a0105", 0xc6, "", 0, "62058a0105c600" },
	{ "62 long form -> short", "6281038a0105", 0xc6, PST, 0,
	  "62118a0105"
	  "c60c" PST },
	{ "FF padding dropped", "62058a0105ffff", 0xc6, PST, 0,
	  "62118a0105"
	  "c60c" PST },
	{ "bytes after 62 dropped", "62038a01059000", 0xc6, PST, 0,
	  "62118a0105"
	  "c60c" PST },
	{ "non-minimal child kept", "62048a810105", 0xc6, PST, 0,
	  "62128a810105"
	  "c60c" PST },
	{ "C6 present: appended", "620ec60c" PST, 0xc6, PST, 0,
	  "621c"
	  "c60c" PST "c60c" PST },

	/* errors: fci must stay unchanged */
	{ "outer tag not 62", "6f038a0105", 0xc6, PST, -EINVAL, NULL },
	{ "malformed child", "62058a01058205", 0xc6, PST, -EINVAL, NULL },
	{ "padding then garbage", "62058a0105ff01", 0xc6, PST, -EINVAL, NULL },
	{ "62 length exceeds buffer", "62058a0105", 0xc6, PST, -EINVAL, NULL },
	{ "multi-byte tag 5F20", FCI_MF, 0x5f20, PST, -EINVAL, NULL },
	{ "tag low bits 1F (DF)", FCI_MF, 0xdf, PST, -EINVAL, NULL },
};

static struct ss_buf *make_fci(size_t content_len)
{
	size_t hdr = content_len < 0x80 ? 2 : 3;
	struct ss_buf *fci = ss_buf_alloc(hdr + content_len);
	uint8_t *p = fci->data;

	*p++ = 0x62;
	if (hdr == 3)
		*p++ = 0x81;
	*p++ = content_len;
	*p++ = 0x8a;
	*p++ = 0x81;
	*p++ = content_len - 3;
	memset(p, 0x00, content_len - 3);
	return fci;
}

static void ss_fcp_add_ie_test(void)
{
	size_t i;

	for (i = 0; i < SS_ARRAY_SIZE(add_ie_cases); i++) {
		const struct add_ie_case *c = &add_ie_cases[i];
		struct ss_file file = { 0 };
		struct ss_buf *value = ss_buf_from_hexstr((char *)c->value_hex);
		struct ss_buf *orig;
		char before[256];
		int rc;

		fprintf(stderr, "TEST: add_ie: %s\n", c->name);

		file.fci = ss_buf_from_hexstr((char *)c->fci_hex);
		orig = file.fci;
		strcpy(before, ss_hexdump(file.fci->data, file.fci->len)); /* hexdump buffers rotate */

		rc = ss_fcp_add_ie(&file, c->tag, value);
		assert(rc == c->expected_rc);

		if (rc == 0) {
			assert(file.fci != orig); /* new buffer (alloc happens before the free, so no reuse) */
			assert(strcmp(ss_hexdump(file.fci->data, file.fci->len), c->expected_fci_hex) == 0);
		} else {
			assert(file.fci == orig); /* untouched on error */
			assert(strcmp(ss_hexdump(file.fci->data, file.fci->len), before) == 0);
		}

		ss_buf_free(file.fci);
		ss_buf_free(value);
	}
}

static void ss_fcp_add_ie_null_args_test(void)
{
	struct ss_buf *value = ss_buf_from_hexstr(PST);
	struct ss_buf no_data = { .data = NULL, .len = 5 };
	struct ss_file file = { 0 };

	fprintf(stderr, "TEST: add_ie: NULL file\n");
	assert(ss_fcp_add_ie(NULL, 0xc6, value) == -EINVAL);

	fprintf(stderr, "TEST: add_ie: NULL file->fci\n");
	file.fci = NULL;
	assert(ss_fcp_add_ie(&file, 0xc6, value) == -EINVAL);

	fprintf(stderr, "TEST: add_ie: NULL fci->data\n");
	file.fci = &no_data;
	assert(ss_fcp_add_ie(&file, 0xc6, value) == -EINVAL);
	assert(file.fci == &no_data); //untouched

	fprintf(stderr, "TEST: add_ie: NULL value\n");
	file.fci = ss_buf_from_hexstr(FCI_MF);
	assert(ss_fcp_add_ie(&file, 0xc6, NULL) == -EINVAL);
	ss_buf_free(file.fci);

	ss_buf_free(value);
}

int main(int argc, char **argv)
{
	ss_fcp_get_file_descr_test();
	ss_fcp_gen_file_descr_test();
	ss_fcp_gen_test();
	ss_fcp_get_tag_test();
	ss_fcp_get_tag_null_args_test();
	ss_fcp_get_tag_inplace_write_test();
	ss_fcp_add_ie_test();
	ss_fcp_add_ie_null_args_test();
	return 0;
}
