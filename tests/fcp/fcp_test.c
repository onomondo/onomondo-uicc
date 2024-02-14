/*
 * Copyright (c) 2024 Onomondo ApS. All rights reserved.
 *
 * SPDX-License-Identifier: GPL-3.0-only
 *
 * Author: Philipp Maier
 */

#include <stdio.h>
#include <stdbool.h>
#include <onomondo/softsim/utils.h>
#include "src/softsim/uicc/btlv.h"
#include "src/softsim/uicc/fcp.h"

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
	char fcp_ef_iccid[] =
	    "621f8202412183022fe2a506d00120d201058a01058b032f06028002000a880110";
	char fcp_adf_usim[] =
	    "6238820278218410a0000000871002ffffffff8907090000a509800171830400018d088a01058c0100c60f90017083010183018183010a83010b";
	char fcp_ef_dir[] =
	    "622282054221002b0883022f00a506d00120d2010b8a01058b032f0604800201588801f0";
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
	printf("generated FCP for a record oriented file: %s\n",
	       ss_hexdump(fcp->data, fcp->len));
	ss_buf_free(fcp);

	/* transparent file */
	fd.shareable = true;
	fd.type = SS_FCP_WORKING_EF;
	fd.structure = SS_FCP_TRANSPARENT;

	fcp = ss_fcp_gen(&fd, 0x1cccc, 255);
	printf("generated FCP for a transparent file: %s\n",
	       ss_hexdump(fcp->data, fcp->len));
	ss_buf_free(fcp);
}

int main(int argc, char **argv)
{
	ss_fcp_get_file_descr_test();
	ss_fcp_gen_file_descr_test();
	ss_fcp_gen_test();
	return 0;
}
