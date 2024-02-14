/*
 * Copyright (c) 2024 Onomondo ApS. All rights reserved.
 * 
 * SPDX-License-Identifier: GPL-3.0-only 
 */

#pragma once

#include <stdint.h>
#include <stdbool.h>
#include <onomondo/softsim/log.h>

struct ss_buf;
struct ber_tlv_desc;
struct ss_file;

enum ss_fcp_file_type {
	SS_FCP_WORKING_EF = 0,
	SS_FCP_INTERNAL_EF = 1,
	SS_FCP_DF_OR_ADF = 7,
};

enum ss_fcp_file_struct {
	SS_FCP_UNKNOWN = 0,
	SS_FCP_TRANSPARENT = 1,
	SS_FCP_LINEAR_FIXED = 2,
	SS_FCP_CYCLIC = 6,
	SS_FCP_BTLV = 57,
};

struct ss_fcp_file_descr {
	bool shareable;
	enum ss_fcp_file_type type;
	enum ss_fcp_file_struct structure;

	/* Only valid for linear fixed and cyclic files */
	uint16_t record_len;
	uint8_t number_of_records;
};

/* See also 11.1.1.3 ETSI TS 102 221 */
#define TS_102_221_IEI_FCP_TMPL 0x62
enum ss_fcp_iei {
	TS_102_221_IEI_FCP_FILE_SIZE = 0x80,
	TS_102_221_IEI_FCP_TOTAL_FILE_SIZE = 0x81,
	TS_102_221_IEI_FCP_FILE_DESCR = 0x82,
	TS_102_221_IEI_FCP_FILE_ID = 0x83,
	TS_102_221_IEI_FCP_DF_NAME = 0x84,
	TS_102_221_IEI_FCP_SHORT_FILE_ID = 0x88,
	TS_102_221_IEI_FCP_LIFE_CYCLE_ST = 0x8A,
	TS_102_221_IEI_FCP_SEC_ATTR_8B = 0x8B,
	TS_102_221_IEI_FCP_SEC_ATTR_8C = 0x8C,
	TS_102_221_IEI_FCP_SEC_ATTR_AB = 0xAB,
	TS_102_221_IEI_FCP_PIN_STAT_TMPL = 0xC6,
};

const struct ber_tlv_desc *ss_fcp_get_descr(void);
struct ss_list *ss_fcp_decode(const struct ss_buf *fcp);
int ss_fcp_dec_file_descr(struct ss_fcp_file_descr *fd,
			  const struct ss_buf *fd_encoded);
struct ss_buf *ss_fcp_gen_file_descr(const struct ss_fcp_file_descr *fd);
struct ss_buf *ss_fcp_gen(const struct ss_fcp_file_descr *fd, uint32_t fid,
			  size_t file_size);
struct ss_buf *ss_fcp_get_df_name(const struct ss_list *fcp_decoded_envelope);
void ss_fcp_dump_file_descr(const struct ss_fcp_file_descr *fd, uint8_t indent,
			    enum log_subsys log_subsys,
			    enum log_level log_level);
int ss_fcp_reencode(struct ss_file *file);
