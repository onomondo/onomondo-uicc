/*
 * Copyright (c) 2024 Onomondo ApS. All rights reserved.
 * 
 * SPDX-License-Identifier: GPL-3.0-only 
 */

#pragma once

#define SMS_MAX_SIZE 140
#define SMS_HDR_MAX_SIZE 24

enum ss_sms_tp_mti {
	SMS_MTI_DELIVER		= 0x00, /* sc to ms */
	SMS_MTI_DELIVER_REPORT	= 0x10, /* ms to sc */
	SMS_MTI_STATUS_REPORT	= 0x02, /* sc to ms */
	SMS_MTI_COMMAND		= 0x12, /* ms to sc */
	SMS_MTI_SUBMIT		= 0x11, /* ms to sc */
	SMS_MTI_SUBMIT_REPORT	= 0x01, /* sc to ms */
	SMS_MTI_INVALID		= 0xFF,
};

enum ss_sms_tp_vpf {
	SMS_VPF_NONE		= 0x00,
	SMS_VPF_RELATIVE	= 0x02,
	SMS_VPF_ENHANCED	= 0x01,
	SMS_VPF_ABSOLUTE	= 0x03,
};

enum ss_sms_tp_ct {
	SMS_CT_ENQUIRY		= 0x00,
	SMS_CT_CANCEL_STATUS	= 0x01,
	SMS_CT_DELETE_MSG	= 0x02,
	SMS_CT_ENABLE_STATUS	= 0x03,
};

enum ss_sms_udh_ie {
	TS_23_040_IEI_CONCAT_SMS		= 0x00,
	TS_23_040_IEI_SPECIAL_SMS_IND		= 0x01,
	TS_23_040_IEI_APP_PORT_ADDR_8		= 0x04,
	TS_23_040_IEI_APP_PORT_ADDR_16		= 0x05,
	TS_23_040_IEI_SMSC_CTRL_PARAM		= 0x06,
	TS_23_040_IEI_UDH_SRC_IND		= 0x07,
	TS_23_040_IEI_CONCAT_SMS_REF		= 0x08,
	TS_23_040_IEI_WL_CTRL_MSG_PROT		= 0x09,
	TS_23_040_IEI_TXT_FORMATTING		= 0x0A,
	TS_23_040_IEI_PREDEF_SOUND		= 0x0B,
	TS_23_040_IEI_USRDEF_SOUND		= 0x0C,
	TS_23_040_IEI_PREDEF_ANIM		= 0x0D,
	TS_23_040_IEI_LARGE_ANIM		= 0x0E,
	TS_23_040_IEI_SMALL_ANIM		= 0x0F,
	TS_23_040_IEI_LARGE_PICT		= 0x10,
	TS_23_040_IEI_SMALL_PICT		= 0x11,
	TS_23_040_IEI_VAR_PICT			= 0x12,
	TS_23_040_IEI_USER_PROMPT_IND		= 0x13,
	TS_23_040_IEI_EXT_OBJECT		= 0x14,
	TS_23_040_IEI_REUSED_EXT_OBJECT		= 0x15,
	TS_23_040_IEI_COMPRESSION_CTRL		= 0x16,
	TS_23_040_IEI_OBJ_DIST_IND		= 0x17,
	TS_23_040_IEI_STD_WVG_OBJ		= 0x18,
	TS_23_040_IEI_CHAR_SIZE_WVG_OBJ		= 0x19,
	TS_23_040_IEI_EXT_OBJ_DATA_REQ_CMD	= 0x1A,
	TS_23_040_IEI_RFC_5322_EMAIL_HDR	= 0x20,
	TS_23_040_IEI_HYPERLINK_FMT_ELEM	= 0x21,
	TS_23_040_IEI_REPLY_ADDR_ELEM		= 0x22,
	TS_23_040_IEI_ENH_VOICE_MAIL_INF	= 0x23,
	TS_23_040_IEI_NAT_LANG_SING_SHIFT	= 0x24,
	TS_23_040_IEI_NAT_LANG_LOCK_SHIFT	= 0x25,
};

struct ss_sms_addr {
	bool extension;
	uint8_t type_of_number;
	uint8_t numbering_plan;
	char digits[21];
};

struct ss_sms_deliver {
	bool tp_mms;
	bool tp_rp;
	bool tp_udhi;
	bool tp_sri;
	struct ss_sms_addr tp_oa;
	uint8_t tp_pid;
	uint8_t tp_dcs;
	uint8_t tp_scts[7];
	uint8_t tp_udl;
};

struct ss_sms_deliver_report {
	bool tp_udhi;
	uint8_t tp_fcs;
	uint8_t tp_pid;
	bool tp_pid_present;
	uint8_t tp_dcs;
	bool tp_dcs_present;
	uint8_t tp_udl;
	bool tp_udl_present;
};

struct ss_sms_submit {
	bool tp_rd;
	uint8_t tp_vpf;
	bool tp_rp;
	bool tp_udhi;
	bool tp_srr;
	uint8_t tp_mr;
	struct ss_sms_addr tp_da;
	uint8_t tp_pid;
	uint8_t tp_dcs;
	uint8_t tp_vp[7];
	uint8_t tp_udl;
};

struct ss_sms_submit_report {
	uint8_t tp_fcs;
};

struct ss_sms_status_report {
	uint8_t tp_mr;
	bool tp_mms;
	struct ss_sms_addr tp_ra;
	uint8_t tp_scts[7];
	uint8_t tp_dt[7];
	uint8_t tp_st;
};

struct ss_sms_command {
	bool tp_rd;
	bool tp_udhi;
	bool tp_srr;
	uint8_t tp_mr;
	uint8_t tp_pid;
	uint8_t tp_ct;
	uint8_t tp_mn;
	struct ss_sms_addr tp_da;
	uint8_t tp_cdl;
};

struct ss_sm_hdr {
	enum ss_sms_tp_mti tp_mti;
	union {
		struct ss_sms_deliver sms_deliver;
		struct ss_sms_deliver_report sms_deliver_report;
		struct ss_sms_status_report sms_status_report;
		struct ss_sms_submit_report sms_submit_report;
		struct ss_sms_submit sms_submit;
		struct ss_sms_command sms_command;
	} u;
};

int ss_sms_hdr_decode(struct ss_sm_hdr *sm_hdr, const uint8_t *sms_tpdu,
		      size_t sms_tpdu_len);
int ss_sms_hdr_encode(uint8_t *sms_tpdu, size_t sms_tpdu_len,
		      const struct ss_sm_hdr *sm_hdr);
