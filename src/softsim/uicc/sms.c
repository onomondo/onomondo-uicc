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
#include <stdint.h>
#include <string.h>
#include <onomondo/softsim/log.h>
#include <onomondo/softsim/list.h>
#include <onomondo/softsim/utils.h>
#include <onomondo/softsim/mem.h>
#include "sms.h"

/* see also: 3GPP TS 23.040, section 9.2.3.1 */
static enum ss_sms_tp_mti decode_mti(const uint8_t *sms_tpdu, size_t sms_tpdu_len, bool ms_to_sc)
{
	uint8_t mti;

	if (sms_tpdu_len < 1)
		return SMS_MTI_INVALID;

	mti = sms_tpdu[0] & 0x03;
	if (mti > 2)
		return SMS_MTI_INVALID;
	if (ms_to_sc)
		mti |= 0x10;

	return mti;
}

static int decode_addr(struct ss_sms_addr *addr_dec, const uint8_t *addr, size_t addr_len)
{
	uint8_t n_digits;
	uint8_t n_bytes;
	uint8_t i;
	char digit;
	char *digits_buf = addr_dec->digits;

	memset(addr_dec, 0, sizeof(*addr_dec));

	if (addr_len < 2)
		return -EINVAL;

	/* Decode number of digits */
	n_digits = addr[0];
	n_bytes = n_digits / 2;
	if (n_digits % 2)
		n_bytes++;
	if (addr_len < n_bytes + 2)
		return -EINVAL;
	addr++;

	/* Decode header */
	addr_dec->extension = (*addr && 0x80);
	addr_dec->type_of_number = *addr >> 4 & 0x07;
	addr_dec->numbering_plan = *addr & 0x0F;
	addr++;

	/* Decode digits to printable string */
	for (i = 0; i < n_bytes; i++) {
		/* odd digit */
		digit = *addr & 0x0f;
		if (digit > 9)
			return -EINVAL + 1;
		*digits_buf = digit | 0x30;
		digits_buf++;

		/* even digit */
		digit = (*addr >> 4) & 0x0F;
		if (digit == 0x0F && n_bytes == i + 1)
			break;
		else if (digit > 9)
			return -EINVAL + 2;
		*digits_buf = digit | 0x30;
		digits_buf++;

		addr++;
	}

	/* Return number of decoded bytes */
	return n_bytes + 2;
}

static int encode_addr(uint8_t *addr, size_t addr_len, const struct ss_sms_addr *addr_dec)
{
	uint8_t n_digits;
	uint8_t n_bytes;
	size_t bytes_used = 0;
	uint8_t d = 0;
	uint8_t i;

	if (addr_len < 2)
		return -ENOMEM;

	/* Encode number of digits */
	n_digits = (uint8_t)ss_strnlen(addr_dec->digits, sizeof(addr_dec->digits));
	addr[bytes_used] = n_digits;
	bytes_used++;

	/* Encode header */
	addr[bytes_used] = 0x00;
	if (addr_dec->extension)
		addr[bytes_used] |= 0x80;
	addr[bytes_used] |= ((addr_dec->type_of_number & 0x07) << 4);
	addr[bytes_used] |= addr_dec->numbering_plan & 0x0F;
	bytes_used++;

	if (addr_len < bytes_used + n_digits + 1 / 2)
		return -ENOMEM;

	/* Encode digits */
	n_bytes = n_digits / 2;
	if (n_digits % 2)
		n_bytes++;
	for (i = 0; i < n_bytes; i++) {
		addr[bytes_used + i] = addr_dec->digits[d] & 0x0F;
		d++;
		if (d < n_digits)
			addr[bytes_used + i] |= ((addr_dec->digits[d] & 0x0F) << 4);
		else
			addr[bytes_used + i] |= 0xF0;
		d++;
	}
	bytes_used += n_bytes;

	return bytes_used;
}

/* see also: 3GPP TS 23.040, section 9.2.2.1 */
static int rx_sms_deliver(struct ss_sms_deliver *sm, const uint8_t *sms_tpdu, size_t sms_tpdu_len)
{
	int addr_len;
	size_t bytes_used = 0;

	/* TP-MMS */
	sm->tp_mms = ((sms_tpdu[0] >> 2) & 1) == 1;

	/* TP-RP */
	sm->tp_rp = ((sms_tpdu[0] >> 7) & 1) == 1;

	/* TP-UDHI */
	sm->tp_udhi = ((sms_tpdu[0] >> 6) & 1) == 1;

	/* TP-SRI */
	sm->tp_sri = ((sms_tpdu[0] >> 5) & 1) == 1;
	bytes_used++;

	/* TP-OA */
	addr_len = decode_addr(&sm->tp_oa, sms_tpdu + bytes_used, sms_tpdu_len - bytes_used);
	if (addr_len < 0) {
		SS_LOGP(SSMS, LERROR, "invalid address (TP-OA) -- reception of SMS-DELIVER failed!\n");
		return -EINVAL;
	}
	bytes_used += addr_len;

	/* TP-PID */
	if (sms_tpdu_len < bytes_used + 1) {
		SS_LOGP(SSMS, LERROR, "unexpected end of message (TP-PID) -- reception of SMS-DELIVER failed!\n");
		return -EINVAL;
	}
	sm->tp_pid = sms_tpdu[bytes_used];
	bytes_used++;

	/* TP-DCS */
	if (sms_tpdu_len < bytes_used + 1) {
		SS_LOGP(SSMS, LERROR, "unexpected end of message (TP-DCS) -- reception of SMS-DELIVER failed!\n");
		return -EINVAL;
	}
	sm->tp_dcs = sms_tpdu[bytes_used];
	bytes_used++;

	/* TP-SCTS */
	if (sms_tpdu_len < bytes_used + 7) {
		SS_LOGP(SSMS, LERROR, "unexpected end of message (TP-SCTS) -- reception of SMS-DELIVER failed!\n");
		return -EINVAL;
	}
	memcpy(sm->tp_scts, sms_tpdu + bytes_used, sizeof(sm->tp_scts));
	bytes_used += 7;

	/* TP-UDL */
	if (sms_tpdu_len < bytes_used + 1) {
		SS_LOGP(SSMS, LERROR, "unexpected end of message (TP-UDL) -- reception of SMS-DELIVER failed!\n");
		return -EINVAL;
	}
	sm->tp_udl = sms_tpdu[bytes_used];
	bytes_used++;

	return bytes_used;
}

/* see also: 3GPP TS 23.040, section 9.2.2.3 */
static int rx_sms_status_report(struct ss_sms_status_report *sm, const uint8_t *sms_tpdu, size_t sms_tpdu_len)
{
	int addr_len;
	size_t bytes_used = 0;

	/* TP-MMS */
	sm->tp_mms = ((sms_tpdu[0] >> 2) & 1) == 1;
	bytes_used++;

	/* TP-MR */
	if (sms_tpdu_len < bytes_used + 1) {
		SS_LOGP(SSMS, LERROR, "unexpected end of message (TP-MR) -- reception of SMS-STATUS-REPORT failed!\n");
		return -EINVAL;
	}
	sm->tp_mr = sms_tpdu[bytes_used];
	bytes_used++;

	/* TP-RA */
	addr_len = decode_addr(&sm->tp_ra, sms_tpdu + bytes_used, sms_tpdu_len - bytes_used);
	if (addr_len < 0) {
		SS_LOGP(SSMS, LERROR, "invalid address (TP-RA) -- reception of SMS-STATUS-REPORT failed!\n");
		return -EINVAL;
	}
	bytes_used += addr_len;

	/* TP-SCTS */
	if (sms_tpdu_len < bytes_used + 7) {
		SS_LOGP(SSMS, LERROR,
			"unexpected end of message (TP-SCTS) -- reception of SMS-STATUS-REPORT failed!\n");
		return -EINVAL;
	}
	memcpy(sm->tp_scts, sms_tpdu + bytes_used, sizeof(sm->tp_scts));
	bytes_used += 7;

	/* TP-DT */
	if (sms_tpdu_len < bytes_used + 7) {
		SS_LOGP(SSMS, LERROR, "unexpected end of message (TP-DT) -- reception of SMS-STATUS-REPORT failed!\n");
		return -EINVAL;
	}
	memcpy(sm->tp_dt, sms_tpdu + bytes_used, sizeof(sm->tp_scts));
	bytes_used += 7;

	/* TP-ST */
	if (sms_tpdu_len < bytes_used + 1) {
		SS_LOGP(SSMS, LERROR, "unexpected end of message (TP-ST) -- reception of SMS-STATUS-REPORT failed!\n");
		return -EINVAL;
	}
	sm->tp_st = sms_tpdu[bytes_used];
	bytes_used++;

	return bytes_used;
}

/* see also: 3GPP TS 23.040, section 9.2.2.2 */
static int rx_sms_submit_report(struct ss_sms_submit_report *sm, const uint8_t *sms_tpdu, size_t sms_tpdu_len)
{
	size_t bytes_used = 0;

	/* First byte only contains the TP-MTI, which we have already parsed */
	bytes_used++;

	/* TP-ST */
	if (sms_tpdu_len < bytes_used + 1) {
		SS_LOGP(SSMS, LERROR, "unexpected end of message (TP-ST) -- reception of SMS-SUBMIT-REPORT failed!\n");
		return -EINVAL;
	}
	sm->tp_fcs = sms_tpdu[bytes_used];
	bytes_used++;

	return bytes_used;
}

/*! Decode SMS TPDU header.
 *  \param[out] sm_hdr pointer to user struct that holds the decoding results.
 *  \param[in] sms_tpdu buffer with binary SMS message header to decode.
 *  \param[in] sms_tpdu_len maximum length of sms_tpdu buffer.
 *  \returns 0 on success, -EINVAL on error. */
int ss_sms_hdr_decode(struct ss_sm_hdr *sm_hdr, const uint8_t *sms_tpdu, size_t sms_tpdu_len)
{
	memset(sm_hdr, 0, sizeof(*sm_hdr));

	sm_hdr->tp_mti = decode_mti(sms_tpdu, sms_tpdu_len, false);

	switch (sm_hdr->tp_mti) {
	case SMS_MTI_DELIVER:
		return rx_sms_deliver(&sm_hdr->u.sms_deliver, sms_tpdu, sms_tpdu_len);
	case SMS_MTI_STATUS_REPORT:
		return rx_sms_status_report(&sm_hdr->u.sms_status_report, sms_tpdu, sms_tpdu_len);
	case SMS_MTI_SUBMIT_REPORT:
		return rx_sms_submit_report(&sm_hdr->u.sms_submit_report, sms_tpdu, sms_tpdu_len);
	default:
		SS_LOGP(SSMS, LERROR, "unexpected or invalid message type (mti=%u) received\n", sm_hdr->tp_mti & 0x03);
		return -EINVAL;
	}

	return -EINVAL;
}

/* see also: 3GPP TS 23.040, section 9.2.2.1a */
static int tx_sms_deliver_report(uint8_t *sms_tpdu, size_t sms_tpdu_len, const struct ss_sms_deliver_report *sm)
{
	size_t bytes_used = 0;

	/* TP-UDHI */
	if (sm->tp_udhi)
		sms_tpdu[bytes_used] |= (1 << 6);
	bytes_used++;

	/* TP-FCS */
	if (sms_tpdu_len < bytes_used + 1)
		return -ENOMEM;
	sms_tpdu[bytes_used] = sm->tp_fcs;
	bytes_used++;

	/* TP-PI */
	if (sms_tpdu_len < bytes_used + 1)
		return -ENOMEM;
	if (sm->tp_pid_present)
		sms_tpdu[bytes_used] |= 1;
	if (sm->tp_dcs_present)
		sms_tpdu[bytes_used] |= (1 << 1);
	if (sm->tp_udl_present)
		sms_tpdu[bytes_used] |= (1 << 2);
	bytes_used++;

	/* TP-PID */
	if (sm->tp_pid_present) {
		if (sms_tpdu_len < bytes_used + 1)
			return -ENOMEM;
		sms_tpdu[bytes_used] = sm->tp_pid;
		bytes_used++;
	}

	/* TP-DCS */
	if (sm->tp_dcs_present) {
		if (sms_tpdu_len < bytes_used + 1)
			return -ENOMEM;
		sms_tpdu[bytes_used] = sm->tp_dcs;
		bytes_used++;
	}

	/* TP-UDL */
	if (sm->tp_udl_present) {
		if (sms_tpdu_len < bytes_used + 1)
			return -ENOMEM;
		sms_tpdu[bytes_used] = sm->tp_udl;
		bytes_used++;
	}

	return bytes_used;
}

/* see also: 3GPP TS 23.040, section 9.2.2.1a */
static int tx_sms_command(uint8_t *sms_tpdu, size_t sms_tpdu_len, const struct ss_sms_command *sm)
{
	size_t bytes_used = 0;
	int rc;

	/* TP-UDHI and TP-SRR */
	if (sm->tp_udhi)
		sms_tpdu[bytes_used] |= (1 << 6);
	if (sm->tp_srr)
		sms_tpdu[bytes_used] |= (1 << 5);
	bytes_used++;

	/* TP-MR */
	if (sms_tpdu_len < bytes_used + 1)
		return -ENOMEM;
	sms_tpdu[bytes_used] = sm->tp_mr;
	bytes_used++;

	/* TP-PID */
	if (sms_tpdu_len < bytes_used + 1)
		return -ENOMEM;
	sms_tpdu[bytes_used] = sm->tp_pid;
	bytes_used++;

	/* TP-CT */
	if (sms_tpdu_len < bytes_used + 1)
		return -ENOMEM;
	sms_tpdu[bytes_used] = sm->tp_ct;
	bytes_used++;

	/* TP-MN */
	if (sms_tpdu_len < bytes_used + 1)
		return -ENOMEM;
	sms_tpdu[bytes_used] = sm->tp_mn;
	bytes_used++;

	/* TP-DA */
	rc = encode_addr(&sms_tpdu[bytes_used], sms_tpdu_len - bytes_used, &sm->tp_da);
	if (rc < 0)
		return -EINVAL;
	bytes_used += rc;

	/* TP-CDL */
	if (sms_tpdu_len < bytes_used + 1)
		return -ENOMEM;
	sms_tpdu[bytes_used] = sm->tp_cdl;
	bytes_used++;

	return bytes_used;
}

/* see also: 3GPP TS 23.040, section 9.2.2.2 */
static int tx_sms_submit(uint8_t *sms_tpdu, size_t sms_tpdu_len, const struct ss_sms_submit *sm)
{
	size_t bytes_used = 0;
	int rc;

	/* TP-RD, TP-VPF, TP-RP, TP-UDHI and TP-SRR */
	if (sm->tp_rd)
		sms_tpdu[bytes_used] |= (1 << 2);
	sms_tpdu[bytes_used] |= ((sm->tp_vpf & 0x03) << 3);
	if (sm->tp_rp)
		sms_tpdu[bytes_used] |= (1 << 7);
	if (sm->tp_udhi)
		sms_tpdu[bytes_used] |= (1 << 6);
	if (sm->tp_srr)
		sms_tpdu[bytes_used] |= (1 << 5);
	bytes_used++;

	/* TP-MR */
	if (sms_tpdu_len < bytes_used + 1)
		return -ENOMEM;
	sms_tpdu[bytes_used] = sm->tp_mr;
	bytes_used++;

	/* TP-DA */
	rc = encode_addr(&sms_tpdu[bytes_used], sms_tpdu_len - bytes_used, &sm->tp_da);
	if (rc < 0)
		return -EINVAL;
	bytes_used += rc;

	/* TP-PID */
	if (sms_tpdu_len < bytes_used + 1)
		return -ENOMEM;
	sms_tpdu[bytes_used] = sm->tp_pid;
	bytes_used++;

	/* TP-DCS */
	if (sms_tpdu_len < bytes_used + 1)
		return -ENOMEM;
	sms_tpdu[bytes_used] = sm->tp_dcs;
	bytes_used++;

	/* TP-VP */
	if (sm->tp_vpf != SMS_VPF_NONE) {
		if (sms_tpdu_len - bytes_used < sizeof(sm->tp_vp))
			return -ENOMEM;
		memcpy(&sms_tpdu[bytes_used], sm->tp_vp, sizeof(sm->tp_vp));
		bytes_used += sizeof(sm->tp_vp);
	}

	/* TP-UDL */
	if (sms_tpdu_len < bytes_used + 1)
		return -ENOMEM;
	sms_tpdu[bytes_used] = sm->tp_udl;
	bytes_used++;

	return bytes_used;
}

/*! Encode SMS TPDU header.
 *  \param[out] sms_tpdu buffer to store resulting binary SMS message header.
 *  \param[in] sms_tpdu_len maximum length of sms_tpdu buffer.
 *  \param[in] sm_hdr pointer to user struct that holds the header data to encode.
 *  \returns 0 on success, -EINVAL on error. */
int ss_sms_hdr_encode(uint8_t *sms_tpdu, size_t sms_tpdu_len, const struct ss_sm_hdr *sm_hdr)
{
	memset(sms_tpdu, 0, sms_tpdu_len);

	if (sms_tpdu_len < 1)
		return -ENOMEM;

	sms_tpdu[0] = sm_hdr->tp_mti & 0x03;

	switch (sm_hdr->tp_mti) {
	case SMS_MTI_DELIVER_REPORT:
		return tx_sms_deliver_report(sms_tpdu, sms_tpdu_len, &sm_hdr->u.sms_deliver_report);
	case SMS_MTI_COMMAND:
		return tx_sms_command(sms_tpdu, sms_tpdu_len, &sm_hdr->u.sms_command);
	case SMS_MTI_SUBMIT:
		return tx_sms_submit(sms_tpdu, sms_tpdu_len, &sm_hdr->u.sms_submit);
	default:
		SS_LOGP(SSMS, LERROR, "cannot encode message with unexpected message type (mti=%u)\n",
			sm_hdr->tp_mti & 0x03);
		return -EINVAL;
	}

	return 0;
}
