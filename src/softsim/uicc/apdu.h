/*
 * Copyright (c) 2024 Onomondo ApS. All rights reserved.
 * 
 * SPDX-License-Identifier: GPL-3.0-only 
 */

#pragma once

#include <stdint.h>
#include <stdlib.h>
struct ss_context;

/*! APDU header */
struct ss_apdu_hdr {
	uint8_t cla;
	uint8_t ins;
	uint8_t p1;
	uint8_t p2;
	uint8_t p3;
} __attribute__((packed));

/*! Internal representation of APDU */
struct ss_apdu {
	/*! logical channel through which APDU is transceived */
	struct ss_lchan *lchan;

	/*! backpointer to softsim context */
	struct ss_context *ctx;

	/* header + command and response payload */
	struct ss_apdu_hdr hdr;
	uint8_t lc;		/*< length (command) */
	uint8_t le;		/*< length (expected response) */
	uint8_t cmd[256];	/*< command body */
	uint8_t rsp[256];	/*< response body */
	size_t rsp_len;		/*< actual length of of rsp */
	uint16_t sw;		/*< status word */
};

struct ss_apdu *ss_apdu_new(struct ss_context *ctx);
void ss_apdu_toss(struct ss_apdu *apdu);
