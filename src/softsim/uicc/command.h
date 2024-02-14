/*
 * Copyright (c) 2024 Onomondo ApS. All rights reserved.
 * 
 * SPDX-License-Identifier: GPL-3.0-only 
 */

#pragma once

#include <stdint.h>
#include <onomondo/softsim/list.h>
struct ss_context;
struct ss_apdu;

/*! Classification of command body according to ISO/IEC 7816-3 Secton 12.1 */
enum ss_command_case {
  SS_COMMAND_CASE_UNDEF = 0, /* TBD remove this when all is properly initialized  */
  SS_COMMAND_CASE_1, /**< just header */
  SS_COMMAND_CASE_2, /**< header, Le */
  SS_COMMAND_CASE_3, /**< header, Lc, data */
  SS_COMMAND_CASE_4, /**< header, Lc, data, Le */
	/* It may turn out that some commands occur in multiple cases; these would
	 * need a special case, and would require an "indeterminate" variant, in
	 * which the handler will be required to indicate the consumed length. */
};

/*! command handler for APDU commands */
struct ss_command {
	/*! Human readable name that describes the command. */
	const char *name;
	/*! CLA and MASK against which to compare CLA from APDU header */
	uint8_t cla;
	uint8_t cla_mask;
	/*! INS against which to compare the INS from APDU header */
	uint8_t ins;
	/*! call-back function to be called when a matching command was received.
	 *  Return value
	 *  	0: OK (SW 9000 is sent by command dispatcher)
	 *  	> 0: use return value as SW
	 *  	< 0: some unexpected internal error, generic error SW is used */
	int (*handler)(struct ss_apdu *apdu);
	/*! Command case: description of which data follows the APDU header
	 *
	 * Having this in metadata (and not just impicitly using the knowledge in the
	 * handler implementation) allows processing commands from multiple buffers,
	 * as they are presented in compact remote commands.
	 */
	enum ss_command_case case_;
};

const struct ss_command *ss_command_match(struct ss_apdu *apdu);
