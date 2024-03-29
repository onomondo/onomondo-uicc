/*
 * Copyright (c) 2024 Onomondo ApS. All rights reserved.
 * 
 * SPDX-License-Identifier: GPL-3.0-only 
 */

#pragma once

enum uicc_ins_byte {

	/* ETSI TS 102 221 Section 10.1.2 Table 10.5 */
	TS_102_221_INS_SELECT_FILE		= 0xa4,
	TS_102_221_INS_STATUS			= 0xf2,
	TS_102_221_INS_READ_BINARY		= 0xb0,
	TS_102_221_INS_UPDATE_BINARY		= 0xd6,
	TS_102_221_INS_READ_RECORD		= 0xb2,
	TS_102_221_INS_UPDATE_RECORD		= 0xdc,
	TS_102_221_INS_SEARCH_RECORD		= 0xa2,
	TS_102_221_INS_INCREASE			= 0x32,
	TS_102_221_INS_RETRIEVE_DATA		= 0xcb,
	TS_102_221_INS_SET_DATA			= 0xdb,
	TS_102_221_INS_VERIFY_PIN		= 0x20,
	TS_102_221_INS_CHANGE_PIN		= 0x24,
	TS_102_221_INS_DISABLE_PIN		= 0x26,
	TS_102_221_INS_ENABLE_PIN		= 0x28,
	TS_102_221_INS_UNBLOCK_PIN		= 0x2c,
	TS_102_221_INS_DEACTIVATE_FILE		= 0x04,
	TS_102_221_INS_ACTIVATE_FILE		= 0x44,
	TS_102_221_INS_AUTHENTICATE		= 0x88,
	TS_102_221_INS_GET_CHALLENGE		= 0x84,
	TS_102_221_INS_TERMINAL_CAPABILITY	= 0xaa,
	TS_102_221_INS_TERMINAL_PROFILE		= 0x10,
	TS_102_221_INS_ENVELOPE			= 0xc2,
	TS_102_221_INS_FETCH			= 0x12,
	TS_102_221_INS_TERMINAL_RESPONSE	= 0x14,
	TS_102_221_INS_MANAGE_CHANNEL		= 0x70,
	TS_102_221_INS_MANAGE_SECURE_CHANNEL	= 0x73,
	TS_102_221_INS_TRANSACT_DATA		= 0x75,
	TS_102_221_INS_SUSPEND_UICC		= 0x76,
	TS_102_221_INS_GET_IDENTITY		= 0x78,
	TS_102_221_INS_GET_RESPONSE		= 0xc0,
	TS_102_221_INS_AUTHENTICATE_EVEN	= 0x88,
	TS_102_221_INS_AUTHENTICATE_ODD		= 0x89,

	/* ETSI TS 102 222 Section 6.1 Table 1 */
	TS_102_222_INS_CREATE_FILE		= 0xe0,
	TS_102_222_INS_DELETE_FILE		= 0xe4,
	TS_102_222_INS_TERMINATE_DF		= 0xe6,
	TS_102_222_INS_TERMINATE_EF		= 0xe8,
	TS_102_222_INS_TERMINATE_CARD_USAGE	= 0xfe,
	TS_102_222_INS_RESIZE_FILE		= 0xd4
};
