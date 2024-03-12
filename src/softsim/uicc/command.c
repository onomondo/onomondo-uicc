/*
 * Copyright (c) 2024 Onomondo ApS. All rights reserved.
 *
 * SPDX-License-Identifier: GPL-3.0-only
 *
 * Author: Philipp Maier
 */

#include <assert.h>
#include <string.h>
#include <stdbool.h>
#include <onomondo/softsim/log.h>
#include <onomondo/softsim/list.h>
#include <onomondo/softsim/utils.h>
#include "command.h"
#include "context.h"
#include "uicc_ins.h"
#include "uicc_pin.h"
#include "uicc_file_ops.h"
#include "uicc_admin.h"
#include "uicc_auth.h"
#include "uicc_cat.h"
#include "uicc_suspend.h"
#include "apdu.h"
#include "sw.h"

const struct ss_command commands[] = {

	/* pin handling */
	{
		.name = "VERIFY PIN",
		.cla = 0x00,
		.cla_mask = 0x70,
		.ins = TS_102_221_INS_VERIFY_PIN,
		.handler = ss_uicc_pin_cmd_verify_pin,
		.case_ = SS_COMMAND_CASE_3,
	},
	{
		.name = "CHANGE PIN",
		.cla = 0x00,
		.cla_mask = 0x70,
		.ins = TS_102_221_INS_CHANGE_PIN,
		.handler = ss_uicc_pin_cmd_change_pin,
		.case_ = SS_COMMAND_CASE_3,
	},
	{
		.name = "DISABLE PIN",
		.cla = 0x00,
		.cla_mask = 0x70,
		.ins = TS_102_221_INS_DISABLE_PIN,
		.handler = ss_uicc_pin_cmd_disable_pin,
		.case_ = SS_COMMAND_CASE_3,
	},
	{
		.name = "ENABLE PIN",
		.cla = 0x00,
		.cla_mask = 0x70,
		.ins = TS_102_221_INS_ENABLE_PIN,
		.handler = ss_uicc_pin_cmd_enable_pin,
		.case_ = SS_COMMAND_CASE_3,
	},
	{
		.name = "UNBLOCK PIN",
		.cla = 0x00,
		.cla_mask = 0x70,
		.ins = TS_102_221_INS_UNBLOCK_PIN,
		.handler = ss_uicc_pin_cmd_unblock_pin,
		.case_ = SS_COMMAND_CASE_3,
	},

	/* file operations */
	{
		.name = "STATUS",
		.cla = 0x00,
		.cla_mask = 0x70,
		.ins = TS_102_221_INS_STATUS,
		.handler = ss_uicc_file_ops_cmd_status,
		.case_ = SS_COMMAND_CASE_2,
	},
	{
		.name = "READ BINARY",
		.cla = 0x00,
		.cla_mask = 0x70,
		.ins = TS_102_221_INS_READ_BINARY,
		.handler = ss_uicc_file_ops_cmd_read_binary,
		.case_ = SS_COMMAND_CASE_2,
	},
	{
		.name = "UPDATE BINARY",
		.cla = 0x00,
		.cla_mask = 0x70,
		.ins = TS_102_221_INS_UPDATE_BINARY,
		.handler = ss_uicc_file_ops_cmd_update_binary,
		.case_ = SS_COMMAND_CASE_3,
	},
	{
		.name = "READ RECORD",
		.cla = 0x00,
		.cla_mask = 0x70,
		.ins = TS_102_221_INS_READ_RECORD,
		.handler = ss_uicc_file_ops_cmd_read_record,
		.case_ = SS_COMMAND_CASE_2,
	},
	{
		.name = "UPDATE RECORD",
		.cla = 0x00,
		.cla_mask = 0x70,
		.ins = TS_102_221_INS_UPDATE_RECORD,
		.handler = ss_uicc_file_ops_cmd_update_record,
		.case_ = SS_COMMAND_CASE_3,
	},
	{
		.name = "SEARCH RECORD",
		.cla = 0x00,
		.cla_mask = 0x70,
		.ins = TS_102_221_INS_SEARCH_RECORD,
		.handler = ss_uicc_file_ops_cmd_search_record,
		.case_ = SS_COMMAND_CASE_4,
	},
	{
		.name = "SELECT FILE",
		.cla = 0x00,
		.cla_mask = 0x70,
		.ins = TS_102_221_INS_SELECT_FILE,
		.handler = ss_uicc_file_ops_cmd_select,
		.case_ = SS_COMMAND_CASE_3, /* It does have response data, but that's not being asked for by an LE */
	},

	/* administrative commands */
	{
		.name = "CREATE FILE",
		.cla = 0x00,
		.cla_mask = 0xB0, /* 0X or 4X */
		.ins = TS_102_222_INS_CREATE_FILE,
		.handler = ss_uicc_admin_cmd_create_file,
		.case_ = SS_COMMAND_CASE_3,
	},
	{
		.name = "DELETE FILE",
		.cla = 0x00,
		.cla_mask = 0xB0, /* 0X or 4X */
		.ins = TS_102_222_INS_DELETE_FILE,
		.handler = ss_uicc_admin_cmd_delete_file,
		.case_ = SS_COMMAND_CASE_3,
	},
	{
		.name = "ACTIVATE",
		.cla = 0x00,
		.cla_mask = 0xB0, /* 0X or 4X */
		.ins = TS_102_221_INS_ACTIVATE_FILE,
		.handler = ss_uicc_admin_cmd_activate_file,
		.case_ = SS_COMMAND_CASE_3,
	},

	/* CAT commands */
	{
		.name = "TERMINAL PROFILE",
		.cla = 0x80,
		.cla_mask = 0xB0, /* 0X or 4X */
		.ins = TS_102_221_INS_TERMINAL_PROFILE,
		.handler = ss_uicc_cat_cmd_term_profile,
		.case_ = SS_COMMAND_CASE_3,
	},
	{
		.name = "ENVELOPE",
		.cla = 0x80,
		.cla_mask = 0xB0, /* 0X or 4X */
		.ins = TS_102_221_INS_ENVELOPE,
		.handler = ss_uicc_cat_cmd_envelope,
		.case_ = SS_COMMAND_CASE_3, /* It does have response data, but that's not being asked for by an LE */
	},
	{
		.name = "FETCH",
		.cla = 0x80,
		.cla_mask = 0xB0, /* 0X or 4X */
		.ins = TS_102_221_INS_FETCH,
		.handler = ss_uicc_cat_cmd_fetch,
		.case_ = SS_COMMAND_CASE_2,
	},
	{
		.name = "TERMINAL RESPONSE",
		.cla = 0x80,
		.cla_mask = 0xB0, /* 0X or 4X */
		.ins = TS_102_221_INS_TERMINAL_RESPONSE,
		.handler = ss_uicc_cat_cmd_term_resp,
		.case_ = SS_COMMAND_CASE_3,
	},

	/* logical channels */
	{
		.name = "MANAGE CHANNEL",
		.cla = 0x00,
		.cla_mask = 0xB0, /* 0X or 4X */
		.ins = TS_102_221_INS_MANAGE_CHANNEL,
		.handler = ss_uicc_lchan_cmd_manage_channel,
		.case_ = SS_COMMAND_CASE_2,
	},

	/* authentication */
	{
		.name = "AUTHENTICATE EVEN",
		.cla = 0x00,
		.cla_mask = 0x70,
		.ins = TS_102_221_INS_AUTHENTICATE_EVEN,
		.handler = ss_uicc_auth_cmd_authenticate_even_fn,
		.case_ = SS_COMMAND_CASE_4,
	},

#ifdef CONFIG_USE_EXPERIMENTAL_SUSPEND_COMMAND
	/* uicc suspend
	 * This implentation is no where near compliant. Use only if you know what you are doing.
	 * OK usecase: modem can't to deep sleep without suspend. RAM is retained during this state, so ctx isn't lost.
	 * */
	{
		.name = "UICC SUSPEND",
		.cla = 0x80,
		.cla_mask = 0xB0, /* 0X or 4X */
		.ins = TS_102_221_INS_SUSPEND_UICC,
		.handler = ss_uicc_suspend_cmd,
		.case_ = SS_COMMAND_CASE_3,
	},
#endif // CONFIG_USE_EXPERIMENTAL_SUSPEND_COMMAND

};

/*! Find the command handler for given APDU CLA+INS.
 *  \param[inout] apdu apdu with incoming command information.
 *  \returns command struct, NULL when command not found. */
const struct ss_command *ss_command_match(struct ss_apdu *apdu)
{
	unsigned int i;
	bool cla_seen = false;

	for (i = 0; i < SS_ARRAY_SIZE(commands); i++) {
		if ((apdu->hdr.cla & commands[i].cla_mask) == commands[i].cla)
			cla_seen = true;

		if ((apdu->hdr.cla & commands[i].cla_mask) == commands[i].cla && apdu->hdr.ins == commands[i].ins) {
			SS_LOGP(SCMD, LINFO, "command found (cla=%02X, cla_mask=%02X, ins=%02X, name=\"%s\")\n",
				commands[i].cla, commands[i].cla_mask, commands[i].ins, commands[i].name);
			return &commands[i];
		}
	}

	SS_LOGP(SCMD, LERROR, "command not found (cla=%02X, ins=%02X)\n", apdu->hdr.cla, apdu->hdr.ins);

	if (!cla_seen)
		apdu->sw = SS_SW_ERR_CHECKING_CLA_INVALID;
	else
		apdu->sw = SS_SW_ERR_CHECKING_INS_INVALID;

	return NULL;
}
