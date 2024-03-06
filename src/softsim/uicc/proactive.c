/*
 * Copyright (c) 2024 Onomondo ApS. All rights reserved.
 *
 * SPDX-License-Identifier: GPL-3.0-only
 *
 * Author: Philipp Maier
 */

#include <errno.h>
#include <onomondo/softsim/log.h>
#include <onomondo/softsim/utils.h>
#include "context.h"
#include "proactive.h"
#include "uicc_refresh.h"
#include "btlv.h"
#include "ctlv.h"

/* Number of poll cycles until a TERMINAL RESPONSE is concidered lost. */
#define MAX_POLL_CYCLES 30

const struct ber_tlv_desc bertlv_cat_descr[] = { {
							 .id = 1,
							 .id_parent = 0,
							 .title = "proprietary",
							 .tag_encoded = TS_101_220_IEI_PROPRITARY,
						 },
						 {
							 .id = 2,
							 .id_parent = 0,
							 .title = "proactive-command",
							 .tag_encoded = TS_101_220_IEI_PROACTIVE_CMD,
						 },
						 {
							 .id = 3,
							 .id_parent = 0,
							 .title = "SMS-PP-download",
							 .tag_encoded = TS_101_220_IEI_SMS_PP_DWNLD,
						 },
						 {
							 .id = 4,
							 .id_parent = 0,
							 .title = "cell-broadcast-download",
							 .tag_encoded = TS_101_220_IEI_CBC_DWNLD,
						 },
						 {
							 .id = 5,
							 .id_parent = 0,
							 .title = "menu-selection",
							 .tag_encoded = TS_101_220_IEI_MENU_SELECTION,
						 },
						 {
							 .id = 6,
							 .id_parent = 0,
							 .title = "call-control",
							 .tag_encoded = TS_101_220_IEI_CALL_CTRL,
						 },
						 {
							 .id = 7,
							 .id_parent = 0,
							 .title = "MO-short-message-control",
							 .tag_encoded = TS_101_220_IEI_MO_SMS_CTRL,
						 },
						 {
							 .id = 8,
							 .id_parent = 0,
							 .title = "event-download",
							 .tag_encoded = TS_101_220_IEI_EVENT_DWNLD,
						 },
						 {
							 .id = 9,
							 .id_parent = 0,
							 .title = "timer-expiration",
							 .tag_encoded = TS_101_220_IEI_TIMER_EXPIR,
						 },
						 {
							 .id = 10,
							 .id_parent = 0,
							 .title = "intra-uicc",
							 .tag_encoded = TS_101_220_IEI_INTRA_UICC,
						 },
						 {
							 .id = 11,
							 .id_parent = 0,
							 .title = "USSD-download",
							 .tag_encoded = TS_101_220_IEI_USSD_DWNLD,
						 },
						 {
							 .id = 12,
							 .id_parent = 0,
							 .title = "MMS-transfer-status",
							 .tag_encoded = TS_101_220_IEI_MMS_TRX_STAT,
						 },
						 {
							 .id = 13,
							 .id_parent = 0,
							 .title = "MMS-notification-download",
							 .tag_encoded = TS_101_220_IEI_MMS_NOTIF_DWNLD,
						 },
						 {
							 .id = 14,
							 .id_parent = 0,
							 .title = "Terminal-application-tag",
							 .tag_encoded = TS_101_220_IEI_TERM_APP,
						 },
						 {
							 .id = 15,
							 .id_parent = 0,
							 .title = "geo-location-reporting-tag",
							 .tag_encoded = TS_101_220_IEI_GEO_LOC,
						 },
						 {
							 .id = 16,
							 .id_parent = 0,
							 .title = "envelope-container",
							 .tag_encoded = TS_101_220_IEI_ENVELOPE_CONTNR,
						 },
						 {
							 .id = 17,
							 .id_parent = 0,
							 .title = "ProSe-report-tag",
							 .tag_encoded = TS_101_220_IEI_PROSE_REPORT,
						 },
						 {
							 .id = 0,
						 } };

/*! Get a btlv description for card application toolkit templates.
 *  \returns description for use with ss_btlv_decode(). */
const struct ber_tlv_desc *ss_proactive_get_cat_descr(void)
{
	return bertlv_cat_descr;
}

const struct ss_proactive_task proactive_tasks[] = {
	{
		.name = "SM QUEUE",
		.handler = ss_uicc_sms_tx_poll,
	},
	{
		.name = "REFRESH",
		.handler = ss_uicc_refresh_poll,
	},
};

/* A defeult callback function that is used in case the caller does not supply
 * a callback function to handle TERMINAL RESPONSE */
static void default_term_response_cb(struct ss_context *ctx, uint8_t *resp_data, uint8_t resp_data_len)
{
	struct ss_list *ctlv_data = NULL;

	if (!resp_data) {
		SS_LOGP(SPROACT, LERROR, "terminal did not respond!\n");
		return;
	}

	SS_LOGP(SPROACT, LDEBUG, "terminal responded: %s\n", ss_hexdump(resp_data, resp_data_len));

	ctlv_data = ss_ctlv_decode(resp_data, resp_data_len);
	if (!ctlv_data) {
		SS_LOGP(SPROACT, LERROR, "Unable to decode response - non valid COMPRESNSION-TLV?\n");
		goto leave;
	}
	ss_ctlv_dump(ctlv_data, 2, SPROACT, LDEBUG);

leave:
	ss_ctlv_free(ctlv_data);
}

/*! Poll proactive tasks and do regular housekeeping.
 *  \param[inout] ctx softsim context. */
void ss_proactive_poll(struct ss_context *ctx)
{
	size_t i;

	/* Go through all proactive tasks and call their handler functions. */
	for (i = 0; i < SS_ARRAY_SIZE(proactive_tasks); i++) {
		SS_LOGP(SPROACT, LDEBUG, "polling proactive task %s\n", proactive_tasks[i].name);
		proactive_tasks[i].handler(ctx);
	}

	/* If for some reason the TERMINAL RESPONSE gets lost or is not sent by
	 * the terminal we will reset te command handling after some time. To
	 * make sure that the caller is informed the callback function will
	 * be called with NULL data. The timeout counting starts immediately
	 * after the data is FETCHed. */
	if (ctx->proactive.term_resp_cb && ctx->proactive.data_len > 0) {
		SS_LOGP(SPROACT, LDEBUG, "waiting for the terminal FETCH %u bytes of data\n", ctx->proactive.data_len);
	} else if (ctx->proactive.term_resp_cb) {
		if (ctx->proactive.term_resp_poll_ctr >= MAX_POLL_CYCLES) {
			SS_LOGP(SPROACT, LDEBUG, "giving up waiting for TERMINAL RESPONSE after %u poll cycles\n",
				ctx->proactive.term_resp_poll_ctr);
			term_resp_cb callback = ctx->proactive.term_resp_cb;
			ss_proactive_reset(ctx);
			callback(ctx, NULL, 0);
		} else {
			SS_LOGP(SPROACT, LDEBUG, "waiting %u poll cycles for TERMINAL RESPONSE\n",
				ctx->proactive.term_resp_poll_ctr);
			ctx->proactive.term_resp_poll_ctr++;
		}
	}
}

/*! Check if we are ready to send a PROACTIVE COMMAND right now.
 *  \param[in] ctx softsim context.
 *  \returns true when ready, false when another command is pending. */
bool ss_proactive_rts(const struct ss_context *ctx)
{
	if (ctx->proactive.data_len)
		return false;
	if (ctx->proactive.term_resp_cb)
		return false;
	return true;
}

/*! Put a PROACTIVE COMMAND for getting it FTECHed by the terminal.
 *  \param[inout] ctx softsim context.
 *  \param[in] term_resp_cb callback function to handle TERMINAL RESPONSE.
 *  \param[in] data command data (COMPRENSION TLV).
 *  \param[in] len length of data.
 *  \returns 0 on success, -EINVAL on error. */
int ss_proactive_put(struct ss_context *ctx, term_resp_cb term_resp_cb, const uint8_t *data, size_t len)
{
	struct ss_list *proact_cmd;
	int rc = 0;

	/*! The parameters *data and len are mandatory. */
	assert(data);
	assert(len > 0);

	if (ctx->proactive.data_len) {
		SS_LOGP(SPROACT, LERROR, "unable to put data, previous data not fetched yet!\n");
		return -EBUSY;
	}

	if (ctx->proactive.term_resp_cb) {
		SS_LOGP(SPROACT, LERROR,
			"unable to put data, still waiting for the response to the previous transaction!\n");
		return -EBUSY;
	}

	proact_cmd = SS_ALLOC(struct ss_list);
	ss_list_init(proact_cmd);
	ss_btlv_new_ie(proact_cmd, "proactive-command", TS_101_220_IEI_PROACTIVE_CMD, len, data);

	ctx->proactive.data_len = ss_btlv_encode(ctx->proactive.data, sizeof(ctx->proactive.data), proact_cmd);
	if (ctx->proactive.data_len == 0) {
		SS_LOGP(SPROACT, LERROR, "unable to put data, cannot encode BER-TLV enevelope!\n");
		rc = -EINVAL;
	}

	ss_btlv_free(proact_cmd);

	if (!term_resp_cb)
		ctx->proactive.term_resp_cb = default_term_response_cb;
	else
		ctx->proactive.term_resp_cb = term_resp_cb;

	return rc;
}

/*! Reset proactive command handling (called after TERMINAL RESPONSE and also after timeout).
 *  \param[inout] ctx softsim context. */
void ss_proactive_reset(struct ss_context *ctx)
{
	memset(ctx->proactive.data, 0, sizeof(ctx->proactive.data));
	ctx->proactive.data_len = 0;
	ctx->proactive.term_resp_cb = NULL;
	ctx->proactive.term_resp_poll_ctr = 0;
}

/*! Utility function to extract the return code from a TERMINAL RESPONSE
 *  \param[in] rep_data COMPREHENSION-TLV encoded response setring.
 *  \param[in] resp_data_len length of the COMPREHEINSION-TLV encoded response string.
 *  \returns return code or -EINVAL when no returncode can be extracted. */
int ss_proactive_get_rc(const uint8_t *resp_data, uint8_t resp_data_len, enum log_subsys log_subsys)
{
	struct ss_list *ctlv_data = NULL;
	struct cmp_tlv_ie *cmd_result_ie;
	int rc;

	/* No response at all */
	if (!resp_data) {
		SS_LOGP(log_subsys, LDEBUG, "no terminal response received -- command unsuccessful!\n");
		return -EINVAL;
	}

	SS_LOGP(log_subsys, LDEBUG, "terminal responded: %s\n", ss_hexdump(resp_data, resp_data_len));

	/* Decode TLV */
	ctlv_data = ss_ctlv_decode(resp_data, resp_data_len);
	if (!ctlv_data) {
		SS_LOGP(log_subsys, LERROR, "Unable to decode response -- command unsuccessful!\n");
		rc = -EINVAL;
		goto leave;
	}
	ss_ctlv_dump(ctlv_data, 2, log_subsys, LDEBUG);

	/* Check result IE (mandatory) */
	cmd_result_ie = ss_ctlv_get_ie_minlen(ctlv_data, TS_101_220_IEI_RESULT, 1);
	if (!cmd_result_ie) {
		/* The result IE does not have the */
		SS_LOGP(log_subsys, LERROR, "result lacks mandatory RESULT IE -- command unsuccessful!\n");
		rc = -EINVAL;
	} else {
		SS_LOGP(log_subsys, LDEBUG, "command result: %02x\n", cmd_result_ie->value->data[0]);
		rc = cmd_result_ie->value->data[0];
	}

leave:
	ss_ctlv_free(ctlv_data);
	return rc;
}

/*! Check the support of a certain feature in TERMINAL PROFILE.
 *  \param[inout] ctx softsim context.
 *  \param[in] byte_idx byte index as defined in ETSI TS 102 223, section 5.2.
 *  \param[in] bit_idx as defined in ETSI TS 102 223, section 5.2.
 *  \returns true when feature is supported, false otherwiese. */
bool ss_proactive_term_prof_bit(const struct ss_context *ctx, size_t byte_idx, uint8_t bit_idx)
{
	uint8_t byte;

	if (byte_idx == 0) {
		SS_LOGP(SPROACT, LERROR, "TERMINAL PROFILE byte indexes start countingt at 1!\n");
		assert(false);
	}
	if (bit_idx == 0) {
		SS_LOGP(SPROACT, LERROR, "TERMINAL PROFILE bit indexes start countingt at 1!\n");
		assert(false);
	}
	if (byte_idx > sizeof(ctx->proactive.term_profile)) {
		SS_LOGP(SPROACT, LERROR, "Tried to access TERMINAL PROFILE byte %zu, but end ist at byte %zu!\n",
			byte_idx, sizeof(ctx->proactive.term_profile));
		assert(false);
	}
	if (bit_idx > 8) {
		SS_LOGP(SPROACT, LERROR, "Tried to access TERMINAL PROFILE byte at bit %u!\n", bit_idx);
		assert(false);
	}

	/* Convert into indexes that start counting at 0 */
	byte_idx -= 1;
	bit_idx -= 1;

	byte = ctx->proactive.term_profile[byte_idx];
	return ((byte >> bit_idx) & 1) == 1;
}
