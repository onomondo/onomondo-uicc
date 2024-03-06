/*
 * Copyright (c) 2024 Onomondo ApS. All rights reserved.
 *
 * SPDX-License-Identifier: GPL-3.0-only
 *
 * Author: Philipp Maier
 */

#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <errno.h>
#include <onomondo/softsim/log.h>
#include <onomondo/softsim/storage.h>
#include <onomondo/softsim/file.h>
#include <onomondo/softsim/utils.h>
#include "sw.h"
#include "command.h"
#include "uicc_cat.h"
#include "uicc_sms_rx.h"
#include "uicc_ins.h"
#include "uicc_lchan.h"
#include "apdu.h"
#include "context.h"
#include "btlv.h"
#include "ctlv.h"
#include "sms.h"

/*! handler to handle CAT enevelope commands */
struct ss_cat_envelope_command {
	/*! human readable name that describes handler function. */
	const char *name;
	/*! IEI of the CAT template that this handler function is processing */
	uint32_t iei;
	/*! expected minimum length of the CAT template (prevent noise and invalid data) */
	uint32_t minlen;
	/*! CLA and MASK against which to compare CLA from APDU header */
	int (*handler)(struct ss_apdu *apdu, struct ss_buf *cat_template);
};

/* Handler function to handle CAT SMS PP Download */
int handle_sms_pp_dwnld(struct ss_apdu *apdu, struct ss_buf *cat_template)
{
	struct ss_list *ctlv_data = NULL;
	struct cmp_tlv_ie *sms_tpdu_ie;
	int rc;

	ctlv_data = ss_ctlv_decode(cat_template->data, cat_template->len);
	if (!ctlv_data) {
		SS_LOGP(SPROACT, LERROR, "failed to decode COMPREHENSION-TLV encoded SMS-PP data\n");
		return SS_SW_ERR_WRONG_PARAM_INCORRECT_DATA;
	}
	ss_ctlv_dump(ctlv_data, 2, SPROACT, LDEBUG);

	sms_tpdu_ie = ss_ctlv_get_ie(ctlv_data, TS_101_220_IEI_SMS_TPDU);
	if (!sms_tpdu_ie) {
		SS_LOGP(SPROACT, LERROR, "failed to receive SMS-PP, SMS-TPDU IE missing\n");
		rc = SS_SW_ERR_WRONG_PARAM_INCORRECT_DATA;
		goto leave;
	}

	apdu->rsp_len = SS_ARRAY_SIZE(apdu->rsp);
	rc = ss_uicc_sms_rx(apdu->ctx, sms_tpdu_ie->value, &apdu->rsp_len, apdu->rsp);
	if (rc != 0)
		apdu->rsp_len = 0;

leave:
	ss_ctlv_free(ctlv_data);
	return 0;
}

const struct ss_cat_envelope_command cat_envelope_commands[] = {
	{
		.name = "SMS PP DOWNLOAD",
		.iei = TS_101_220_IEI_SMS_PP_DWNLD,
		.handler = handle_sms_pp_dwnld,
		.minlen = 3,
	},
};

/*! TERMINAL PROFILE (TS 102 221 Section 11.2.1) */
int ss_uicc_cat_cmd_term_profile(struct ss_apdu *apdu)
{
	size_t term_profile_len;

	/* Clear old profile */
	memset(apdu->ctx->proactive.term_profile, 0, sizeof(apdu->ctx->proactive.term_profile));

	/* Store profile */
	if (apdu->lc <= sizeof(apdu->ctx->proactive.term_profile)) {
		term_profile_len = apdu->lc;
	} else {
		/* Note: the buffer size is chosen large enough, so that this
		 * error should never occur. */
		SS_LOGP(SPROACT, LERROR, "transmitted TERMINAL PROFILE too large for internal buffer\n");
		term_profile_len = sizeof(apdu->ctx->proactive.term_profile);
	}
	memcpy(apdu->ctx->proactive.term_profile, apdu->cmd, term_profile_len);

	/* Enable proactive behaviour globally */
	apdu->ctx->proactive.enabled = true;

	return 0;
}

/*! ENVELOPE (TS 102 221 Section 11.2.2) */
int ss_uicc_cat_cmd_envelope(struct ss_apdu *apdu)
{
	struct ss_list *envelope = NULL;
	int rc = 0;

	unsigned int i;
	struct ber_tlv_ie *cat_template;

	SS_LOGP(SPROACT, LDEBUG, "Data fed into BTLV: %s\n", ss_hexdump(apdu->cmd, apdu->hdr.p3));
	size_t data_len = apdu->hdr.p3; /* The announced length */
	/* Let's not read outside initialized data */
	if (apdu->lc < data_len) {
		SS_LOGP(SPROACT, LERROR, "Data length anounced in P3 exceeds available data\n");
		return SS_SW_ERR_WRONG_PARAM_INCORRECT_DATA;
	}
	envelope = ss_btlv_decode(apdu->cmd, data_len, ss_proactive_get_cat_descr());
	if (!envelope) {
		SS_LOGP(SPROACT, LERROR, "failed to decode BER-TLV encoded envelope\n");
		return SS_SW_ERR_WRONG_PARAM_INCORRECT_DATA;
	}
	ss_btlv_dump(envelope, 2, SPROACT, LDEBUG);

	rc = SS_SW_ERR_WRONG_PARAM_FUNCTION_NOT_SUPPORTED;
	for (i = 0; i < SS_ARRAY_SIZE(cat_envelope_commands); i++) {
		cat_template =
			ss_btlv_get_ie_minlen(envelope, cat_envelope_commands[i].iei, cat_envelope_commands[i].minlen);
		if (cat_template) {
			SS_LOGP(SPROACT, LDEBUG, "executing handler function for CAT TEMPLATE %02x: %s\n",
				cat_envelope_commands[i].iei, cat_envelope_commands[i].name);
			rc = cat_envelope_commands[i].handler(apdu, cat_template->value);
		}
	}

	ss_btlv_free(envelope);
	return rc;
}

/*! FETCH (TS 102 221 Section 11.2.3) */
int ss_uicc_cat_cmd_fetch(struct ss_apdu *apdu)
{
	int rc = 0;

	if (!apdu->ctx->proactive.enabled) {
		apdu->le = 0;
		rc = SS_SW_ERR_WRONG_PARAM_FUNCTION_NOT_SUPPORTED;
		goto leave;
	}

	memcpy(apdu->rsp, apdu->ctx->proactive.data, apdu->ctx->proactive.data_len);
	apdu->rsp_len = apdu->ctx->proactive.data_len;

leave:
	/* Mark data as consumed so that the status word will no longer
	 * announce proactive data. */
	apdu->ctx->proactive.data_len = 0;

	return rc;
}

/*! TERMINAL RESPONSE (TS 102 221 Section 11.2.4) */
int ss_uicc_cat_cmd_term_resp(struct ss_apdu *apdu)
{
	if (!apdu->ctx->proactive.enabled)
		return SS_SW_ERR_WRONG_PARAM_FUNCTION_NOT_SUPPORTED;

	term_resp_cb callback = apdu->ctx->proactive.term_resp_cb;
	ss_proactive_reset(apdu->ctx);
	callback(apdu->ctx, apdu->cmd, apdu->lc);

	return 0;
}
