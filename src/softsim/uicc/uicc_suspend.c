/*
 * Copyright (c) 2024 Onomondo ApS. All rights reserved.
 *
 * SPDX-License-Identifier: GPL-3.0-only
 *
 * Author: Peter S. Bornerup
 *
 * NOTE: This function is used to store the internal status of the UICC so that the power supply
 * to the UICC can be switched off, and to subsequently restore the UICC status.
 *
 * NOTE: This implentation is not yet complete and compliant. Use carefully.
 * The usecase for which this initial implementation has been written, is for cases
 * where the modem can't enter deep sleep without the UICC being suspended. But since RAM is
 * retained during the deep sleep state (make sure to validate your specific platform) the
 * SoftSIM CTX isn't lost and hence the SoftSIM can be suspended/resumed.
 */

#include <onomondo/softsim/log.h>
#include <onomondo/softsim/utils.h>
#include <onomondo/softsim/storage.h>
#include <onomondo/softsim/file.h>
#include "command.h"
#include "sw.h"
#include "apdu.h"
#include "context.h"

static int ss_uicc_suspend(struct ss_apdu *apdu);
static int ss_uicc_resume(struct ss_apdu *apdu);

/* SUSPEND UICC, see ETSI TS 102 221, section 11.1.22 */
int ss_uicc_suspend_cmd(struct ss_apdu *apdu)
{
	int rc;

	switch (apdu->hdr.p1) {
	case 0x00:
		rc = ss_uicc_suspend(apdu);
		break;
	case 0x01:
		rc = ss_uicc_resume(apdu);
		break;
	default:
		return SS_SW_ERR_CHECKING_WRONG_P1_P2;
	}

	if (rc != 0)
		SS_LOGP(SUICC, LERROR, "UICC suspend/resume failed, err: %u!\n", rc);

	return rc;
}

/* SUSPEND, see ETSI TS 102 221, section 11.1.22.2 */
static int ss_uicc_suspend(struct ss_apdu *apdu)
{
	/* Length of the subsequent data field is always 4 bytes, covering:
	 * Minimum duration of the suspension proposed by the terminal (2 bytes)
	 * Maximum duration of the suspension proposed by the terminal (2 bytes) */
	if (apdu->lc != 4) {
		return SS_SW_ERR_CHECKING_WRONG_LENGTH;
	}

	/* Return maximum duration proposed by the terminal as default in the first 2 bytes of the response*/
	apdu->rsp[0] = apdu->cmd[2];
	apdu->rsp[1] = apdu->cmd[3];

	/* The UICC generates a random resume token of 8 bytes and stores it with the complete status. */
	char *secret_token = "onomondo"; /* a static token, introduce random token if desired. */
	memcpy(&apdu->rsp[2], secret_token, 8);

	apdu->rsp_len = 10;
	apdu->ctx->is_suspended = true;
	return 0;
}

/* RESUME, see ETSI TS 102 221, section 11.1.22.3 */
static int ss_uicc_resume(struct ss_apdu *apdu)
{
	/* Length of the subsequent data field is always 4 bytes, covering:
	 * Minimum duration of the suspension proposed by the terminal (2 bytes)
	 * Maximum duration of the suspension proposed by the terminal (2 bytes) */
	if (apdu->lc != 8) {
		return SS_SW_ERR_CHECKING_WRONG_LENGTH;
	}

	/* The UICC compares the Resume token passed by the terminal with the token stored in the non-volatile memory. */
	char *secret_token = "onomondo";
	apdu->ctx->is_suspended = false;
	if (memcmp(apdu->cmd, secret_token, 8) != 0) {
		return SS_SW_ERR_CMD_NOT_ALLOWED_SECURITY_STATUS;
	}

	/* No output expected from the resume function */
	return 0;
}
