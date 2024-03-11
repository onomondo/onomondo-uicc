/*
 * Author: Peter S. Borneurp
 *
 */

#include <stdbool.h>
#include <string.h>
#include <onomondo/softsim/log.h>
#include <onomondo/softsim/utils.h>
#include <onomondo/softsim/storage.h>
#include <onomondo/softsim/file.h>
#include "uicc_lchan.h"
#include "command.h"
#include "sw.h"
#include "apdu.h"
#include "context.h"
static int ss_uicc_suspend(struct ss_apdu *apdu);
static int ss_uicc_resume(struct ss_apdu *apdu);

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

	if (rc != 0) {
		SS_LOGP(SUICC, LERROR, "UICC susped/resume failed!\n");
	}

	return rc;
}

static int ss_uicc_suspend(struct ss_apdu *apdu)
{
	if (apdu->lc != 4) {
		return SS_SW_ERR_CHECKING_WRONG_LENGTH;
	}

	// return maximum duration by default
	apdu->rsp[0] = apdu->cmd[0];
	apdu->rsp[1] = apdu->cmd[1];

	char *secret_token = "onomondo";
	memcpy(&apdu->rsp[2], secret_token, 8);

	apdu->rsp_len = 10;
	apdu->ctx->is_suspended = true;
	return 0;
}
static int ss_uicc_resume(struct ss_apdu *apdu)
{
	if (apdu->lc != 8) {
		return SS_SW_ERR_CHECKING_WRONG_LENGTH;
	}
	char *secret_token = "onomondo";
	apdu->ctx->is_suspended = false;

	if (memcmp(apdu->cmd, secret_token, 8) != 0) {
		return SS_SW_ERR_CMD_NOT_ALLOWED_SECURITY_STATUS;
	}

	return 0;
}
