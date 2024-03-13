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
#include <onomondo/softsim/utils.h>
#include <onomondo/softsim/storage.h>
#include <onomondo/softsim/file.h>
#include "uicc_lchan.h"
#include "command.h"
#include "uicc_pin.h"
#include "uicc_ins.h"
#include "sw.h"
#include "apdu.h"
#include "fs.h"
#include "fs_utils.h"
#include "fcp.h"

/* PIN code file in file system */
#define PIN_FID 0xA003

const uint8_t pins_in_psdo[] = {
	SS_PIN_1,
	SS_PIN_2,
	SS_PIN_ADM1,
};

/* Record layout of the file is the same as the layout of the pin_context
 * struct. */
struct pin_context {
	bool enabled;
	uint8_t max_tries;
	uint8_t tries;
	uint8_t max_unblock_tries;
	uint8_t unblock_tries;
	uint8_t pin_no; /* Value-compatible with `enum pin`, but u8 to not depend on system integer width and endianness */
	uint8_t pin[8];
	uint8_t puk[8];
} __attribute__((packed));

/* find the PIN context for a given PIN number in PIN code file
 *
 * @param[out] sw      A setatus word containing additional error details
 * @param[in]  pin_no  A key reference (cf. `enum pin`)
 *
 * @return A pointer to the first pin context matching pin_no. Must be freed
 * later by calling @ref pin_context_free.
 */
static struct pin_context *get_pin_context(uint16_t *sw, uint8_t pin_no)
{
	unsigned int i;
	int rc;
	struct ss_list pin_context_path;
	struct ss_buf *pin_context_buf;
	struct pin_context *pin_context_ptr;
	struct ss_file *pin_context_file;
	uint8_t n_pins;

	/* Select pin code file. */
	ss_fs_init(&pin_context_path);
	rc = ss_fs_select(&pin_context_path, PIN_FID);
	if (rc < 0) {
		SS_LOGP(SPIN, LERROR, "PIN code file not selectable -- cannot load context for PIN No.:%02x!\n",
			pin_no);
		ss_path_reset(&pin_context_path);
		return NULL;
	}
	pin_context_file = ss_get_file_from_path(&pin_context_path);
	if (!pin_context_file) {
		SS_LOGP(SPIN, LERROR, "PIN code file not available -- cannot load context for PIN No.:%02x!\n", pin_no);
		ss_path_reset(&pin_context_path);
		return NULL;
	}

	/* Read pin context from pin code file */
	SS_LOGP(SPIN, LINFO, "loading pin PIN code file for PIN No.:%02x...\n", pin_no);
	n_pins = pin_context_file->fcp_file_descr->number_of_records;
	for (i = 0; i < n_pins; i++) {
		pin_context_buf = ss_fs_read_file_record(&pin_context_path, i + 1);
		if (!pin_context_buf) {
			SS_LOGP(SPIN, LERROR, "PIN code file inconsistent -- cannot read record (%u)!\n", i + 1);
			ss_path_reset(&pin_context_path);
			return NULL;
		}

		pin_context_ptr = (struct pin_context *)pin_context_buf->data;
		if (pin_no == pin_context_ptr->pin_no) {
			ss_path_reset(&pin_context_path);
			/* The pin_context_free function relies on this implementation details of
			 * ss_buf, as otherwise there is not offsetof available */
			assert((uintptr_t)pin_context_buf + sizeof(struct ss_buf) == (uintptr_t)pin_context_ptr);
			/* pin_context_buf is "leaked" here, but reconstructed and freed when
			 * pin_context_free is called
			 *
			 * The alternative designs here would be to copy data around into an own
			 * buffer (rejected to avoid needless coping, but can be switched to
			 * API-compatibly) and using caller allocated buffers (which are a bit
			 * pointless as long as files are read into a dynamically allocated
			 * buffer already).
			 * */
			return pin_context_ptr;
		}

		ss_buf_free(pin_context_buf);
	}

	SS_LOGP(SPIN, LERROR, "invalid PIN (%u) -- abort\n", pin_no);
	if (sw)
		*sw = SS_SW_ERR_CHECKING_WRONG_P1_P2;
	ss_path_reset(&pin_context_path);
	return NULL;
}

static void pin_context_free(struct pin_context *pin)
{
	if (pin == NULL)
		return;

	struct ss_buf *pin_context_buf = (struct ss_buf *)(((char *)pin) - sizeof(struct ss_buf));
	ss_buf_free(pin_context_buf);
}

/* Find PIN context in PIN code file and update it. */
static int update_pin_context(const struct pin_context *pin)
{
	unsigned int i;
	int rc;
	struct ss_list pin_context_path;
	struct ss_buf *pin_context_buf;
	struct pin_context *pin_context_ptr;
	struct ss_file *pin_context_file;
	uint8_t n_pins;

	/* Select pin code file. */
	ss_fs_init(&pin_context_path);
	rc = ss_fs_select(&pin_context_path, PIN_FID);
	if (rc < 0) {
		SS_LOGP(SPIN, LERROR, "PIN code file not selectable -- cannot update context for PIN No.:%02x!\n",
			pin->pin_no);
		ss_path_reset(&pin_context_path);
		return -EINVAL;
	}
	pin_context_file = ss_get_file_from_path(&pin_context_path);
	if (!pin_context_file) {
		SS_LOGP(SPIN, LERROR, "PIN code file not available -- cannot update context for PIN No.:%02x!\n",
			pin->pin_no);
		ss_path_reset(&pin_context_path);
		return -EINVAL;
	}

	/* Update pin context from pin code file */
	SS_LOGP(SPIN, LINFO, "updating pin PIN code file for PIN No.:%02x...\n", pin->pin_no);
	n_pins = pin_context_file->fcp_file_descr->number_of_records;
	for (i = 0; i < n_pins; i++) {
		pin_context_buf = ss_fs_read_file_record(&pin_context_path, i + 1);
		if (!pin_context_buf) {
			SS_LOGP(SPIN, LERROR, "PIN code file inconsistent -- cannot read record (%u)!\n", i + 1);
			ss_path_reset(&pin_context_path);
			return -EINVAL;
		}

		pin_context_ptr = (struct pin_context *)pin_context_buf->data;
		if (pin->pin_no == pin_context_ptr->pin_no) {
			rc = ss_fs_write_file_record(&pin_context_path, i + 1, (uint8_t *)pin, sizeof(*pin));
			if (rc < 0) {
				SS_LOGP(SPIN, LERROR, "PIN code file update failed -- cannot write record (%u)!\n",
					i + 1);
				ss_buf_free(pin_context_buf);
				ss_path_reset(&pin_context_path);
				return -EINVAL;
			}

			ss_buf_free(pin_context_buf);
			ss_path_reset(&pin_context_path);
			return 0;
		}

		ss_buf_free(pin_context_buf);
	}

	ss_path_reset(&pin_context_path);
	return 0;
}

/* check the PIN retry counter. If the retry counter has exceeded the maximum
 * amount of tries, then return false */
static bool check_pin_retry_counter(const struct pin_context *pin)
{
	if (pin->tries >= pin->max_tries) {
		SS_LOGP(SPIN, LERROR, "PIN (%u) is blocked -- abort\n", pin->pin_no);
		return false;
	}

	return true;
}

/* VERIFY PIN, see also ETSI TS 102 221, section 11.1.9 */
int ss_uicc_pin_cmd_verify_pin(struct ss_apdu *apdu)
{
	struct pin_context *pin = NULL;
	int rc;
	int result;

	/* Get PIN context */
	pin = get_pin_context(&apdu->sw, apdu->hdr.p2);
	if (!pin)
		return SS_SW_ERR_EXEC_MEMORY_PROBLEM;

	/* Return number of remaining tries, see also ETSI TS 102 221,
	 * section 11.1.9.1.2 */
	if (apdu->lc == 0) {
		SS_LOGP(SPIN, LDEBUG, "no operation, number of remaining tries (%u) requested\n",
			(pin->max_tries - pin->tries) & 0x0f);
		result = SS_SW_WARN_VERIFICATION_FAILED_X_REMAIN | ((pin->max_tries - pin->tries) & 0x0f);
		goto leave;
	}

	/* Check retry counter */
	if (!check_pin_retry_counter(pin)) {
		result = SS_SW_ERR_CMD_NOT_ALLOWED_PIN_BLOCKED;
		goto leave;
	}

	/* PIN must not be disabled */
	if (!pin->enabled) {
		SS_LOGP(SPIN, LERROR, "cannot verify, PIN (%u) is disabled -- abort\n", pin->pin_no);
		result = SS_SW_ERR_CMD_NOT_ALLOWED_CONDITONS_NOT_SATISFIED;
		goto leave;
	}

	/* Check length and match PIN code */
	if (apdu->lc != sizeof(pin->pin) || memcmp(apdu->cmd, pin->pin, sizeof(pin->pin))) {
		SS_LOGP(SPIN, LERROR, "incorrect PIN (%u), VERIFY PIN failed -- abort\n", pin->pin_no);
		pin->tries++;
		rc = update_pin_context(pin);
		if (rc < 0)
			result = SS_SW_ERR_CMD_NOT_ALLOWED_PIN_BLOCKED;
		else
			result = SS_SW_WARN_VERIFICATION_FAILED_X_REMAIN | ((pin->max_tries - pin->tries) & 0x0f);
		goto leave;
	}

	SS_LOGP(SPIN, LINFO, "valid PIN (%u), VERIFY PIN successful\n", pin->pin_no);
	apdu->lchan->pin_verfied[pin->pin_no] = true;
	pin->tries = 0;
	rc = update_pin_context(pin);
	if (rc < 0)
		result = SS_SW_ERR_CMD_NOT_ALLOWED_PIN_BLOCKED;
	else
		result = 0;

leave:
	pin_context_free(pin);
	return result;
}

/* CHANGE PIN, see also ETSI TS 102 221, section 11.1.10 */
int ss_uicc_pin_cmd_change_pin(struct ss_apdu *apdu)
{
	struct pin_context *pin = NULL;
	int rc;
	int result;

	/* Get PIN context */
	pin = get_pin_context(&apdu->sw, apdu->hdr.p2);
	if (!pin)
		return SS_SW_ERR_EXEC_MEMORY_PROBLEM;

	/* PIN must not be blocked, check retry counter */
	if (!check_pin_retry_counter(pin)) {
		result = SS_SW_ERR_CMD_NOT_ALLOWED_PIN_BLOCKED;
		goto leave;
	}

	/* PIN must not be disabled */
	if (!pin->enabled) {
		SS_LOGP(SPIN, LERROR, "cannot change, PIN (%u) is disabled -- abort\n", pin->pin_no);
		result = SS_SW_ERR_CMD_NOT_ALLOWED_CONDITONS_NOT_SATISFIED;
		goto leave;
	}

	/* Check length and match old PIN code */
	if (apdu->lc != sizeof(pin->pin) * 2 || memcmp(apdu->cmd, pin->pin, sizeof(pin->pin))) {
		SS_LOGP(SPIN, LERROR, "incorrect old PIN (%u), CHANGE PIN failed -- abort\n", pin->pin_no);
		pin->tries++;
		rc = update_pin_context(pin);
		if (rc < 0)
			result = SS_SW_ERR_CMD_NOT_ALLOWED_PIN_BLOCKED;
		else
			result = SS_SW_WARN_VERIFICATION_FAILED_X_REMAIN | ((pin->max_tries - pin->tries) & 0x0f);
		goto leave;
	}

	/* Apply new PIN code */
	memcpy(pin->pin, apdu->cmd + sizeof(pin->pin), sizeof(pin->pin));
	rc = update_pin_context(pin);
	if (rc < 0) {
		result = SS_SW_ERR_CMD_NOT_ALLOWED_PIN_BLOCKED;
		goto leave;
	}

	SS_LOGP(SPIN, LINFO, "valid PIN (%u), CHANGE PIN successful\n", pin->pin_no);

	result = 0;

leave:
	pin_context_free(pin);
	return result;
}

/* DISABLE PIN, see also ETSI TS 102 221, section 11.1.11 */
int ss_uicc_pin_cmd_disable_pin(struct ss_apdu *apdu)
{
	/* Note: This implementation ignores the usage of an "alternative global
	 * key reference". */

	struct pin_context *pin = NULL;
	int rc;
	int result;

	/* Get PIN context */
	pin = get_pin_context(&apdu->sw, apdu->hdr.p2);
	if (!pin)
		return SS_SW_ERR_EXEC_MEMORY_PROBLEM;

	/* Check retry counter */
	if (!check_pin_retry_counter(pin)) {
		result = SS_SW_ERR_CMD_NOT_ALLOWED_PIN_BLOCKED;
		goto leave;
	}

	/* Check length and match PIN code */
	if (apdu->lc != sizeof(pin->pin) || memcmp(apdu->cmd, pin->pin, sizeof(pin->pin))) {
		SS_LOGP(SPIN, LERROR, "incorrect PIN (%u), DISABLE PIN failed -- abort\n", pin->pin_no);
		pin->tries++;
		rc = update_pin_context(pin);
		if (rc < 0)
			result = SS_SW_ERR_CMD_NOT_ALLOWED_PIN_BLOCKED;
		else
			result = SS_SW_WARN_VERIFICATION_FAILED_X_REMAIN | ((pin->max_tries - pin->tries) & 0x0f);
		goto leave;
	}

	SS_LOGP(SPIN, LINFO, "valid PIN (%u), DISABLE PIN successful\n", pin->pin_no);
	pin->tries = 0;
	pin->enabled = false;
	rc = update_pin_context(pin);
	if (rc < 0)
		result = SS_SW_ERR_CMD_NOT_ALLOWED_PIN_BLOCKED;
	else
		result = 0;

leave:
	pin_context_free(pin);
	return result;
}

/* ENABLE PIN, see also ETSI TS 102 221, section 11.1.12 */
int ss_uicc_pin_cmd_enable_pin(struct ss_apdu *apdu)
{
	/* Note: This implementation ignores the usage of an "alternative global
	 * key reference". */

	struct pin_context *pin = NULL;
	int rc;
	int result;

	/* Get PIN context */
	pin = get_pin_context(&apdu->sw, apdu->hdr.p2);
	if (!pin)
		return SS_SW_ERR_EXEC_MEMORY_PROBLEM;

	/* Check retry counter */
	if (!check_pin_retry_counter(pin)) {
		result = SS_SW_ERR_CMD_NOT_ALLOWED_PIN_BLOCKED;
		goto leave;
	}

	/* Check length and match PIN code */
	if (apdu->lc != sizeof(pin->pin) || memcmp(apdu->cmd, pin->pin, sizeof(pin->pin))) {
		SS_LOGP(SPIN, LERROR, "incorrect PIN (%u), ENABLE PIN failed -- abort\n", pin->pin_no);
		pin->tries++;
		rc = update_pin_context(pin);
		if (rc < 0)
			result = SS_SW_ERR_CMD_NOT_ALLOWED_PIN_BLOCKED;
		else
			result = SS_SW_WARN_VERIFICATION_FAILED_X_REMAIN | ((pin->max_tries - pin->tries) & 0x0f);
		goto leave;
	}

	SS_LOGP(SPIN, LINFO, "valid PIN (%u), ENABLE PIN successful\n", pin->pin_no);
	pin->tries = 0;
	pin->enabled = true;
	rc = update_pin_context(pin);
	if (rc < 0)
		result = SS_SW_ERR_CMD_NOT_ALLOWED_PIN_BLOCKED;
	else
		result = 0;

leave:
	pin_context_free(pin);
	return result;
}

/* UNBLOCK PIN, see also ETSI TS 102 221, section 11.1.13.1.2 */
int ss_uicc_pin_cmd_unblock_pin(struct ss_apdu *apdu)
{
	struct pin_context *pin = NULL;
	int rc;
	int result;

	/* Get PIN context */
	pin = get_pin_context(&apdu->sw, apdu->hdr.p2);
	if (!pin)
		return SS_SW_ERR_EXEC_MEMORY_PROBLEM;

	/* Return number of remaining tries, see also ETSI TS 102 221,
	 * section 11.1.13.1.2 */
	if (apdu->lc == 0) {
		SS_LOGP(SPIN, LDEBUG, "no operation, number of remaining tries (%u) requested\n",
			(pin->max_unblock_tries - pin->unblock_tries) & 0x0f);
		result = SS_SW_WARN_VERIFICATION_FAILED_X_REMAIN |
			 ((pin->max_unblock_tries - pin->unblock_tries) & 0x0f);
		goto leave;
	}

	/* PUK must not be blocked, check retry counter */
	if (pin->unblock_tries >= pin->max_unblock_tries) {
		SS_LOGP(SPIN, LERROR, "PUK (%u) is blocked -- abort\n", pin->pin_no);
		result = SS_SW_ERR_CMD_NOT_ALLOWED_PIN_BLOCKED;
		goto leave;
	}

	/* Check length and match PUK code */
	if (apdu->lc != sizeof(pin->puk) + sizeof(pin->pin) || memcmp(apdu->cmd, pin->puk, sizeof(pin->puk))) {
		SS_LOGP(SPIN, LERROR, "incorrect PUK (%u), UNBLOCK PIN failed -- abort\n", pin->pin_no);
		pin->unblock_tries++;
		rc = update_pin_context(pin);
		if (rc < 0)
			result = SS_SW_ERR_CMD_NOT_ALLOWED_PIN_BLOCKED;
		else
			result = SS_SW_WARN_VERIFICATION_FAILED_X_REMAIN |
				 ((pin->max_unblock_tries - pin->unblock_tries) & 0x0f);
		goto leave;
	}

	/* Apply new PIN code */
	memcpy(pin->pin, apdu->cmd + sizeof(pin->puk), sizeof(pin->pin));
	pin->unblock_tries = 0;
	pin->tries = 0;
	rc = update_pin_context(pin);
	if (rc < 0) {
		result = SS_SW_ERR_CMD_NOT_ALLOWED_PIN_BLOCKED;
	} else {
		SS_LOGP(SPIN, LINFO, "valid PUK (%u), UNBLOCK PIN successful\n", pin->pin_no);
		result = 0;
	}

leave:
	pin_context_free(pin);
	return result;
}

/*! Check verfication status of a specified PIN.
 *  \param[in] in_no number of the PIN to check.
 *  \param[in] lchan logicl channel (stores the pin verification state).
 *  \returns verfication status of the specified pin. */
bool ss_uicc_pin_verified(enum pin pin_no, const struct ss_lchan *lchan)
{
	struct pin_context *pin = NULL;
	bool result;

	pin = get_pin_context(NULL, pin_no);
	if (!pin)
		return false;

	if (pin_no == pin->pin_no) {
		if (pin->enabled)
			result = lchan->pin_verfied[pin_no];
		else
			result = true;
	} else {
		result = false;
	}

	pin_context_free(pin);
	return result;
}

/*! Update PS_DO flag inside a given pin status template.
 *
 *  \param[in] pin_stat_templ pin status template string.
 *  \returns 0 on success -EINVAL on failure.
 *
 * This relies on the elements to be constructed precisely as in @ref
 * ss_uicc_pin_gen_pst_do.
 *  */
int ss_uicc_pin_update_pst_do(struct ss_buf *pin_stat_templ)
{
	if (pin_stat_templ->len < 4) {
		SS_LOGP(SPIN, LERROR, "pin status template too short!\n");
		/* We exclusively work with those generated in ss_uicc_pin_gen_pst_do, but
		 * we can't easily know that precise length here, so the check is only for
		 * what we actively use to avoid causing a memory error from a programming
		 * error. (The programming error will result in the PST_DO being
		 * nonsensical, but we can't check all of it without the effort of
		 * rebuilding it). */
		return -EINVAL;
	}

	uint8_t pins_enabled = 0;
	int i = 0;
	/* There is only 1 byte allocated to store the bits */
	assert(SS_ARRAY_SIZE(pins_in_psdo) <= 7);
	for (i = 0; i < SS_ARRAY_SIZE(pins_in_psdo); ++i) {
		struct pin_context *pin = NULL;
		pin = get_pin_context(NULL, pins_in_psdo[i]);
		if (!pin)
			return -EINVAL;
		if (pin->enabled) {
			pins_enabled |= 1 << (7 - i);
		}
		pin_context_free(pin);
	}
	SS_LOGP(SPIN, LDEBUG, "Set of enabled pins is %02x\n", pins_enabled);
	pin_stat_templ->data[2] = pins_enabled;

	return 0;
}

/*! Generate a valid PIN Status Template DO string.
 *
 *  \returns buffer with PIN Status Template DO on success NULL on failure.
 *
 *  The buffer contains the enablement status of and corresponding key
 *  references to all \ref pins_in_psdo (independent of the selected DF) under
 *  the implementation's constraint of only using a single set of credentials.
 *  */
struct ss_buf *ss_uicc_pin_gen_pst_do(void)
{
	struct ss_buf *pin_stat_templ;
	int rc;
	int i = 0;

	pin_stat_templ = ss_buf_alloc(3 + 3 * SS_ARRAY_SIZE(pins_in_psdo));
	if (!pin_stat_templ)
		return pin_stat_templ;
	/* PS_DO */
	pin_stat_templ->data[0] = 0x90; /* tag */
	pin_stat_templ->data[1] = 0x01; /* length */
	pin_stat_templ->data[2] = 0x00; /* to be set in ss_uicc_pin_update_pst_do */

	/* No Usage Qualifier tag: We don't support the Universal Pin, in
	 * particular don't set the Key reference value to 0x11, and thus don't
	 * need a Usage Qualifier (ETSI TS 102 221 V16 p94) */

	for (i = 0; i < SS_ARRAY_SIZE(pins_in_psdo); ++i) {
		/* Key reference */
		pin_stat_templ->data[3 + i * 3 + 0] = 0x83; /* tag */
		pin_stat_templ->data[3 + i * 3 + 1] = 0x01; /* length */
		pin_stat_templ->data[3 + i * 3 + 2] = pins_in_psdo[i];
	}

	rc = ss_uicc_pin_update_pst_do(pin_stat_templ);
	if (rc < 0) {
		SS_LOGP(SPIN, LERROR, "pin status template has been generated but it was not possible to update it!\n");
	}
	return pin_stat_templ;
}
