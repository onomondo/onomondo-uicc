/*
 * Copyright (c) 2024 Onomondo ApS. All rights reserved.
 *
 * SPDX-License-Identifier: GPL-3.0-only
 *
 * Author: Onomondo ApS
 */

#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "onomondo/softsim/log.h"
#include "onomondo/softsim/mem.h"
#include "onomondo/softsim/fs.h"
#include "onomondo/softsim/storage.h"
#include "onomondo/utils/ss_profile.h"
#include "onomondo/utils/ss_provision.h"

/* Relative paths used inside storage. These will be concatenated with the
 * configured storage path (see ss_storage_get_path()). */
static const char *ICCID_REL_PATH = PATH_SEPARATOR "3f00" PATH_SEPARATOR "2fe2";
static const char *IMSI_REL_PATH = PATH_SEPARATOR "3f00" PATH_SEPARATOR "7ff0" PATH_SEPARATOR "6f07";
static const char *A001_REL_PATH = PATH_SEPARATOR "3f00" PATH_SEPARATOR "a001";
static const char *A003_REL_PATH = PATH_SEPARATOR "3f00" PATH_SEPARATOR "a003";
static const char *A004_REL_PATH = PATH_SEPARATOR "3f00" PATH_SEPARATOR "a004";
static const char *SMSP_REL_PATH = PATH_SEPARATOR "3f00" PATH_SEPARATOR "7ff0" PATH_SEPARATOR "6f42";

/* SMSC offset inside EF.SMSP, in characters */
#define SMSC_OFFSET 74

/*! Write one EF inside storage
 *  \param[in] rel_path path of the EF relative to the storage root
 *  \param[in] mode "w" to replace the EF, "r+" to update it without truncating
 *  \param[in] offset offset to write at
 *  \param[in] data data to write
 *  \param[in] len length of data
 *  \returns 0 on success, -1 if the EF could not be opened, -2 if it was opened
 *  and not written whole */
static int write_ef(const char *rel_path, char *mode, long offset, const void *data, size_t len)
{
	char path[SS_STORAGE_PATH_MAX + 1];
	ss_FILE f;
	size_t wrote;
	int path_len;

	path_len = snprintf(path, sizeof(path), "%s%s", ss_storage_get_path(), rel_path);
	if (path_len < 0 || (size_t)path_len >= sizeof(path))
		return -2;

	/* "r+" does not create the EF, so a template tree missing it lands here. */
	f = ss_fopen(path, mode);
	if (!f)
		return -1;

	if (offset != 0 && ss_fseek(f, offset, SEEK_SET) != 0) {
		ss_fclose(f);
		return -2;
	}

	wrote = ss_fwrite(data, 1, len, f);

	/* An EF that was opened and then not written whole is torn, which is a
	 * different answer than one that was never there. The close carries that too:
	 * a buffered write reports a full disk there. */
	if (ss_fclose(f) != 0 || wrote != len)
		return -2;

	return 0;
}

/*! Write the decoded profile to the SoftSIM filesystem
 *  \param[in] profile Pointer to the decoded SoftSIM profile
 *  \returns 0 on success, -1 on failure */
static int write_profile_to_fs(const struct ss_profile *profile)
{
	const uint8_t zeros[SMSP_RECORD_SIZE * 2] = { 0 };
	const char *missing = NULL;
	int rc;

	/* The EFs below are written whether or not the profile carried the tag that
	 * fills them, so a field the profile left empty has to be caught here. The
	 * parser zeroes the struct and writes only what it found, so an absent tag
	 * leaves its field zeroed. Judged on the hex characters and never on the
	 * decoded keys: an all-zero Ki or OPc is a legitimate value, and it arrives
	 * here as '0' characters, not as NUL.
	 *
	 * KIC and KID are deliberately absent from the list. They are OTA keys
	 * (TS 102 225, TS 31.115) and a device that never receives a secured packet
	 * has no use for them, so the exporter emits them only when the profile has
	 * them. The four below are the ones that leave an unusable card when zeroed. */
	if (memcmp(profile->_3F00_2FE2, zeros, ICCID_LEN) == 0)
		missing = "ICCID";
	else if (memcmp(profile->_3F00_7ff0_6f07, zeros, IMSI_LEN) == 0)
		missing = "IMSI";
	else if (memcmp(&profile->_3F00_A001[0], zeros, KEY_SIZE) == 0)
		missing = "Ki";
	else if (memcmp(&profile->_3F00_A001[KEY_SIZE], zeros, KEY_SIZE) == 0)
		missing = "OPc";

	if (missing) {
		SS_LOGP(SSTORAGE, LERROR, "profile carries no %s, refusing to provision it\n", missing);
		return -1;
	}

	if (write_ef(ICCID_REL_PATH, "w", 0, profile->_3F00_2FE2, ICCID_LEN) != 0)
		return -1;

	if (write_ef(IMSI_REL_PATH, "w", 0, profile->_3F00_7ff0_6f07, IMSI_LEN) != 0)
		return -1;

	if (write_ef(A001_REL_PATH, "w", 0, profile->_3F00_A001, A001_LEN) != 0)
		return -1;

	/* PIN code file. It holds state the card maintains -- a PIN the user changed,
	 * the enabled flag, the retry and unblock counters -- so it is written only
	 * when the profile carries a value to put in it. Writing it unconditionally
	 * would put the shipped defaults back over all of that.
	 *
	 * Updated rather than replaced: a template may hold records this format does
	 * not describe, and those must survive. Optional, because a reduced template
	 * need not ship the file at all: "r+" does not create it, and a file that was
	 * never there is the one failure this EF forgives. A torn write is not. */
	if (profile->pin_present) {
		rc = write_ef(A003_REL_PATH, "r+", 0, profile->_3F00_A003, A003_LEN);
		if (rc == -1)
			SS_LOGP(SPIN, LINFO, "no PIN code file to update, keeping the card's PIN configuration\n");
		else if (rc != 0)
			return -1;
	}

	if (write_ef(A004_REL_PATH, "w", 0, profile->_3F00_A004, A004_LEN) != 0)
		return -1;

	/* EF.SMSP and the SMSC inside it are optional: a profile carrying neither
	 * keeps what the template shipped. */
	if (memcmp(profile->SMSP, zeros, SMSP_RECORD_SIZE * 2) != 0 &&
	    write_ef(SMSP_REL_PATH, "r+", 0, profile->SMSP, SMSP_RECORD_SIZE * 2) != 0)
		return -1;

	if (memcmp(profile->SMSC, zeros, SMSC_LEN) != 0 &&
	    write_ef(SMSP_REL_PATH, "r+", SMSC_OFFSET, profile->SMSC, SMSC_LEN) != 0)
		return -1;

	return 0;
}

/*! Provision a SoftSIM profile from e.g. an AT command string
 *  \param[in] profile Profile string as received from AT command
 *  \returns 0 on success */
int onomondo_profile_provisioning(const char *at_profile)
{
	struct ss_profile *profile = SS_ALLOC(*profile);
	size_t input_string_size;
	int rc;

	if (!profile)
		return -1;

	input_string_size = strlen(at_profile);
	if (input_string_size > UINT16_MAX) {
		rc = -1;
		goto exit;
	}

	rc = ss_profile_from_string((uint16_t)input_string_size, at_profile, profile);
	if (rc != 0)
		goto exit;

	rc = write_profile_to_fs(profile);

exit:
	SS_FREE(profile);
	return rc;
}
