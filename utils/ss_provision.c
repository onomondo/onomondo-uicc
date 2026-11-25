/*
 * Copyright (c) 2024 Onomondo ApS. All rights reserved.
 *
 * SPDX-License-Identifier: GPL-3.0-only
 *
 * Author: Onomondo ApS
 */

#include <ctype.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "onomondo/softsim/log.h"
#include "onomondo/softsim/mem.h"
#include "onomondo/softsim/fs.h"
#include "onomondo/softsim/storage.h"
#include "onomondo/utils/ss_profile.h"
#include "onomondo/utils/ss_provision.h"
#include "ss_utils_memzero.h"

/* Relative paths used inside storage. These will be concatenated with the
 * configured storage path (see ss_storage_get_path()). */
static const char *ICCID_REL_PATH = PATH_SEPARATOR "3f00" PATH_SEPARATOR "2fe2";
static const char *IMSI_REL_PATH = PATH_SEPARATOR "3f00" PATH_SEPARATOR "7ff0" PATH_SEPARATOR "6f07";
static const char *A001_REL_PATH = PATH_SEPARATOR "3f00" PATH_SEPARATOR "a001";
static const char *A003_REL_PATH = PATH_SEPARATOR "3f00" PATH_SEPARATOR "a003";
static const char *A004_REL_PATH = PATH_SEPARATOR "3f00" PATH_SEPARATOR "a004";
static const char *SMSP_REL_PATH = PATH_SEPARATOR "3f00" PATH_SEPARATOR "7ff0" PATH_SEPARATOR "6f42";

#define A001_TAGS (SS_TAG_BIT(KI_TAG) | SS_TAG_BIT(OPC_TAG))
#define A003_TAGS (SS_TAG_BIT(PIN_1_TAG) | SS_TAG_BIT(PIN_2_TAG) | SS_TAG_BIT(PIN_ADM_TAG) | SS_TAG_BIT(PUK_TAG))
#define A004_TAGS (SS_TAG_BIT(KIC_TAG) | SS_TAG_BIT(KID_TAG))

/* A004 record 1 header: TAR b00011 | MSL 06 | KIC indication | KID indication.*/
static const char a004_tar_msl[8] = "b0001106";
static const char a004_key_ind[2] = "01";

/* A001 flag value: the key in the OPc slot is an OPc, not an OP */
static const char a001_flag_opc[2] = "00";

/* A003 counter value: no failed attempts */
static const char a003_no_tries[2] = "00";

/* EF.IMSI as the template ships it: 08 09 10 10 00 00 00 00 10, IMSI
 * 001010000000001. A card holding it is not provisioned. */
static const char default_imsi[IMSI_LEN] = "080910100000000010";

#ifdef CONFIG_COMPACT_STORAGE
/* The largest EF this writer reads or writes, in bytes */
#define EF_BIN_MAX A004_BIN_LEN

/* hex is a pair of characters the writer produced or the parser checked */
static uint8_t hex_to_uint8(const char *hex)
{
	return (uint8_t)((hex[0] % 32 + 9) % 25 * 16 + (hex[1] % 32 + 9) % 25);
}
#endif

/*! Read one EF inside storage, whole
 *  \param[in] rel_path path of the EF relative to the storage root
 *  \param[out] data buffer of len hex characters: as stored with the hex
 *  backend, lower case with the compact one.
 *  \param[in] len number of hex characters to read
 *  \returns 0 on success, -1 if the EF could not be opened, -2 if it was opened
 *  and is shorter than len */
static int read_ef(const char *rel_path, void *data, size_t len)
{
	char path[SS_STORAGE_PATH_MAX + 1];
	ss_FILE f;
	size_t got;
	int path_len;
	int rc = -2;
#ifdef CONFIG_COMPACT_STORAGE
	static const char hex_digits[] = "0123456789abcdef";
	uint8_t bin[EF_BIN_MAX];
	char *hex = data;
	size_t i;

	if (len % 2 || len / 2 > sizeof(bin))
		return -2;
#endif

	path_len = snprintf(path, sizeof(path), "%s%s", ss_storage_get_path(), rel_path);
	if (path_len < 0 || (size_t)path_len >= sizeof(path))
		goto exit;

	f = ss_fopen(path, "r");
	if (!f) {
		rc = -1;
		goto exit;
	}

#ifdef CONFIG_COMPACT_STORAGE
	got = ss_fread(bin, 1, len / 2, f) * 2;
#else
	got = ss_fread(data, 1, len, f);
#endif
	ss_fclose(f);
	if (got != len)
		goto exit;

#ifdef CONFIG_COMPACT_STORAGE
	for (i = 0; i < len / 2; i++) {
		hex[2 * i] = hex_digits[bin[i] >> 4];
		hex[2 * i + 1] = hex_digits[bin[i] & 0x0f];
	}
#endif
	rc = 0;

exit:
#ifdef CONFIG_COMPACT_STORAGE
	ss_utils_memzero(bin, sizeof(bin)); /* it held a PIN code file */
#endif
	return rc;
}

/*! Write one EF inside storage
 *  \param[in] rel_path path of the EF relative to the storage root
 *  \param[in] mode "w" to replace the EF, "r+" to update it without truncating
 *  \param[in] offset offset to write at, in hex characters
 *  \param[in] data hex characters to write, stored as given with the hex backend.
 *  They are lower case, the format of the EFs: the parser normalizes every
 *  profile field, and the fixed values here are lower case.
 *  \param[in] len number of hex characters
 *  \returns 0 on success, -1 if the EF could not be opened, -2 if it was opened
 *  and not written whole */
static int write_ef(const char *rel_path, char *mode, long offset, const void *data, size_t len)
{
	char path[SS_STORAGE_PATH_MAX + 1];
	ss_FILE f;
	size_t wrote;
	int path_len;
	int rc = -2;
#ifdef CONFIG_COMPACT_STORAGE
	uint8_t bin[EF_BIN_MAX];
	const char *hex = data;
	size_t i;

	if (len % 2 || offset % 2 || len / 2 > sizeof(bin))
		return -2;
	for (i = 0; i < len / 2; i++)
		bin[i] = hex_to_uint8(&hex[2 * i]);
	data = bin;
	offset /= 2;
	len /= 2;
#endif

	path_len = snprintf(path, sizeof(path), "%s%s", ss_storage_get_path(), rel_path);
	if (path_len < 0 || (size_t)path_len >= sizeof(path))
		goto exit;

	f = ss_fopen(path, mode);
	if (!f) {
		rc = -1;
		goto exit;
	}

	if (offset != 0 && ss_fseek(f, offset, SEEK_SET) != 0) {
		ss_fclose(f);
		goto exit;
	}

	wrote = ss_fwrite(data, 1, len, f);

	if (ss_fclose(f) != 0 || wrote != len)
		goto exit;

	rc = 0;

exit:
#ifdef CONFIG_COMPACT_STORAGE
	ss_utils_memzero(bin, sizeof(bin)); /* it held key material */
#endif
	return rc;
}

/*! Put a PIN or PUK into one A003 record and clear the counter of failed attempts
 *  \param[in,out] a003 the PIN code file, A003_LEN hex characters
 *  \param[in] record record number, 0 to 2
 *  \param[in] value_offset PIN_OFFSET or PUK_OFFSET
 *  \param[in] tries_offset A003_TRIES_OFFSET or A003_UNBLOCK_TRIES_OFFSET
 *  \param[in] value PIN_SIZE hex characters */
static void a003_set_value(uint8_t *a003, size_t record, size_t value_offset, size_t tries_offset, const uint8_t *value)
{
	uint8_t *rec = &a003[record * A003_RECORD_SIZE];

	memcpy(&rec[value_offset], value, PIN_SIZE);
	memcpy(&rec[tries_offset], a003_no_tries, sizeof(a003_no_tries));
}

/* See in ss_provision.h */
int ss_profile_write_to_fs(const struct ss_profile *profile)
{
	uint8_t a001[A001_LEN];
	uint8_t a003[A003_LEN];
	uint8_t a004[A004_LEN];
	int rc = -1;

	/* KIC and KID are deliberately absent from the list. They are OTA keys
	 * (TS 102 225, TS 31.115) and a device that never receives a secured packet
	 * has no use for them.
	 * The four below are the ones that leave an unusable card when missing. */
	if (!ss_profile_has_required_tags(profile)) {
		SS_LOGP(SSTORAGE, LERROR, "profile carries no %s, refusing to provision it\n",
			!ss_profile_has_tag(profile, ICCID_TAG) ? "ICCID" :
			!ss_profile_has_tag(profile, IMSI_TAG)	? "IMSI" :
			!ss_profile_has_tag(profile, KI_TAG)	? "Ki" :
								  "OPc");
		return -1;
	}

	/* EF.IMSI is what onomondo_profile_check_provisioned() judges by, 
	 * set to the default first, written last. A provisioning
	 * that fails partway then leaves a card that reports as not provisioned */
	if (write_ef(IMSI_REL_PATH, "w", 0, default_imsi, IMSI_LEN) != 0)
		goto exit;

	if (write_ef(ICCID_REL_PATH, "w", 0, profile->iccid, ICCID_LEN) != 0)
		goto exit;

	/* A001: Ki | OPc | flag. Both keys are required above, so the EF is always
	 * built whole from the profile. */
	if ((profile->tags & A001_TAGS) == A001_TAGS) {
		memcpy(&a001[A001_KI_OFFSET], profile->ki, KEY_SIZE);
		memcpy(&a001[A001_OPC_OFFSET], profile->opc, KEY_SIZE);
		memcpy(&a001[A001_FLAG_OFFSET], a001_flag_opc, sizeof(a001_flag_opc));
		if (write_ef(A001_REL_PATH, "w", 0, a001, A001_LEN) != 0)
			goto exit;
	}

	/* A003, the PIN code file. It holds state the card maintains -- a PIN the user
	 * changed, the enabled flag, the retry and unblock counters -- so it is
	 * touched only when the profile carries a value for it, and then only the
	 * values the profile carries are patched into the stored file. A new value
	 * also clears its failed attempt counter, as those attempts were made against
	 * the old value; a PIN blocked before would otherwise stay blocked. Everything
	 * else -- enabled, max tries, pin_no, every value the profile does not name --
	 * stays as it is. */
	if (profile->tags & A003_TAGS) {
		int read_rc = read_ef(A003_REL_PATH, a003, A003_LEN);

		if (read_rc == -1) {
			SS_LOGP(SPIN, LINFO, "no PIN code file to update, keeping the card's PIN configuration\n");
		} else if (read_rc != 0) {
			goto exit;
		} else {
			if (ss_profile_has_tag(profile, PIN_1_TAG))
				a003_set_value(a003, 0, PIN_OFFSET, A003_TRIES_OFFSET, profile->pin1);
			if (ss_profile_has_tag(profile, PIN_2_TAG))
				a003_set_value(a003, 1, PIN_OFFSET, A003_TRIES_OFFSET, profile->pin2);
			if (ss_profile_has_tag(profile, PIN_ADM_TAG))
				a003_set_value(a003, 2, PIN_OFFSET, A003_TRIES_OFFSET, profile->adm);
			/* One PUK unblocks both PIN1 and PIN2; the ADM record has none. */
			if (ss_profile_has_tag(profile, PUK_TAG)) {
				a003_set_value(a003, 0, PUK_OFFSET, A003_UNBLOCK_TRIES_OFFSET, profile->puk);
				a003_set_value(a003, 1, PUK_OFFSET, A003_UNBLOCK_TRIES_OFFSET, profile->puk);
			}
			if (write_ef(A003_REL_PATH, "r+", 0, a003, A003_LEN) != 0)
				goto exit;
		}
	}

	/* A004, the OTA keys. A provisioning defines the OTA state: the EF starts
	 * erased, and only the keys the profile carries are set, each with its key
	 * indication. A profile without KIC and KID therefore disables OTA rather
	 * than leaving the template's keys usable. */
	memset(a004, 'f', A004_LEN);
	if (profile->tags & A004_TAGS) {
		memcpy(a004, a004_tar_msl, sizeof(a004_tar_msl));
		if (ss_profile_has_tag(profile, KIC_TAG)) {
			memcpy(&a004[sizeof(a004_tar_msl)], a004_key_ind, sizeof(a004_key_ind));
			memcpy(&a004[A004_KIC_OFFSET], profile->kic, KEY_SIZE);
		}
		if (ss_profile_has_tag(profile, KID_TAG)) {
			memcpy(&a004[sizeof(a004_tar_msl) + sizeof(a004_key_ind)], a004_key_ind, sizeof(a004_key_ind));
			memcpy(&a004[A004_KID_OFFSET], profile->kid, KEY_SIZE);
		}
	}
	if (write_ef(A004_REL_PATH, "w", 0, a004, A004_LEN) != 0)
		goto exit;

	/* EF.SMSP and the SMSC inside it are optional: a profile carrying neither
	 * keeps what the template shipped. */
	if (ss_profile_has_tag(profile, SMSP_TAG) && write_ef(SMSP_REL_PATH, "r+", 0, profile->smsp, SMSP_LEN) != 0)
		goto exit;

	if (ss_profile_has_tag(profile, SMSC_TAG) &&
	    write_ef(SMSP_REL_PATH, "r+", SMSC_OFFSET, profile->smsc, SMSC_LEN) != 0)
		goto exit;

	/* Last: only now does the card report as provisioned */
	if (write_ef(IMSI_REL_PATH, "w", 0, profile->imsi, IMSI_LEN) != 0)
		goto exit;

	rc = 0;

exit:
	/* The buffers held Ki, OPc, KIC, KID and the PINs */
	ss_utils_memzero(a001, sizeof(a001));
	ss_utils_memzero(a003, sizeof(a003));
	ss_utils_memzero(a004, sizeof(a004));
	return rc;
}

/*! Fill the profile that "00" provisions: the smallest one the writer accepts.
 *  Default IMSI, so the card reads as not provisioned; ICCID, Ki and OPc zeroed.
 *  With no KIC or KID the writer erases A004, and with no PIN or SMSP tags it
 *  leaves A003 and EF.SMSP alone. The fields are hex characters, so they are
 *  filled with '0', not with byte 0.
 *  \param[out] profile the profile to fill */
static void set_unbind_profile(struct ss_profile *profile)
{
	memset(profile, 0, sizeof *profile);
	memcpy(profile->imsi, default_imsi, IMSI_LEN);
	memset(profile->iccid, '0', ICCID_LEN);
	memset(profile->ki, '0', KEY_SIZE);
	memset(profile->opc, '0', KEY_SIZE);
	profile->tags = SS_TAG_BIT(IMSI_TAG) | SS_TAG_BIT(ICCID_TAG) | SS_TAG_BIT(KI_TAG) | SS_TAG_BIT(OPC_TAG);
}

/* See in ss_provision.h */
int onomondo_profile_unbind(void)
{
	struct ss_profile *profile = SS_ALLOC(*profile);
	int rc;

	if (!profile)
		return -1;

	set_unbind_profile(profile);
	rc = ss_profile_write_to_fs(profile);

	ss_profile_wipe(profile);
	SS_FREE(profile);
	return rc;
}

/*! Provision a SoftSIM profile from e.g. an AT command string
 *  \param[in] profile Profile string as received from AT command, or "00" to
 *  unbind the card (see onomondo_profile_unbind())
 *  \returns 0 on success */
int onomondo_profile_provisioning(const char *at_profile)
{
	struct ss_profile *profile;
	size_t input_string_size;
	int rc;

	if (!at_profile)
		return -1;

	input_string_size = strlen(at_profile);
	if (ss_profile_is_unbind(at_profile, input_string_size))
		return onomondo_profile_unbind();

	profile = SS_ALLOC(*profile);
	if (!profile)
		return -1;

	if (input_string_size > UINT16_MAX) {
		rc = -1;
		goto exit;
	}

	rc = ss_profile_from_string((uint16_t)input_string_size, at_profile, profile);
	if (rc != 0)
		goto exit;

	rc = ss_profile_write_to_fs(profile);

exit:
	/* The struct holds Ki, OPc and the OTA keys; scrub before the allocator
	 * reuses the memory. */
	ss_profile_wipe(profile);
	SS_FREE(profile);
	return rc;
}

/*! Check whether a SoftSIM profile is provisioned
 *  A card counts as provisioned only while EF.IMSI holds a real subscriber
 *  \returns 1 if provisioned, 0 otherwise */
int onomondo_profile_check_provisioned(void)
{
	char imsi[IMSI_LEN];
	bool zeroed = true;
	size_t i;

	if (read_ef(IMSI_REL_PATH, imsi, IMSI_LEN) != 0)
		return 0;

	for (i = 0; i < IMSI_LEN; i++) {
		if (!isxdigit((unsigned char)imsi[i]))
			return 0;
		if (imsi[i] != '0')
			zeroed = false;
	}
	if (zeroed)
		return 0;

	for (i = 0; i < IMSI_LEN; i++) {
		if (tolower((unsigned char)imsi[i]) != default_imsi[i])
			return 1;
	}
	return 0;
}
