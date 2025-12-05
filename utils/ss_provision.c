/*
 * Copyright (c) 2024 Onomondo ApS. All rights reserved.
 *
 * SPDX-License-Identifier: GPL-3.0-only
 * 
 * Author: Onomondo ApS
 */

#include <stdio.h>
#include <string.h>
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
static const char *A004_REL_PATH = PATH_SEPARATOR "3f00" PATH_SEPARATOR "a004";
static const char *SMSP_REL_PATH = PATH_SEPARATOR "3f00" PATH_SEPARATOR "7ff0" PATH_SEPARATOR "6f42";

/*! Write the decoded profile to the SoftSIM filesystem
 *  \param[in] profile Pointer to the decoded SoftSIM profile
 *  \returns 0 on success, -1 on failure */
static int write_profile_to_fs(const struct ss_profile *profile)
{
    size_t wrote = 0;
    ss_FILE f = NULL;
    char path[SS_STORAGE_PATH_MAX + 1];
    const char *storage = ss_storage_get_path();

    /* write ICCID */
    snprintf(path, sizeof(path), "%s%s", storage, ICCID_REL_PATH);
    f = ss_fopen(path, "w");
    wrote = ss_fwrite(profile->_3F00_2FE2, 1, ICCID_LEN, f);
    ss_fclose(f);
    if (wrote == 0 || wrote != ICCID_LEN)
        goto exit;

    /* write IMSI */
    snprintf(path, sizeof(path), "%s%s", storage, IMSI_REL_PATH);
    f = ss_fopen(path, "w");
    wrote = ss_fwrite(profile->_3F00_7ff0_6f07, 1, IMSI_LEN, f);
    ss_fclose(f);
    if (wrote == 0 || wrote != IMSI_LEN)
        goto exit;

    /* write A001 */
    snprintf(path, sizeof(path), "%s%s", storage, A001_REL_PATH);
    f = ss_fopen(path, "w");
    wrote = ss_fwrite(profile->_3F00_A001, 1, A001_LEN, f);
    ss_fclose(f);
    if (wrote == 0 || wrote != A001_LEN)
        goto exit;

    /* write A004 */
    snprintf(path, sizeof(path), "%s%s", storage, A004_REL_PATH);
    f = ss_fopen(path, "w");
    wrote = ss_fwrite(profile->_3F00_A004, 1, A004_LEN, f);
    ss_fclose(f);
    if (wrote == 0 || wrote != A004_LEN)
        goto exit;

    /* write EF.SMSP */
    uint8_t zeros[SMSP_RECORD_SIZE * 2] = {0};
    if (memcmp(profile->SMSP, zeros, (SMSP_RECORD_SIZE * 2)) != 0) {
        snprintf(path, sizeof(path), "%s%s", storage, SMSP_REL_PATH);
        f = ss_fopen(path, "r+"); /* open for update without truncation */
        wrote = ss_fwrite(profile->SMSP, 1, (SMSP_RECORD_SIZE * 2), f);
        ss_fclose(f);
        if (wrote == 0 || wrote != (SMSP_RECORD_SIZE * 2))
            goto exit;
    }

    return 0;

exit:
    return -1;
} 

/*! Provision a SoftSIM profile from e.g. an AT command string
 *  \param[in] profile Profile string as received from AT command
 *  \returns 0 on success */
int onomondo_profile_provisioning(const char *at_profile)
{
    struct ss_profile *profile = SS_ALLOC(*profile);
    memset(profile, 0, sizeof *profile);

    /* Validate the size of the profile hiding in the FS */
    uint16_t input_string_size = strlen(at_profile);

    int rc = ss_profile_from_string(input_string_size, at_profile, profile);
    if (rc != 0)
        goto exit;

    rc = write_profile_to_fs(profile);
    if (rc != 0)
        goto exit;

exit:
    SS_FREE(profile);
    return rc;
}
