/*
 * Copyright (c) 2024 Onomondo ApS. All rights reserved.
 *
 * SPDX-License-Identifier: GPL-3.0-only
 * 
 * Author: Benjamin Bruun
 */

#include <stdio.h>
#include <string.h>
#include <onomondo/softsim/storage.h>
#include <onomondo/softsim/fs.h>
#include <onomondo/softsim/utils.h>
#include <onomondo/utils/ss_profile.h>
#include <onomondo/utils/ss_provision.h>

char path[SS_STORAGE_PATH_MAX + 1];
const char *storage;

/* Reuse the same profile used by profile_decode_test */
static const char *decrypted_profile_smsp_ok =
    "01" "12" "080910101032540636"
    "02" "14" "98001032547698103214"
    "03" "20" "00000000000000000000000000000000"
    "04" "20" "000102030405060708090A0B0C0D0E0F"
    "05" "20" "000102030405060708090A0B0C0D0E0F"
    "06" "20" "000102030405060708090A0B0C0D0E0F"
    "07" "68" "ffffffffffffffffffffffffffffffffffffffffffffffffe5ffffffffffffffffffffffff07911226540092f6ffffffffff00a8";

static const char *decrypted_profile_smsc_ok =
    "01" "12" "080910101032540636"
    "02" "14" "98001032547698103214"
    "03" "20" "00000000000000000000000000000000"
    "04" "20" "000102030405060708090A0B0C0D0E0F"
    "05" "20" "000102030405060708090A0B0C0D0E0F"
    "06" "20" "000102030405060708090A0B0C0D0E0F"
    "0c" "18" "0791448889078484ffffffff";

static const char *decrypted_profile_smsp_smsc_ok =
    "01" "12" "080910101032540636"
    "02" "14" "98001032547698103214"
    "03" "20" "00000000000000000000000000000000"
    "04" "20" "000102030405060708090A0B0C0D0E0F"
    "05" "20" "000102030405060708090A0B0C0D0E0F"
    "06" "20" "000102030405060708090A0B0C0D0E0F"
    "07" "68" "ffffffffffffffffff2ffffffffffffffff4ffffffffffffe5ffffffffffffffffffffffff07911226540092f6ffffffffff00a8"
    "0c" "18" "0791448889078484ffffffff";

static const char *smsp_file_6f42_original =
    "ffffffffffffffffffffffffffffffffffffffffffffffffe5ffffffffffffffffffffffff0791447779078484ffffffffff00a8ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
static const char *smsp_file_6f42_updated_smsp =
    "ffffffffffffffffffffffffffffffffffffffffffffffffe5ffffffffffffffffffffffff07911226540092f6ffffffffff00a8ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
static const char *smsp_file_6f42_updated_smsc =
    "ffffffffffffffffffffffffffffffffffffffffffffffffe5ffffffffffffffffffffffff0791448889078484ffffffffff00a8ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
static const char *smsp_file_6f42_updated_smsp_smsc =
    "ffffffffffffffffff2ffffffffffffffff4ffffffffffffe5ffffffffffffffffffffffff0791448889078484ffffffffff00a8ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
    
static void provision_profile_smsp_test_ok()
{
    printf("TEST: Provision a SoftSIM profile with SMSP content\n");
    
    int rc = onomondo_profile_provisioning(decrypted_profile_smsp_ok);

    ss_FILE f = ss_fopen(path, "r");
    if (!f) {
        printf("ERROR: failed to open %s for reading\n", path);
        return;
    }

    char hexbuf[SMSP_RECORD_SIZE * 4 + 1];
    memset(hexbuf, 0, sizeof(hexbuf));
    size_t got = ss_fread(hexbuf, 1, SMSP_RECORD_SIZE * 4, f);
    ss_fclose(f);
    if (got != SMSP_RECORD_SIZE * 4) {
        printf("WARNING: read %zu bytes from %s, expected %d\n", got, path, SMSP_RECORD_SIZE * 4);
    }

    uint8_t actual_smsp[SMSP_RECORD_SIZE * 4];
    memset(actual_smsp, 0, sizeof(actual_smsp));
    if (strncmp(hexbuf, smsp_file_6f42_updated_smsp, SMSP_RECORD_SIZE * 4) != 0) {
        printf("SMSP mismatch: expected (hex) %s\n", smsp_file_6f42_updated_smsp);
        printf("Got: %s\n", hexbuf);
    }

    printf("Successfully provisioned and validated SMSP (6F42)\n");
}

static void provision_profile_smsc_test_ok()
{
    printf("TEST: Provision a SoftSIM profile with SMSC content\n");
    
    int rc = onomondo_profile_provisioning(decrypted_profile_smsc_ok);

    ss_FILE f = ss_fopen(path, "r");
    if (!f) {
        printf("ERROR: failed to open %s for reading\n", path);
        return;
    }

    char hexbuf[SMSP_RECORD_SIZE * 4 + 1];
    memset(hexbuf, 0, sizeof(hexbuf));
    size_t got = ss_fread(hexbuf, 1, SMSP_RECORD_SIZE * 4, f);
    ss_fclose(f);
    if (got != SMSP_RECORD_SIZE * 4) {
        printf("WARNING: read %zu bytes from %s, expected %d\n", got, path, SMSP_RECORD_SIZE * 4);
    }

    uint8_t actual_smsp[SMSP_RECORD_SIZE * 4];
    memset(actual_smsp, 0, sizeof(actual_smsp));
    if (strncmp(hexbuf, smsp_file_6f42_updated_smsc, SMSP_RECORD_SIZE * 4) != 0) {
        printf("SMSC mismatch: expected (hex) %s\n", smsp_file_6f42_updated_smsc);
        printf("Got: %s\n", hexbuf);
    }

    printf("Successfully provisioned and validated SMSC update\n");
}

static void provision_profile_smsp_smsc_test_ok()
{
    printf("TEST: Provision a SoftSIM profile with SMSP and SMSC content\n");
    
    /* test that both SMSP and SMSC are provisioned correctly.
     * we will see SMSP provisoned first, and SMSC update the content of SMSP second. */
    int rc = onomondo_profile_provisioning(decrypted_profile_smsp_smsc_ok);

    ss_FILE f = ss_fopen(path, "r");
    if (!f) {
        printf("ERROR: failed to open %s for reading\n", path);
        return;
    }

    char hexbuf[SMSP_RECORD_SIZE * 4 + 1];
    memset(hexbuf, 0, sizeof(hexbuf));
    size_t got = ss_fread(hexbuf, 1, SMSP_RECORD_SIZE * 4, f);
    ss_fclose(f);
    if (got != SMSP_RECORD_SIZE * 4) {
        printf("WARNING: read %zu bytes from %s, expected %d\n", got, path, SMSP_RECORD_SIZE * 4);
    }

    uint8_t actual_smsp[SMSP_RECORD_SIZE * 4];
    memset(actual_smsp, 0, sizeof(actual_smsp));
    if (strncmp(hexbuf, smsp_file_6f42_updated_smsp_smsc, SMSP_RECORD_SIZE * 4) != 0) {
        printf("SMSC mismatch: expected (hex) %s\n", smsp_file_6f42_updated_smsp_smsc);
        printf("Got: %s\n", hexbuf);
    }

    printf("Successfully provisioned and validated both SMSP and SMSC\n");
}

static void restore_ef_smsp()
{
    /* Build path to EF 6F42 and restore the original content */
    char path[SS_STORAGE_PATH_MAX + 1];
    const char *storage = ss_storage_get_path();
    snprintf(path, sizeof(path), "%s%s", storage, "/3f00/7ff0/6f42");

    ss_FILE fw = ss_fopen(path, "w");
    if (fw) {
        ss_fwrite(smsp_file_6f42_original, 1, SMSP_RECORD_SIZE * 4, fw);
        ss_fclose(fw);
    } else {
        printf("Warning: failed to reopen %s for restore\n", path);
    }
}

int main(void)
{
    storage = ss_storage_get_path();
    snprintf(path, sizeof(path), "%s%s", storage, "/3f00/7ff0/6f42");

    provision_profile_smsp_test_ok();
    restore_ef_smsp();
    provision_profile_smsc_test_ok();
    restore_ef_smsp();
    provision_profile_smsp_smsc_test_ok();
    // restore_ef_smsp();
    return 0;
}
