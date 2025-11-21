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

/* Reuse the same profile used by profile_decode_test */
static const char *decrypted_profile_ok =
    "01" "12" "080910101032540636"
    "02" "14" "98001032547698103214"
    "03" "20" "00000000000000000000000000000000"
    "04" "20" "000102030405060708090A0B0C0D0E0F"
    "05" "20" "000102030405060708090A0B0C0D0E0F"
    "06" "20" "000102030405060708090A0B0C0D0E0F"
    "07" "68" "ffffffffffffffffffffffffffffffffffffffffffffffffe5ffffffffffffffffffffffff07911226540092f6ffffffffff00a8";

static const char *smsp_file_6f42_original =
    "ffffffffffffffffffffffffffffffffffffffffffffffffe5ffffffffffffffffffffffff0791447779078484ffffffffff00a8ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
static const char *smsp_file_6f42_updated =
    "ffffffffffffffffffffffffffffffffffffffffffffffffe5ffffffffffffffffffffffff07911226540092f6ffffffffff00a8ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";

int main(void)
{
    /* Provision (write) the profile to storage using production code */
    int rc = onomondo_profile_provisioning(decrypted_profile_ok);

    /* Build path to EF 6F42 and read back the content */
    char path[SS_STORAGE_PATH_MAX + 1];
    const char *storage = ss_storage_get_path();
    snprintf(path, sizeof(path), "%s%s", storage, "/3f00/7ff0/6f42");

    ss_FILE f = ss_fopen(path, "r");

    char hexbuf[SMSP_RECORD_SIZE * 2 + 1];
    memset(hexbuf, 0, sizeof(hexbuf));
    size_t got = ss_fread(hexbuf, 1, SMSP_RECORD_SIZE * 2, f);
    ss_fclose(f);

    uint8_t actual_smsp[SMSP_RECORD_SIZE];
    memset(actual_smsp, 0, sizeof(actual_smsp));
    if (strncmp(hexbuf, smsp_file_6f42_updated, SMSP_RECORD_SIZE * 2) != 0) {
        printf("SMSP mismatch: expected (hex) %s\n", smsp_file_6f42_updated);
        printf("Got: %s\n", hexbuf);
        return 1;
    }

    printf("Successfully provisioned and validated SMSP (6F42)\n");
    return 0;
}