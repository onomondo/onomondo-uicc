/*
 * Copyright (c) 2024 Onomondo ApS. All rights reserved.
 *
 * SPDX-License-Identifier: GPL-3.0-only
 * 
 * Author: Benjamin Bruun
 */

#include <assert.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <onomondo/softsim/storage.h>
#include <onomondo/softsim/fs.h>
#include <onomondo/softsim/utils.h>
#include <onomondo/utils/ss_profile.h>
#include <onomondo/utils/ss_provision.h>

char path[SS_STORAGE_PATH_MAX + 1];
const char *storage;

static bool tear_a003_write;

/* fs.c declares the storage entry points weak, so this stands in for one and
 * cuts a single write short on request. The PIN code file is the only EF written
 * A003_LEN bytes at a time, which is what picks it out. */
size_t ss_fwrite(const void *ptr, size_t size, size_t count, ss_FILE f)
{
	if (tear_a003_write && size == 1 && count == A003_LEN) {
		tear_a003_write = false;
		count /= 2;
	}

	return fwrite(ptr, size, count, (FILE *)f);
}

/* Reuse the same profile used by profile_decode_test */
static const char *decrypted_profile_smsp_ok =
	"01"
	"12"
	"080910101032540636"
	"02"
	"14"
	"98001032547698103214"
	"03"
	"20"
	"00000000000000000000000000000000"
	"04"
	"20"
	"000102030405060708090A0B0C0D0E0F"
	"05"
	"20"
	"000102030405060708090A0B0C0D0E0F"
	"06"
	"20"
	"000102030405060708090A0B0C0D0E0F"
	"07"
	"68"
	"ffffffffffffffffffffffffffffffffffffffffffffffffe5ffffffffffffffffffffffff07911226540092f6ffffffffff00a8";

static const char *decrypted_profile_smsc_ok = "01"
					       "12"
					       "080910101032540636"
					       "02"
					       "14"
					       "98001032547698103214"
					       "03"
					       "20"
					       "00000000000000000000000000000000"
					       "04"
					       "20"
					       "000102030405060708090A0B0C0D0E0F"
					       "05"
					       "20"
					       "000102030405060708090A0B0C0D0E0F"
					       "06"
					       "20"
					       "000102030405060708090A0B0C0D0E0F"
					       "0c"
					       "18"
					       "0791448889078484ffffffff";

static const char *decrypted_profile_smsp_smsc_ok =
	"01"
	"12"
	"080910101032540636"
	"02"
	"14"
	"98001032547698103214"
	"03"
	"20"
	"00000000000000000000000000000000"
	"04"
	"20"
	"000102030405060708090A0B0C0D0E0F"
	"05"
	"20"
	"000102030405060708090A0B0C0D0E0F"
	"06"
	"20"
	"000102030405060708090A0B0C0D0E0F"
	"07"
	"68"
	"ffffffffffffffffff2ffffffffffffffff4ffffffffffffe5ffffffffffffffffffffffff07911226540092f6ffffffffff00a8"
	"0c"
	"18"
	"0791448889078484ffffffff";

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
	int rc;

	printf("TEST: Provision a SoftSIM profile with SMSP content\n");

	rc = onomondo_profile_provisioning(decrypted_profile_smsp_ok);

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
	int rc;

	printf("TEST: Provision a SoftSIM profile with SMSC content\n");

	rc = onomondo_profile_provisioning(decrypted_profile_smsc_ok);

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
	int rc;

	printf("TEST: Provision a SoftSIM profile with SMSP and SMSC content\n");

	/* test that both SMSP and SMSC are provisioned correctly.
     * we will see SMSP provisoned first, and SMSC update the content of SMSP second. */
	rc = onomondo_profile_provisioning(decrypted_profile_smsp_smsc_ok);

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

/* PIN 6868, PUK 79797979 and the 16 character ADM 8034270253113864, each as the
 * hex encoded ASCII the profile carries. */
static const char *decrypted_profile_pins_ok = "01"
					       "12"
					       "080910101032540636"
					       "02"
					       "14"
					       "98001032547698103214"
					       "03"
					       "20"
					       "00000000000000000000000000000000"
					       "04"
					       "20"
					       "000102030405060708090A0B0C0D0E0F"
					       "05"
					       "20"
					       "000102030405060708090A0B0C0D0E0F"
					       "06"
					       "20"
					       "000102030405060708090A0B0C0D0E0F"
					       "08"
					       "08"
					       "36383638"
					       "0b"
					       "10"
					       "3739373937393739"
					       "0a"
					       "20"
					       "38303334323730323533313133383634";

static const char *a003_file_shipped = "0003000a000131323334ffffffff3132333435363738"
				       "0003000a008131323334ffffffff3132333435363738"
				       "01030000000a31323334ffffffffffffffffffffffff";
static const char *a003_file_provisioned = "0003000a000136383638ffffffff3739373937393739"
					   "0003000a008131323334ffffffff3739373937393739"
					   "01030000000a8034270253113864ffffffffffffffff";

static int read_ef(const char *rel_path, char *buf, size_t len)
{
	char ef_path[SS_STORAGE_PATH_MAX + 1];
	ss_FILE f;
	size_t got;

	snprintf(ef_path, sizeof(ef_path), "%s%s", ss_storage_get_path(), rel_path);
	f = ss_fopen(ef_path, "r");
	if (!f)
		return -1;

	got = ss_fread(buf, 1, len, f);
	ss_fclose(f);

	return got == len ? 0 : -1;
}

static void restore_ef(const char *rel_path, const char *content, size_t len)
{
	char ef_path[SS_STORAGE_PATH_MAX + 1];
	ss_FILE f;

	snprintf(ef_path, sizeof(ef_path), "%s%s", ss_storage_get_path(), rel_path);
	f = ss_fopen(ef_path, "w");
	if (!f) {
		printf("Warning: failed to reopen %s for restore\n", ef_path);
		return;
	}

	ss_fwrite(content, 1, len, f);
	ss_fclose(f);
}

/* A profile carrying PIN, PUK and ADM values puts all three into the PIN code
 * file. The PIN2 record keeps its default PIN, since this profile carries no
 * PIN2 tag, but takes the PUK. */
static void provision_profile_pins_test_ok()
{
	char a003[A003_LEN];
	int rc;

	printf("TEST: Provision a SoftSIM profile with PIN, PUK and ADM content\n");

	rc = onomondo_profile_provisioning(decrypted_profile_pins_ok);
	printf("Provisioning return value: %d\n", rc);
	assert(rc == 0);

	rc = read_ef("/3f00/a003", a003, sizeof(a003));
	assert(rc == 0);
	printf("PIN code file: %.*s\n", A003_LEN, a003);
	assert(memcmp(a003, a003_file_provisioned, A003_LEN) == 0);

	restore_ef("/3f00/a003", a003_file_shipped, A003_LEN);
}

/* A profile without PIN tags has nothing to say about the PIN code file, so the
 * file must come out unchanged. */
static void provision_profile_no_pins_test_ok()
{
	char a003[A003_LEN];
	int rc;

	printf("TEST: Provision a SoftSIM profile without PIN content\n");

	rc = onomondo_profile_provisioning(decrypted_profile_smsp_ok);
	printf("Provisioning return value: %d\n", rc);
	assert(rc == 0);

	rc = read_ef("/3f00/a003", a003, sizeof(a003));
	assert(rc == 0);
	assert(memcmp(a003, a003_file_shipped, A003_LEN) == 0);
	printf("PIN code file unchanged\n");
}

/* The PIN code file holds state the card maintains, not only what a profile put
 * there: a PIN the user changed, the retry counter a failed VERIFY decremented.
 * A profile that carries no PIN value must leave all of it alone. */
static void provision_profile_keeps_live_pin_state_test()
{
	/* Record layout is struct pin_context (uicc_pin.c): enabled, max_tries,
	 * tries, max_unblock_tries, unblock_tries, pin_no, PIN[8], PUK[8]. This is
	 * record 1 with the PIN changed to 5678 and two tries spent. */
	static const char *a003_file_in_use = "0003020a000135363738ffffffff3132333435363738"
					      "0003000a008131323334ffffffff3132333435363738"
					      "01030000000a31323334ffffffffffffffffffffffff";
	char a003[A003_LEN];
	int rc;

	printf("TEST: Provision a SoftSIM profile without PIN content over a card in use\n");

	restore_ef("/3f00/a003", a003_file_in_use, A003_LEN);

	rc = onomondo_profile_provisioning(decrypted_profile_smsp_ok);
	printf("Provisioning return value: %d\n", rc);
	assert(rc == 0);

	rc = read_ef("/3f00/a003", a003, sizeof(a003));
	assert(rc == 0);
	assert(memcmp(a003, a003_file_in_use, A003_LEN) == 0);
	printf("PIN code file left as the card had it\n");

	restore_ef("/3f00/a003", a003_file_shipped, A003_LEN);
}

/* An EF that was opened and then not written whole is torn, which is a different
 * answer than a template that never shipped the file. */
static void provision_profile_torn_a003_write_test()
{
	int rc;

	printf("TEST: Provision a SoftSIM profile when the PIN code file write is cut short\n");

	tear_a003_write = true;
	rc = onomondo_profile_provisioning(decrypted_profile_pins_ok);
	printf("Provisioning return value: %d\n", rc);
	assert(rc != 0);
	tear_a003_write = false;

	restore_ef("/3f00/a003", a003_file_shipped, A003_LEN);
}

/* The PIN code file is updated, not replaced: a record this format does not
 * describe must survive provisioning. */
static void provision_profile_keeps_extra_a003_records_test()
{
	char extended[A003_LEN + A003_RECORD_SIZE];
	char readback[A003_LEN + A003_RECORD_SIZE];
	int rc;

	printf("TEST: Provision a SoftSIM profile over a PIN code file with an extra record\n");

	memcpy(extended, a003_file_shipped, A003_LEN);
	memset(&extended[A003_LEN], 'a', A003_RECORD_SIZE);
	restore_ef("/3f00/a003", extended, sizeof(extended));

	rc = onomondo_profile_provisioning(decrypted_profile_pins_ok);
	printf("Provisioning return value: %d\n", rc);
	assert(rc == 0);

	rc = read_ef("/3f00/a003", readback, sizeof(readback));
	assert(rc == 0);
	assert(memcmp(readback, a003_file_provisioned, A003_LEN) == 0);
	assert(memcmp(&readback[A003_LEN], &extended[A003_LEN], A003_RECORD_SIZE) == 0);
	printf("Extra record preserved\n");

	restore_ef("/3f00/a003", a003_file_shipped, A003_LEN);
}

/* No Ki tag, so nothing may be written at all. KIC and KID are absent too, which
 * on its own is a profile the provisioner accepts: they are OTA keys. */
static const char *decrypted_profile_no_keys = "01"
					       "12"
					       "080910101032540636"
					       "02"
					       "14"
					       "98001032547698103214"
					       "03"
					       "20"
					       "00000000000000000000000000000000";

/* An incomplete profile is refused before the first EF is written, rather than
 * writing NUL over the key material and reporting success. */
static void provision_profile_missing_tag_test()
{
	/* A001 holds the Ki this profile omits, so it is the file at risk. Snapshot it
	 * rather than comparing against the shipped template: the tests above have
	 * already provisioned over it. */
	char a001_before[A001_LEN], a001_after[A001_LEN];
	int rc;

	printf("TEST: Provision a SoftSIM profile that is missing its Ki\n");

	rc = read_ef("/3f00/a001", a001_before, sizeof(a001_before));
	assert(rc == 0);

	rc = onomondo_profile_provisioning(decrypted_profile_no_keys);
	printf("Provisioning return value: %d\n", rc);
	assert(rc != 0);

	rc = read_ef("/3f00/a001", a001_after, sizeof(a001_after));
	assert(rc == 0);
	assert(memcmp(a001_before, a001_after, A001_LEN) == 0);
	printf("Key material untouched\n");
}

/* KIC and KID are OTA keys, so a profile without them provisions normally. */
static const char *decrypted_profile_no_ota_keys = "01"
						   "12"
						   "080910101032540636"
						   "02"
						   "14"
						   "98001032547698103214"
						   "03"
						   "20"
						   "00000000000000000000000000000000"
						   "04"
						   "20"
						   "000102030405060708090A0B0C0D0E0F";

static void provision_profile_without_ota_keys_test()
{
	char a004[A004_LEN], expect[A004_LEN];
	int rc;

	printf("TEST: Provision a SoftSIM profile that carries no KIC or KID\n");

	rc = onomondo_profile_provisioning(decrypted_profile_no_ota_keys);
	printf("Provisioning return value: %d\n", rc);
	assert(rc == 0);

	/* The key area comes out NUL, which truncates the record when it is read
	 * back, so remote commands are rejected rather than verified against a key
	 * the profile never carried. */
	memcpy(expect, "b00011060101", A004_HEADER_SIZE);
	memset(&expect[A004_HEADER_SIZE], 0, 2 * KEY_SIZE);
	memset(&expect[A004_HEADER_SIZE + 2 * KEY_SIZE], 'f', A004_LEN - A004_HEADER_SIZE - 2 * KEY_SIZE);
	rc = read_ef("/3f00/a004", a004, sizeof(a004));
	assert(rc == 0);
	assert(memcmp(a004, expect, A004_LEN) == 0);
	printf("OTA key area left unusable\n");
}

/* The PIN code file is optional: a reduced template need not ship it, and the
 * rest of the profile must still be provisioned. */
static void provision_profile_without_a003_test()
{
	char a003_path[SS_STORAGE_PATH_MAX + 1];
	int rc;

	printf("TEST: Provision a SoftSIM profile into a storage tree with no PIN code file\n");

	snprintf(a003_path, sizeof(a003_path), "%s%s", ss_storage_get_path(), "/3f00/a003");
	rc = remove(a003_path);
	assert(rc == 0);

	rc = onomondo_profile_provisioning(decrypted_profile_pins_ok);
	printf("Provisioning return value: %d\n", rc);
	assert(rc == 0);

	restore_ef("/3f00/a003", a003_file_shipped, A003_LEN);
}

/* A storage tree that cannot be opened must be reported, not written through. */
static void provision_profile_bad_storage_test()
{
	char saved[SS_STORAGE_PATH_MAX];
	int rc;

	printf("TEST: Provision a SoftSIM profile into a storage path that does not exist\n");

	snprintf(saved, sizeof(saved), "%s", ss_storage_get_path());
	rc = ss_storage_set_path("./no-such-storage");
	assert(rc == 0);

	rc = onomondo_profile_provisioning(decrypted_profile_smsp_ok);
	printf("Provisioning return value: %d\n", rc);
	assert(rc != 0);

	rc = ss_storage_set_path(saved);
	assert(rc == 0);
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
	provision_profile_pins_test_ok();
	provision_profile_no_pins_test_ok();
	provision_profile_keeps_live_pin_state_test();
	provision_profile_torn_a003_write_test();
	provision_profile_keeps_extra_a003_records_test();
	provision_profile_without_a003_test();
	provision_profile_missing_tag_test();
	provision_profile_without_ota_keys_test();
	provision_profile_bad_storage_test();
	return 0;
}
