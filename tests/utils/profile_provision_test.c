/*
 * Copyright (c) 2024 Onomondo ApS. All rights reserved.
 *
 * SPDX-License-Identifier: GPL-3.0-only
 *
 * Author: Benjamin Bruun
 */

/* Profile provisioning, run against every storage layout.
 *
 * This file is built once per layout:
 *  - the default storage, which keeps every EF as the hex text it spells, or
 *    with CONFIG_COMPACT_STORAGE, as the bytes;
 *  - EFs in a directory tree (3f00/7ff0/6f07), or with CONFIG_ALT_FILE_SEPARATOR
 *    as flat files in one directory (_3f00_7ff0_6f07).
 * The test itself speaks hex throughout -- EF contents, offsets and lengths are
 * those of the hex form -- and only the EF helpers below know how the backend
 * stores them. Every build prints the same output and is compared against the
 * same .ok file, so a case can not be covered for one layout and forgotten for
 * another.
 *
 * Each build runs on its own copy of the files/ template tree. The template is
 * read from it before the first test, and every test starts by writing the EFs
 * provisioning touches back, in the layout under test. */

#include <assert.h>
#include <ctype.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include <onomondo/softsim/storage.h>
#include <onomondo/softsim/fs.h>
#include <onomondo/softsim/utils.h>
#include <onomondo/utils/ss_profile.h>
#include <onomondo/utils/ss_provision.h>

/* Bytes the backend stores for an EF of hex_len hex characters */
#ifdef CONFIG_COMPACT_STORAGE
#define EF_SIZE(hex_len) ((hex_len) / 2)
#else
#define EF_SIZE(hex_len) (hex_len)
#endif

/* The largest EF this test reads, in hex characters */
#define EF_HEX_MAX 512

/* The template tree, as the build copies files/: directories, hex */
#define TEMPLATE_ROOT "./files"

/* Where provisioning writes. The flat layout keeps every EF in one directory. */
#ifdef CONFIG_ALT_FILE_SEPARATOR
#define STORAGE_ROOT "./flat/"
#else
#define STORAGE_ROOT TEMPLATE_ROOT
#endif

/* EF paths relative to the storage root, in the layout under test */
#define SEP PATH_SEPARATOR
#define ICCID_EF SEP "3f00" SEP "2fe2"
#define IMSI_EF SEP "3f00" SEP "7ff0" SEP "6f07"
#define A001_EF SEP "3f00" SEP "a001"
#define A003_EF SEP "3f00" SEP "a003"
#define A004_EF SEP "3f00" SEP "a004"
#define SMSP_EF SEP "3f00" SEP "7ff0" SEP "6f42"

/* EF.SMSP as the template ships it: two records */
#define SMSP_EF_LEN (2 * SMSP_LEN)

static bool tear_a003_write;

/* fs.c declares the storage entry points weak, so this stands in for one and
 * cuts a single write short on request. The PIN code file is the only EF written
 * whole in one call of its size, which is what picks it out. */
size_t ss_fwrite(const void *ptr, size_t size, size_t count, ss_FILE f)
{
	if (tear_a003_write && size == 1 && count == EF_SIZE(A003_LEN)) {
		tear_a003_write = false;
		count /= 2;
	}

	return fwrite(ptr, size, count, (FILE *)f);
}

/* ---------------------------------------------------------------------------
 * EF helpers: hex in and out, whatever the backend stores
 * ------------------------------------------------------------------------- */

static void ef_path(char *buf, size_t len, const char *rel_path)
{
	int n = snprintf(buf, len, "%s%s", ss_storage_get_path(), rel_path);

	assert(n > 0 && (size_t)n < len);
}

static uint8_t hex_pair(const char *hex)
{
	unsigned int b;
	char pair[3] = { hex[0], hex[1], 0 };

	assert(isxdigit((unsigned char)hex[0]) && isxdigit((unsigned char)hex[1]));
	sscanf(pair, "%2x", &b);
	return (uint8_t)b;
}

/* Size of the EF in hex characters, or -1 if it is missing */
static int ef_len(const char *rel_path)
{
	char path[SS_STORAGE_PATH_MAX + 1];
	int size;

	ef_path(path, sizeof(path), rel_path);
	size = ss_file_size(path);
	if (size < 0)
		return -1;
#ifdef CONFIG_COMPACT_STORAGE
	return size * 2;
#else
	return size;
#endif
}

/* Read the first hex_len hex characters of an EF, in lower case.
 * \returns 0 on success, -1 if the EF is missing or shorter */
static int read_ef(const char *rel_path, char *hex, size_t hex_len)
{
	char path[SS_STORAGE_PATH_MAX + 1];
	uint8_t raw[EF_HEX_MAX];
	size_t want = EF_SIZE(hex_len), got, i;
	ss_FILE f;

	assert(want <= sizeof(raw));
	ef_path(path, sizeof(path), rel_path);
	f = ss_fopen(path, "r");
	if (!f)
		return -1;
	got = ss_fread(raw, 1, want, f);
	ss_fclose(f);
	if (got != want)
		return -1;

#ifdef CONFIG_COMPACT_STORAGE
	static const char digits[] = "0123456789abcdef";

	for (i = 0; i < want; i++) {
		hex[2 * i] = digits[raw[i] >> 4];
		hex[2 * i + 1] = digits[raw[i] & 0x0f];
	}
#else
	for (i = 0; i < want; i++)
		hex[i] = (char)tolower(raw[i]);
#endif
	return 0;
}

/* Replace an EF with exactly the bytes given, in the backend's own form */
static void write_ef_raw(const char *rel_path, const void *data, size_t len)
{
	char path[SS_STORAGE_PATH_MAX + 1];
	ss_FILE f;

	ef_path(path, sizeof(path), rel_path);
	f = ss_fopen(path, "w");
	assert(f);
	assert(ss_fwrite(data, 1, len, f) == len);
	ss_fclose(f);
}

/* Replace an EF with the content hex spells */
static void write_ef(const char *rel_path, const char *hex, size_t hex_len)
{
#ifdef CONFIG_COMPACT_STORAGE
	uint8_t bin[EF_HEX_MAX / 2];
	size_t i;

	assert(hex_len % 2 == 0 && hex_len / 2 <= sizeof(bin));
	for (i = 0; i < hex_len / 2; i++)
		bin[i] = hex_pair(&hex[2 * i]);
	write_ef_raw(rel_path, bin, hex_len / 2);
#else
	write_ef_raw(rel_path, hex, hex_len);
#endif
}

static void remove_ef(const char *rel_path)
{
	char path[SS_STORAGE_PATH_MAX + 1];

	ef_path(path, sizeof(path), rel_path);
	assert(remove(path) == 0);
}

/* The EF is ef_hex_len hex characters long, and at hex_off holds what hex spells */
static void check_ef(const char *what, const char *rel_path, size_t ef_hex_len, size_t hex_off, const char *hex)
{
	char buf[EF_HEX_MAX];
	size_t n = strlen(hex);

	assert(ef_len(rel_path) == (int)ef_hex_len);
	assert(hex_off + n <= ef_hex_len);
	assert(read_ef(rel_path, buf, ef_hex_len) == 0);
	assert(strncasecmp(&buf[hex_off], hex, n) == 0);
	printf("%-30s %s\n", what, hex);
}

/* ---------------------------------------------------------------------------
 * The template tree
 * ------------------------------------------------------------------------- */

/* The EFs provisioning touches, as files/ ships them. Read once at start, so
 * every test can begin from the template rather than from what the test before
 * it left behind. */
static struct {
	const char *template_path;
	const char *rel_path;
	size_t len;
	char hex[EF_HEX_MAX];
} template_efs[] = {
	{ "/3f00/2fe2", ICCID_EF, ICCID_LEN },	   { "/3f00/7ff0/6f07", IMSI_EF, IMSI_LEN },
	{ "/3f00/a001", A001_EF, A001_LEN },	   { "/3f00/a003", A003_EF, A003_LEN },
	{ "/3f00/a004", A004_EF, A004_LEN },	   { "/3f00/7ff0/6f42", SMSP_EF, SMSP_EF_LEN },
};

#define TEMPLATE_EF_COUNT (sizeof(template_efs) / sizeof(template_efs[0]))

/* Read the template from the tree as files/ ships it: directories and hex text,
 * whatever the layout under test, as the build copies files/ unchanged. Then
 * point the storage at where the layout under test keeps its EFs. */
static void load_template(void)
{
	char path[SS_STORAGE_PATH_MAX + 1];
	size_t i;
	FILE *f;

	for (i = 0; i < TEMPLATE_EF_COUNT; i++) {
		snprintf(path, sizeof(path), "%s%s", TEMPLATE_ROOT, template_efs[i].template_path);
		f = fopen(path, "r");
		assert(f);
		assert(fread(template_efs[i].hex, 1, template_efs[i].len, f) == template_efs[i].len);
		fclose(f);
	}

	mkdir(STORAGE_ROOT, 0755);
	assert(ss_storage_set_path(STORAGE_ROOT) == 0);
}

/* Put every EF provisioning touches back as the template has it, in the
 * backend's form */
static void reset_tree(void)
{
	size_t i;

	for (i = 0; i < TEMPLATE_EF_COUNT; i++)
		write_ef(template_efs[i].rel_path, template_efs[i].hex, template_efs[i].len);
}

/* ---------------------------------------------------------------------------
 * Profiles
 * ------------------------------------------------------------------------- */

// clang-format off
#define BASE_TAGS \
	"01" "12" "080910101032540636" \
	"02" "14" "98001032547698103214" \
	"03" "20" "00000000000000000000000000000000" \
	"04" "20" "000102030405060708090A0B0C0D0E0F"

#define OTA_TAGS \
	"05" "20" "000102030405060708090A0B0C0D0E0F" \
	"06" "20" "000102030405060708090A0B0C0D0E0F"

static const char *decrypted_profile_smsp_ok =
	BASE_TAGS OTA_TAGS
	"07" "68" "ffffffffffffffffffffffffffffffffffffffffffffffffe5ffffffffffffffffffffffff07911226540092f6ffffffffff00a8";

static const char *decrypted_profile_smsc_ok =
	BASE_TAGS OTA_TAGS
	"0c" "18" "0791448889078484ffffffff";

static const char *decrypted_profile_smsp_smsc_ok =
	BASE_TAGS OTA_TAGS
	"07" "68" "ffffffffffffffffff2ffffffffffffffff4ffffffffffffe5ffffffffffffffffffffffff07911226540092f6ffffffffff00a8"
	"0c" "18" "0791448889078484ffffffff";

/* PIN 6868, PUK 79797979 and the 16 character ADM 8034270253113864, each as the
 * hex encoded ASCII the profile carries. */
#define PIN_TAGS \
	"08" "08" "36383638" \
	"0b" "10" "3739373937393739" \
	"0a" "20" "38303334323730323533313133383634"

static const char *decrypted_profile_pins_ok = BASE_TAGS OTA_TAGS PIN_TAGS;

/* Every field, each key distinct, so a key written to the wrong place shows */
static const char *decrypted_profile_full =
	"01" "12" "080910101032540636"
	"02" "14" "98001032547698103214"
	"03" "20" "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	"04" "20" "000102030405060708090a0b0c0d0e0f"
	"05" "20" "11111111111111111111111111111111"
	"06" "20" "22222222222222222222222222222222"
	PIN_TAGS
	"0c" "18" "07919408000000f0ffffffff";

/* No Ki tag, so nothing may be written at all. KIC and KID are absent too, which
 * on its own is a profile the provisioner accepts: they are OTA keys. */
static const char *decrypted_profile_no_keys =
	"01" "12" "080910101032540636"
	"02" "14" "98001032547698103214"
	"03" "20" "00000000000000000000000000000000";

/* KIC and KID are OTA keys, so a profile without them provisions normally. */
static const char *decrypted_profile_no_ota_keys = BASE_TAGS;

/* Everything but the OPc */
static const char *decrypted_profile_no_opc =
	"01" "12" "080910101032540636"
	"02" "14" "98001032547698103214"
	"04" "20" "000102030405060708090a0b0c0d0e0f";
// clang-format on

static const char *smsp_file_6f42_updated_smsp =
	"ffffffffffffffffffffffffffffffffffffffffffffffffe5ffffffffffffffffffffffff07911226540092f6ffffffffff00a8ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
static const char *smsp_file_6f42_updated_smsc =
	"ffffffffffffffffffffffffffffffffffffffffffffffffe5ffffffffffffffffffffffff0791448889078484ffffffffff00a8ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
static const char *smsp_file_6f42_updated_smsp_smsc =
	"ffffffffffffffffff2ffffffffffffffff4ffffffffffffe5ffffffffffffffffffffffff0791448889078484ffffffffff00a8ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";

static const char *a003_file_shipped = "0003000a000131323334ffffffff3132333435363738"
				       "0003000a008131323334ffffffff3132333435363738"
				       "01030000000a31323334ffffffffffffffffffffffff";
static const char *a003_file_provisioned = "0003000a000136383638ffffffff3739373937393739"
					   "0003000a008131323334ffffffff3739373937393739"
					   "01030000000a8034270253113864ffffffffffffffff";

/* ---------------------------------------------------------------------------
 * EF.SMSP
 * ------------------------------------------------------------------------- */

static void check_smsp(const char *profile, const char *expect)
{
	char smsp[SMSP_EF_LEN];
	int rc;

	reset_tree();
	rc = onomondo_profile_provisioning(profile);
	assert(rc == 0);

	rc = read_ef(SMSP_EF, smsp, sizeof(smsp));
	assert(rc == 0);
	if (strncmp(smsp, expect, SMSP_EF_LEN) != 0) {
		printf("SMSP mismatch: expected (hex) %s\n", expect);
		printf("Got: %.*s\n", SMSP_EF_LEN, smsp);
		assert(0);
	}
}

static void provision_profile_smsp_test_ok(void)
{
	printf("TEST: Provision a SoftSIM profile with SMSP content\n");
	check_smsp(decrypted_profile_smsp_ok, smsp_file_6f42_updated_smsp);
	printf("Successfully provisioned and validated SMSP (6F42)\n");
}

static void provision_profile_smsc_test_ok(void)
{
	printf("TEST: Provision a SoftSIM profile with SMSC content\n");
	check_smsp(decrypted_profile_smsc_ok, smsp_file_6f42_updated_smsc);
	printf("Successfully provisioned and validated SMSC update\n");
}

/* SMSP is written first, and SMSC then updates the content SMSP put there */
static void provision_profile_smsp_smsc_test_ok(void)
{
	printf("TEST: Provision a SoftSIM profile with SMSP and SMSC content\n");
	check_smsp(decrypted_profile_smsp_smsc_ok, smsp_file_6f42_updated_smsp_smsc);
	printf("Successfully provisioned and validated both SMSP and SMSC\n");
}

/* ---------------------------------------------------------------------------
 * Every field, at its place
 * ------------------------------------------------------------------------- */

/* Whether the EF, as the backend stores it, holds an upper case hex digit. Only
 * the hex backend stores characters; compact EFs are bytes, which have no case. */
static bool ef_has_upper_case(const char *rel_path)
{
#ifdef CONFIG_COMPACT_STORAGE
	(void)rel_path;
	return false;
#else
	char path[SS_STORAGE_PATH_MAX + 1];
	char raw[EF_HEX_MAX];
	size_t n, i;
	FILE *f;

	ef_path(path, sizeof(path), rel_path);
	f = fopen(path, "r");
	assert(f);
	n = fread(raw, 1, sizeof(raw), f);
	fclose(f);
	for (i = 0; i < n; i++) {
		if (raw[i] >= 'A' && raw[i] <= 'F')
			return true;
	}
	return false;
#endif
}

/* Hex case carries no meaning, but the EFs are lower case, like the template and
 * everything the storage layer writes. A profile in upper case is written in the
 * files' format. */
static void provision_profile_upper_case_test(void)
{
	// clang-format off
	static const char *profile_upper =
		"01" "12" "080910101032540636"
		"02" "14" "98001032547698103214"
		"03" "20" "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
		"04" "20" "000102030405060708090A0B0C0D0E0F"
		"05" "20" "ABCDEFABCDEFABCDEFABCDEFABCDEFAB"
		"0c" "18" "07919408000000F0FFFFFFFF";
	// clang-format on
	int rc;

	printf("TEST: Provision a SoftSIM profile carrying upper case hex\n");
	reset_tree();

	rc = onomondo_profile_provisioning(profile_upper);
	printf("Provisioning return value: %d\n", rc);
	assert(rc == 0);

	check_ef("A001 Ki", A001_EF, A001_LEN, A001_KI_OFFSET, "000102030405060708090a0b0c0d0e0f");
	check_ef("A001 OPc", A001_EF, A001_LEN, A001_OPC_OFFSET, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
	check_ef("A004 KIC", A004_EF, A004_LEN, A004_KIC_OFFSET, "abcdefabcdefabcdefabcdefabcdefab");
	check_ef("SMSC", SMSP_EF, SMSP_EF_LEN, SMSC_OFFSET, "07919408000000f0ffffffff");
	assert(!ef_has_upper_case(A001_EF));
	assert(!ef_has_upper_case(A004_EF));
	assert(!ef_has_upper_case(SMSP_EF));
	printf("EFs written in lower case\n");
}

static void provision_profile_full_test(void)
{
	int rc;

	printf("TEST: Provision a SoftSIM profile carrying every field\n");
	reset_tree();

	rc = onomondo_profile_provisioning(decrypted_profile_full);
	printf("Provisioning return value: %d\n", rc);
	assert(rc == 0);

	check_ef("ICCID", ICCID_EF, ICCID_LEN, 0, "98001032547698103214");
	check_ef("IMSI", IMSI_EF, IMSI_LEN, 0, "080910101032540636");
	check_ef("A001 Ki", A001_EF, A001_LEN, A001_KI_OFFSET, "000102030405060708090a0b0c0d0e0f");
	check_ef("A001 OPc", A001_EF, A001_LEN, A001_OPC_OFFSET, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
	check_ef("A001 flag", A001_EF, A001_LEN, A001_FLAG_OFFSET, "00");
	check_ef("A003 record 1 header kept", A003_EF, A003_LEN, 0, "0003000a0001");
	check_ef("A003 PIN1", A003_EF, A003_LEN, PIN_OFFSET, "36383638ffffffff");
	check_ef("A003 PUK record 1", A003_EF, A003_LEN, PUK_OFFSET, "3739373937393739");
	check_ef("A003 PIN2 kept", A003_EF, A003_LEN, A003_RECORD_SIZE + PIN_OFFSET, "31323334ffffffff");
	check_ef("A003 PUK record 2", A003_EF, A003_LEN, A003_RECORD_SIZE + PUK_OFFSET, "3739373937393739");
	check_ef("A003 ADM", A003_EF, A003_LEN, 2 * A003_RECORD_SIZE + PIN_OFFSET, "8034270253113864");
	check_ef("A004 header", A004_EF, A004_LEN, 0, "b00011060101");
	check_ef("A004 KIC", A004_EF, A004_LEN, A004_KIC_OFFSET, "11111111111111111111111111111111");
	check_ef("A004 KID", A004_EF, A004_LEN, A004_KID_OFFSET, "22222222222222222222222222222222");
	check_ef("A004 record 2 erased", A004_EF, A004_LEN, A004_HEADER_SIZE + 2 * KEY_SIZE, "ffffffff");
	check_ef("SMSC", SMSP_EF, SMSP_EF_LEN, SMSC_OFFSET, "07919408000000f0ffffffff");
}

/* ---------------------------------------------------------------------------
 * The PIN code file
 * ------------------------------------------------------------------------- */

/* A profile carrying PIN, PUK and ADM values puts all three into the PIN code
 * file. The PIN2 record keeps its default PIN, since this profile carries no
 * PIN2 tag, but takes the PUK. */
static void provision_profile_pins_test_ok(void)
{
	char a003[A003_LEN];
	int rc;

	printf("TEST: Provision a SoftSIM profile with PIN, PUK and ADM content\n");
	reset_tree();

	rc = onomondo_profile_provisioning(decrypted_profile_pins_ok);
	printf("Provisioning return value: %d\n", rc);
	assert(rc == 0);

	rc = read_ef(A003_EF, a003, sizeof(a003));
	assert(rc == 0);
	printf("PIN code file: %.*s\n", A003_LEN, a003);
	assert(memcmp(a003, a003_file_provisioned, A003_LEN) == 0);
}

/* A profile without PIN tags has nothing to say about the PIN code file, so the
 * file must come out unchanged. */
static void provision_profile_no_pins_test_ok(void)
{
	char a003[A003_LEN];
	int rc;

	printf("TEST: Provision a SoftSIM profile without PIN content\n");
	reset_tree();

	rc = onomondo_profile_provisioning(decrypted_profile_smsp_ok);
	printf("Provisioning return value: %d\n", rc);
	assert(rc == 0);

	rc = read_ef(A003_EF, a003, sizeof(a003));
	assert(rc == 0);
	assert(memcmp(a003, a003_file_shipped, A003_LEN) == 0);
	printf("PIN code file unchanged\n");
}

/* The PIN code file holds state the card maintains, not only what a profile put
 * there: a PIN the user changed, the retry counter a failed VERIFY decremented.
 * A profile that carries no PIN value must leave all of it alone. */
static void provision_profile_keeps_live_pin_state_test(void)
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
	reset_tree();
	write_ef(A003_EF, a003_file_in_use, A003_LEN);

	rc = onomondo_profile_provisioning(decrypted_profile_smsp_ok);
	printf("Provisioning return value: %d\n", rc);
	assert(rc == 0);

	rc = read_ef(A003_EF, a003, sizeof(a003));
	assert(rc == 0);
	assert(memcmp(a003, a003_file_in_use, A003_LEN) == 0);
	printf("PIN code file left as the card had it\n");
}

/* An EF that was opened and then not written whole is torn, which is a different
 * answer than a template that never shipped the file. */
static void provision_profile_torn_a003_write_test(void)
{
	int rc;

	printf("TEST: Provision a SoftSIM profile when the PIN code file write is cut short\n");
	reset_tree();

	tear_a003_write = true;
	rc = onomondo_profile_provisioning(decrypted_profile_pins_ok);
	printf("Provisioning return value: %d\n", rc);
	assert(rc != 0);
	tear_a003_write = false;
}

/* The PIN code file is updated, not replaced: a record this format does not
 * describe must survive provisioning. */
static void provision_profile_keeps_extra_a003_records_test(void)
{
	char extended[A003_LEN + A003_RECORD_SIZE];
	char readback[A003_LEN + A003_RECORD_SIZE];
	int rc;

	printf("TEST: Provision a SoftSIM profile over a PIN code file with an extra record\n");
	reset_tree();

	memcpy(extended, a003_file_shipped, A003_LEN);
	memset(&extended[A003_LEN], 'a', A003_RECORD_SIZE);
	write_ef(A003_EF, extended, sizeof(extended));

	rc = onomondo_profile_provisioning(decrypted_profile_pins_ok);
	printf("Provisioning return value: %d\n", rc);
	assert(rc == 0);

	rc = read_ef(A003_EF, readback, sizeof(readback));
	assert(rc == 0);
	assert(memcmp(readback, a003_file_provisioned, A003_LEN) == 0);
	assert(memcmp(&readback[A003_LEN], &extended[A003_LEN], A003_RECORD_SIZE) == 0);
	printf("Extra record preserved\n");
}

/* The PIN code file is optional: a reduced template need not ship it, and the
 * rest of the profile must still be provisioned. */
static void provision_profile_without_a003_test(void)
{
	int rc;

	printf("TEST: Provision a SoftSIM profile into a storage tree with no PIN code file\n");
	reset_tree();
	remove_ef(A003_EF);

	rc = onomondo_profile_provisioning(decrypted_profile_pins_ok);
	printf("Provisioning return value: %d\n", rc);
	assert(rc == 0);
	assert(ef_len(A003_EF) == -1);
}

/* A PIN code file shorter than the format is refused, and left as it was */
static void provision_profile_short_a003_test(void)
{
	int rc;

	printf("TEST: Provision a SoftSIM profile over a short PIN code file\n");
	reset_tree();
	write_ef(A003_EF, "0003000a", 8);

	rc = onomondo_profile_provisioning(decrypted_profile_pins_ok);
	printf("Provisioning return value: %d\n", rc);
	assert(rc != 0);
	check_ef("Short PIN code file untouched", A003_EF, 8, 0, "0003000a");
}

/* ---------------------------------------------------------------------------
 * Keys and refusals
 * ------------------------------------------------------------------------- */

/* An incomplete profile is refused before the first EF is written, rather than
 * writing NUL over the key material and reporting success. */
static void provision_profile_missing_tag_test(void)
{
	/* A001 holds the Ki this profile omits, so it is the file at risk. Snapshot it
	 * after a provisioning, so it differs from the template. */
	char a001_before[A001_LEN], a001_after[A001_LEN];
	int rc;

	printf("TEST: Provision a SoftSIM profile that is missing its Ki\n");
	reset_tree();
	rc = onomondo_profile_provisioning(decrypted_profile_full);
	assert(rc == 0);

	rc = read_ef(A001_EF, a001_before, sizeof(a001_before));
	assert(rc == 0);

	rc = onomondo_profile_provisioning(decrypted_profile_no_keys);
	printf("Provisioning return value: %d\n", rc);
	assert(rc != 0);

	rc = read_ef(A001_EF, a001_after, sizeof(a001_after));
	assert(rc == 0);
	assert(memcmp(a001_before, a001_after, A001_LEN) == 0);
	printf("Key material untouched\n");
}

static void provision_profile_without_ota_keys_test(void)
{
	char a004[A004_LEN], expect[A004_LEN];
	int rc;

	printf("TEST: Provision a SoftSIM profile that carries no KIC or KID\n");
	reset_tree();

	rc = onomondo_profile_provisioning(decrypted_profile_no_ota_keys);
	printf("Provisioning return value: %d\n", rc);
	assert(rc == 0);

	/* The EF comes out erased: a key indication of 0xff matches no remote
	 * command, so OTA is rejected rather than verified against a key the profile
	 * never carried -- the template's test keys included. */
	memset(expect, 'f', A004_LEN);
	assert(ef_len(A004_EF) == A004_LEN);
	rc = read_ef(A004_EF, a004, sizeof(a004));
	assert(rc == 0);
	assert(memcmp(a004, expect, A004_LEN) == 0);
	printf("OTA key area left unusable\n");
}

/* A storage tree that cannot be opened must be reported, not written through. */
static void provision_profile_bad_storage_test(void)
{
	char saved[SS_STORAGE_PATH_MAX];
	int rc;

	printf("TEST: Provision a SoftSIM profile into a storage path that does not exist\n");
	reset_tree();

	snprintf(saved, sizeof(saved), "%s", ss_storage_get_path());
	/* A directory, so that with the flat layout the EFs do not land next to it
	 * as ./no-such-storage_3f00_... */
	rc = ss_storage_set_path("./no-such-storage/");
	assert(rc == 0);

	rc = onomondo_profile_provisioning(decrypted_profile_smsp_ok);
	printf("Provisioning return value: %d\n", rc);
	assert(rc != 0);

	rc = ss_storage_set_path(saved);
	assert(rc == 0);
}

/* ---------------------------------------------------------------------------
 * Whether a card is provisioned
 * ------------------------------------------------------------------------- */

/* A card counts as provisioned only while EF.IMSI holds a real subscriber: not
 * the template's default, not a zeroed (unbound) IMSI, and not a missing EF. */
static void check_provisioned_test(void)
{
	static const uint8_t zero_bytes[IMSI_LEN];
	int rc;

	printf("TEST: Check whether a SoftSIM profile is provisioned\n");
	reset_tree();

	rc = onomondo_profile_provisioning(decrypted_profile_smsp_ok);
	assert(rc == 0);
	assert(onomondo_profile_check_provisioned() == 1);
	printf("Provisioned IMSI reported as provisioned\n");

	write_ef(IMSI_EF, "080910100000000010", IMSI_LEN);
	assert(onomondo_profile_check_provisioned() == 0);
	printf("Default IMSI reported as not provisioned\n");

	write_ef(IMSI_EF, "000000000000000000", IMSI_LEN);
	assert(onomondo_profile_check_provisioned() == 0);
	write_ef_raw(IMSI_EF, zero_bytes, EF_SIZE(IMSI_LEN));
	assert(onomondo_profile_check_provisioned() == 0);
	printf("Zeroed IMSI reported as not provisioned\n");

	write_ef(IMSI_EF, "0809", 4);
	assert(onomondo_profile_check_provisioned() == 0);
	printf("Short IMSI reported as not provisioned\n");

	remove_ef(IMSI_EF);
	assert(onomondo_profile_check_provisioned() == 0);
	printf("Missing IMSI reported as not provisioned\n");
}

/* EF.IMSI is set to the default IMSI before the first write and to the real one
 * after the last, so a provisioning that fails partway never reports as
 * provisioned: neither on a fresh card, nor over an earlier profile whose IMSI
 * would otherwise vouch for EFs that are now half old, half new. The PIN code
 * file write, which comes after ICCID and A001, is the one cut short. */
static void check_provisioned_after_failed_write_test(void)
{
	int rc;

	printf("TEST: A provisioning that fails partway does not report as provisioned\n");

	reset_tree();
	tear_a003_write = true;
	rc = onomondo_profile_provisioning(decrypted_profile_pins_ok);
	tear_a003_write = false;
	assert(rc != 0);
	assert(onomondo_profile_check_provisioned() == 0);
	printf("First provisioning cut short: not provisioned\n");

	reset_tree();
	rc = onomondo_profile_provisioning(decrypted_profile_smsp_ok);
	assert(rc == 0);
	assert(onomondo_profile_check_provisioned() == 1);
	tear_a003_write = true;
	rc = onomondo_profile_provisioning(decrypted_profile_pins_ok);
	tear_a003_write = false;
	assert(rc != 0);
	assert(onomondo_profile_check_provisioned() == 0);
	printf("Provisioning over an earlier profile cut short: not provisioned\n");

	/* A retry that succeeds provisions the card */
	rc = onomondo_profile_provisioning(decrypted_profile_smsp_ok);
	assert(rc == 0);
	assert(onomondo_profile_check_provisioned() == 1);
	printf("Retry provisions the card\n");
}

/* ---------------------------------------------------------------------------
 * A platform with a key store, provisioning the way hypthetical keystore 
 * mechanism will do. 
 *
 * Ki, KIC and KID go into a key store (PSA). Their fields are then
 * edited to hold a reference -- the record tag in the first byte, zeros after --
 * and the generic writer puts that reference where the key would be. At run
 * time the platform's crypto reads the first byte of the key slot and resolves
 * it to the stored key. OPc is not a key to an operation but data Milenage XORs
 * with, so it stays in A001 as it is.
 * ------------------------------------------------------------------------- */

enum { KS_KI, KS_KIC, KS_KID, KS_COUNT };

/* The key store is hypothetical: it stands in for loading the keys into the
 * MCU's hardware key storage (a secure element, PSA key slots, a crypto
 * peripheral), which a host test does not have. All it models is what the
 * provisioning flow relies on -- keys go in, leave the filesystem, and a
 * reference resolves back to them -- not how any real hardware holds them.
 *
 * Keys held as the profile spells them: KEY_SIZE hex characters */
static struct {
	bool present;
	char key[KEY_SIZE];
} keystore[KS_COUNT];

static void keystore_import(int slot, const uint8_t *hex)
{
	size_t i;

	for (i = 0; i < KEY_SIZE; i++)
		keystore[slot].key[i] = (char)tolower(hex[i]);
	keystore[slot].present = true;
}

static void keystore_destroy(int slot)
{
	memset(&keystore[slot], 0, sizeof(keystore[slot]));
}

/* What the platform crypto does with a key slot: resolve its first byte */
static const char *keystore_resolve(const char *key_slot_hex)
{
	uint8_t tag = hex_pair(key_slot_hex);
	int slot = tag == KI_TAG ? KS_KI : tag == KIC_TAG ? KS_KIC : tag == KID_TAG ? KS_KID : -1;

	return slot >= 0 && keystore[slot].present ? keystore[slot].key : NULL;
}

/* A field holds hex: the tag's two characters, then '0' for the 15 zero bytes */
static void set_reference(uint8_t field[KEY_SIZE], uint8_t tag)
{
	static const char digits[] = "0123456789abcdef";

	memset(field, '0', KEY_SIZE);
	field[0] = (uint8_t)digits[tag >> 4];
	field[1] = (uint8_t)digits[tag & 0x0f];
}

static int provision_with_keystore(const char *profile_string)
{
	struct ss_profile profile;
	int rc;

	if (ss_profile_from_string((uint16_t)strlen(profile_string), profile_string, &profile) != 0)
		return -1;

	/* Validated before the key store is touched: a refused profile must not
	 * have replaced the keys of the one provisioned before it. */
	if (!ss_profile_has_tag(&profile, ICCID_TAG) || !ss_profile_has_tag(&profile, IMSI_TAG) ||
	    !ss_profile_has_tag(&profile, KI_TAG) || !ss_profile_has_tag(&profile, OPC_TAG)) {
		ss_profile_wipe(&profile);
		return -1;
	}

	keystore_import(KS_KI, profile.ki);
	set_reference(profile.ki, KI_TAG);

	/* Only the OTA keys the profile carries are imported; the stale ones go, as
	 * the writer erases A004 and nothing references them any more. */
	if (ss_profile_has_tag(&profile, KIC_TAG)) {
		keystore_import(KS_KIC, profile.kic);
		set_reference(profile.kic, KIC_TAG);
	} else {
		keystore_destroy(KS_KIC);
	}
	if (ss_profile_has_tag(&profile, KID_TAG)) {
		keystore_import(KS_KID, profile.kid);
		set_reference(profile.kid, KID_TAG);
	} else {
		keystore_destroy(KS_KID);
	}

	rc = ss_profile_write_to_fs(&profile);

	/* Key store and filesystem can not change together. When the write fails,
	 * drop the Ki, so the device reads as not provisioned rather than as
	 * provisioned with keys that do not match its files. */
	if (rc != 0)
		keystore_destroy(KS_KI);

	ss_profile_wipe(&profile);
	return rc;
}

/* Whether the EF holds the key anywhere, on a byte boundary */
static bool ef_contains_key(const char *rel_path, size_t ef_hex_len, const char *key)
{
	char buf[EF_HEX_MAX];
	size_t i;

	assert(read_ef(rel_path, buf, ef_hex_len) == 0);
	for (i = 0; i + KEY_SIZE <= ef_hex_len; i += 2) {
		if (memcmp(&buf[i], key, KEY_SIZE) == 0)
			return true;
	}
	return false;
}

static void keystore_provision_full_test(void)
{
	static const char ki[] = "000102030405060708090a0b0c0d0e0f";
	static const char kic[] = "11111111111111111111111111111111";
	static const char kid[] = "22222222222222222222222222222222";
	char a001[A001_LEN], a004[A004_LEN];
	const char *resolved;
	int rc;

	printf("TEST: Provision a full SoftSIM profile with its keys in a key store\n");
	reset_tree();
	memset(keystore, 0, sizeof(keystore));

	rc = provision_with_keystore(decrypted_profile_full);
	printf("Provisioning return value: %d\n", rc);
	assert(rc == 0);

	/* The files hold references where the keys were, and the real OPc */
	check_ef("A001 Ki slot: reference", A001_EF, A001_LEN, A001_KI_OFFSET, "04000000000000000000000000000000");
	check_ef("A001 OPc", A001_EF, A001_LEN, A001_OPC_OFFSET, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
	check_ef("A001 flag", A001_EF, A001_LEN, A001_FLAG_OFFSET, "00");
	check_ef("A004 header", A004_EF, A004_LEN, 0, "b00011060101");
	check_ef("A004 KIC slot: reference", A004_EF, A004_LEN, A004_KIC_OFFSET, "05000000000000000000000000000000");
	check_ef("A004 KID slot: reference", A004_EF, A004_LEN, A004_KID_OFFSET, "06000000000000000000000000000000");
	check_ef("ICCID", ICCID_EF, ICCID_LEN, 0, "98001032547698103214");
	check_ef("IMSI", IMSI_EF, IMSI_LEN, 0, "080910101032540636");
	check_ef("A003 PIN1", A003_EF, A003_LEN, PIN_OFFSET, "36383638ffffffff");

	/* The real keys are in the key store, and in no file */
	assert(keystore[KS_KI].present && memcmp(keystore[KS_KI].key, ki, KEY_SIZE) == 0);
	assert(keystore[KS_KIC].present && memcmp(keystore[KS_KIC].key, kic, KEY_SIZE) == 0);
	assert(keystore[KS_KID].present && memcmp(keystore[KS_KID].key, kid, KEY_SIZE) == 0);
	assert(!ef_contains_key(A001_EF, A001_LEN, ki));
	assert(!ef_contains_key(A004_EF, A004_LEN, kic) && !ef_contains_key(A004_EF, A004_LEN, kid));
	printf("Ki, KIC and KID in the key store, in no file\n");

	/* What the card code hands the crypto resolves to the stored key */
	assert(read_ef(A001_EF, a001, sizeof(a001)) == 0);
	resolved = keystore_resolve(&a001[A001_KI_OFFSET]);
	assert(resolved && memcmp(resolved, ki, KEY_SIZE) == 0);
	assert(read_ef(A004_EF, a004, sizeof(a004)) == 0);
	resolved = keystore_resolve(&a004[A004_KIC_OFFSET]);
	assert(resolved && memcmp(resolved, kic, KEY_SIZE) == 0);
	resolved = keystore_resolve(&a004[A004_KID_OFFSET]);
	assert(resolved && memcmp(resolved, kid, KEY_SIZE) == 0);
	printf("Key slot references resolve to the stored keys\n");
}

static void keystore_provision_no_ota_keys_test(void)
{
	char a004[A004_LEN], expect[A004_LEN];
	int rc;

	printf("TEST: Provision a SoftSIM profile without KIC or KID with a key store\n");
	reset_tree();
	/* OTA keys left over from a previous profile */
	keystore[KS_KIC].present = true;
	keystore[KS_KID].present = true;

	rc = provision_with_keystore(decrypted_profile_no_ota_keys);
	printf("Provisioning return value: %d\n", rc);
	assert(rc == 0);
	assert(keystore[KS_KI].present);
	assert(!keystore[KS_KIC].present && !keystore[KS_KID].present);

	memset(expect, 'f', A004_LEN);
	assert(ef_len(A004_EF) == A004_LEN);
	assert(read_ef(A004_EF, a004, sizeof(a004)) == 0);
	assert(memcmp(a004, expect, A004_LEN) == 0);
	printf("Stale OTA keys removed from the key store, A004 erased\n");
}

/* A profile without OPc is refused before anything changes: the key store keeps
 * the previous profile's Ki, and the files stay as they were. */
static void keystore_provision_refused_test(void)
{
	static const char old_ki[] = "5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a";
	char before[A001_LEN], after[A001_LEN];
	int rc;

	printf("TEST: Refuse a SoftSIM profile without OPc with a key store\n");
	reset_tree();
	memcpy(keystore[KS_KI].key, old_ki, KEY_SIZE);
	keystore[KS_KI].present = true;
	assert(read_ef(A001_EF, before, sizeof(before)) == 0);

	rc = provision_with_keystore(decrypted_profile_no_opc);
	printf("Provisioning return value: %d\n", rc);
	assert(rc == -1);
	assert(keystore[KS_KI].present && memcmp(keystore[KS_KI].key, old_ki, KEY_SIZE) == 0);
	assert(ef_len(A001_EF) == A001_LEN);
	assert(read_ef(A001_EF, after, sizeof(after)) == 0);
	assert(memcmp(before, after, A001_LEN) == 0);
	printf("Key store and files untouched\n");
}

/* A write that fails after the keys were imported leaves no Ki behind, so the
 * device reads as not provisioned. A directory where EF.IMSI should be makes the
 * IMSI write fail. */
static void keystore_provision_failed_write_test(void)
{
	char imsi_path[SS_STORAGE_PATH_MAX + 1];
	int rc;

	printf("TEST: Provision with a key store into storage that refuses the IMSI\n");
	reset_tree();
	remove_ef(IMSI_EF);
	ef_path(imsi_path, sizeof(imsi_path), IMSI_EF);
	assert(mkdir(imsi_path, 0755) == 0);

	rc = provision_with_keystore(decrypted_profile_full);
	printf("Provisioning return value: %d\n", rc);
	assert(rc == -1);
	assert(!keystore[KS_KI].present);
	printf("Ki removed from the key store\n");

	assert(rmdir(imsi_path) == 0);
}

int main(void)
{
	load_template();

	provision_profile_smsp_test_ok();
	provision_profile_smsc_test_ok();
	provision_profile_smsp_smsc_test_ok();
	provision_profile_full_test();
	provision_profile_upper_case_test();
	provision_profile_pins_test_ok();
	provision_profile_no_pins_test_ok();
	provision_profile_keeps_live_pin_state_test();
	provision_profile_torn_a003_write_test();
	provision_profile_keeps_extra_a003_records_test();
	provision_profile_without_a003_test();
	provision_profile_short_a003_test();
	provision_profile_missing_tag_test();
	provision_profile_without_ota_keys_test();
	provision_profile_bad_storage_test();
	check_provisioned_test();
	check_provisioned_after_failed_write_test();
	keystore_provision_full_test();
	keystore_provision_no_ota_keys_test();
	keystore_provision_refused_test();
	keystore_provision_failed_write_test();

	reset_tree();
	return 0;
}
