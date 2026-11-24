/*
 * Copyright (c) 2026 Onomondo ApS. All rights reserved.
 *
 * SPDX-License-Identifier: GPL-3.0-only
 */

/* Provisioning against the compact storage backend, which keeps every EF as the
 * bytes its hex spells. The parser and the writer work in hex either way; this
 * test checks that what lands on disk is the binary form, at the binary offsets
 * and sizes. Each test starts from a fresh tree holding the template's EFs. */

#include <assert.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <onomondo/softsim/storage.h>
#include <onomondo/utils/ss_profile.h>
#include <onomondo/utils/ss_provision.h>

#define TEST_ROOT "./compact_provision_fs"

/* The template's EFs, as files/ ships them */
// clang-format off
static const struct {
	const char *path;
	const char *hex;
} template_efs[] = {
	{ "/3f00/2fe2", "00112233445566778899" },
	{ "/3f00/7ff0/6f07", "080910100000000010" },
	{ "/3f00/a001", "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f00" },
	{ "/3f00/a003", "0003000a000131323334ffffffff31323334353637380003000a008131323334ffffffff"
			"313233343536373801030000000a31323334ffffffffffffffffffffffff" },
	{ "/3f00/a004", "b0001106030300112233445566778899aabbccddeeff0123456789abcdef0123456701234567"
			"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
			"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff" },
	{ "/3f00/7ff0/6f42", "ffffffffffffffffffffffffffffffffffffffffffffffffe5ffffffffffffffffffffff"
			                   "ff0791447779078484ffffffffff00a8ffffffffffffffffffffffffffffffffffffffff"
			                   "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff" },
};

#define BASE_TAGS \
	"01" "12" "080910101032540636" \
	"02" "14" "98001032547698103214" \
	"03" "20" "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" \
	"04" "20" "000102030405060708090a0b0c0d0e0f"

static const char *profile_full =
	BASE_TAGS
	"05" "20" "11111111111111111111111111111111"
	"06" "20" "22222222222222222222222222222222"
	"08" "08" "36383638"                           /* PIN1 6868 */
	"0b" "10" "3739373937393739"                   /* PUK 79797979 */
	"0a" "20" "38303334323730323533313133383634"   /* ADM 8034270253113864 */
	"0c" "18" "07919408000000f0ffffffff";          /* SMSC */
// clang-format on

static size_t hex_to_bytes(const char *hex, uint8_t *out, size_t max)
{
	size_t n = strlen(hex) / 2, i;
	unsigned int b;

	assert(n <= max);
	for (i = 0; i < n; i++) {
		assert(sscanf(&hex[2 * i], "%2x", &b) == 1);
		out[i] = (uint8_t)b;
	}
	return n;
}

/* hex_len characters, not NUL terminated: a profile field */
static void hex_to_bytes_n(const char *hex, size_t hex_len, uint8_t *out)
{
	unsigned int b;

	for (size_t i = 0; i < hex_len / 2; i++) {
		char pair[3] = { hex[2 * i], hex[2 * i + 1], 0 };

		assert(sscanf(pair, "%2x", &b) == 1);
		out[i] = (uint8_t)b;
	}
}

static void write_raw(const char *ef, const uint8_t *data, size_t len)
{
	char path[256];
	FILE *f;

	snprintf(path, sizeof(path), TEST_ROOT "%s", ef);
	f = fopen(path, "wb");
	assert(f);
	assert(fwrite(data, 1, len, f) == len);
	fclose(f);
}

static size_t read_raw(const char *ef, uint8_t *buf, size_t max)
{
	char path[256];
	FILE *f;
	size_t n;

	snprintf(path, sizeof(path), TEST_ROOT "%s", ef);
	f = fopen(path, "rb");
	if (!f)
		return 0;
	n = fread(buf, 1, max, f);
	fclose(f);
	return n;
}

/* A fresh tree holding the template's EFs in binary */
static void reset_tree(void)
{
	uint8_t buf[256];
	size_t i;

	mkdir(TEST_ROOT, 0755);
	mkdir(TEST_ROOT "/3f00", 0755);
	mkdir(TEST_ROOT "/3f00/7ff0", 0755);
	for (i = 0; i < sizeof(template_efs) / sizeof(template_efs[0]); i++)
		write_raw(template_efs[i].path, buf, hex_to_bytes(template_efs[i].hex, buf, sizeof(buf)));
}

/* The EF holds exactly len bytes, and at off the bytes hex spells */
static void check_ef(const char *what, const char *ef, size_t len, size_t off, const char *hex)
{
	uint8_t buf[256], want[128];
	size_t n = read_raw(ef, buf, sizeof(buf));
	size_t wl = hex_to_bytes(hex, want, sizeof(want));

	assert(n == len);
	assert(off + wl <= n);
	assert(memcmp(&buf[off], want, wl) == 0);
	printf("%-30s %s\n", what, hex);
}

static void provision_compact_full_test(void)
{
	int rc;

	printf("TEST: Provision a full SoftSIM profile into compact storage\n");
	reset_tree();

	rc = onomondo_profile_provisioning(profile_full);
	printf("Provisioning return value: %d\n", rc);
	assert(rc == 0);

	check_ef("ICCID", "/3f00/2fe2", ICCID_BIN_LEN, 0, "98001032547698103214");
	check_ef("IMSI", "/3f00/7ff0/6f07", IMSI_BIN_LEN, 0, "080910101032540636");
	check_ef("A001 Ki", "/3f00/a001", A001_BIN_LEN, 0, "000102030405060708090a0b0c0d0e0f");
	check_ef("A001 OPc", "/3f00/a001", A001_BIN_LEN, KEY_BIN_LEN, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
	check_ef("A001 flag", "/3f00/a001", A001_BIN_LEN, 2 * KEY_BIN_LEN, "00");
	check_ef("A003 record 1 header kept", "/3f00/a003", A003_BIN_LEN, 0, "0003000a0001");
	check_ef("A003 PIN1", "/3f00/a003", A003_BIN_LEN, PIN_BIN_OFFSET, "36383638ffffffff");
	check_ef("A003 PUK record 1", "/3f00/a003", A003_BIN_LEN, PUK_BIN_OFFSET, "3739373937393739");
	check_ef("A003 PIN2 kept", "/3f00/a003", A003_BIN_LEN, A003_BIN_RECORD_SIZE + PIN_BIN_OFFSET,
		 "31323334ffffffff");
	check_ef("A003 PUK record 2", "/3f00/a003", A003_BIN_LEN, A003_BIN_RECORD_SIZE + PUK_BIN_OFFSET,
		 "3739373937393739");
	check_ef("A003 ADM", "/3f00/a003", A003_BIN_LEN, 2 * A003_BIN_RECORD_SIZE + PIN_BIN_OFFSET,
		 "8034270253113864");
	check_ef("A004 header", "/3f00/a004", A004_BIN_LEN, 0, "b00011060101");
	check_ef("A004 KIC", "/3f00/a004", A004_BIN_LEN, A004_BIN_HEADER_SIZE, "11111111111111111111111111111111");
	check_ef("A004 KID", "/3f00/a004", A004_BIN_LEN, A004_BIN_HEADER_SIZE + KEY_BIN_LEN,
		 "22222222222222222222222222222222");
	check_ef("A004 record 2 erased", "/3f00/a004", A004_BIN_LEN, A004_BIN_RECORD_SIZE, "ffffffff");
	check_ef("SMSC", "/3f00/7ff0/6f42", 2 * SMSP_BIN_LEN, SMSC_BIN_OFFSET, "07919408000000f0ffffffff");
}

/* Without KIC and KID the OTA keys are erased, so the template's test keys can
 * not be used. */
static void provision_compact_no_ota_keys_test(void)
{
	uint8_t buf[256];
	size_t n, i;
	int rc;

	printf("TEST: Provision a SoftSIM profile without KIC or KID into compact storage\n");
	reset_tree();

	rc = onomondo_profile_provisioning(BASE_TAGS);
	printf("Provisioning return value: %d\n", rc);
	assert(rc == 0);

	n = read_raw("/3f00/a004", buf, sizeof(buf));
	assert(n == A004_BIN_LEN);
	for (i = 0; i < n; i++)
		assert(buf[i] == 0xff);
	printf("A004 erased\n");
}

/* The PIN code file is optional; a short one is refused and left alone. */
static void provision_compact_a003_test(void)
{
	uint8_t buf[256];
	int rc;

	printf("TEST: Provision PINs into compact storage with no PIN code file\n");
	reset_tree();
	assert(unlink(TEST_ROOT "/3f00/a003") == 0);
	rc = onomondo_profile_provisioning(BASE_TAGS "0808" "31323334");
	printf("Provisioning return value: %d\n", rc);
	assert(rc == 0);

	printf("TEST: Provision PINs into compact storage with a short PIN code file\n");
	reset_tree();
	write_raw("/3f00/a003", (const uint8_t *)"\x00\x03\x00\x0a", 4);
	rc = onomondo_profile_provisioning(BASE_TAGS "0808" "31323334");
	printf("Provisioning return value: %d\n", rc);
	assert(rc == -1);
	assert(read_raw("/3f00/a003", buf, sizeof(buf)) == 4);
	printf("Short PIN code file left untouched\n");
}

/* --- A platform with a key store, provisioning the way the nRF91 port does ---
 *
 * Ki, KIC and KID go into a key store (PSA on the nRF91). Their fields are then
 * edited to hold a reference -- the record tag in the first byte, zeros after --
 * and the generic writer puts that reference where the key would be. At run
 * time the platform's crypto reads the first byte of the key slot and resolves
 * it to the stored key. OPc is not a key to an operation but data Milenage XORs
 * with, so it stays in A001 as it is. */

enum { KS_KI, KS_KIC, KS_KID, KS_COUNT };

static struct {
	bool present;
	uint8_t key[KEY_BIN_LEN];
} keystore[KS_COUNT];

static void keystore_import(int slot, const uint8_t *hex)
{
	hex_to_bytes_n((const char *)hex, KEY_SIZE, keystore[slot].key);
	keystore[slot].present = true;
}

static void keystore_destroy(int slot)
{
	memset(&keystore[slot], 0, sizeof(keystore[slot]));
}

/* What the platform crypto does with a key slot: resolve its first byte */
static const uint8_t *keystore_resolve(const uint8_t *key_slot)
{
	int slot = key_slot[0] == KI_TAG ? KS_KI : key_slot[0] == KIC_TAG ? KS_KIC : key_slot[0] == KID_TAG ? KS_KID : -1;

	return slot >= 0 && keystore[slot].present ? keystore[slot].key : NULL;
}

/* A field holds hex: the tag's two characters, then '0' for the 15 zero bytes */
static void set_reference(uint8_t field[KEY_SIZE], uint8_t tag)
{
	static const char hex_digits[] = "0123456789abcdef";

	memset(field, '0', KEY_SIZE);
	field[0] = (uint8_t)hex_digits[tag >> 4];
	field[1] = (uint8_t)hex_digits[tag & 0x0f];
}

static int nrf91_style_provision(const char *profile_string)
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

static bool contains(const uint8_t *buf, size_t n, const uint8_t *needle, size_t nl)
{
	for (size_t i = 0; i + nl <= n; i++) {
		if (memcmp(&buf[i], needle, nl) == 0)
			return true;
	}
	return false;
}

static void nrf91_style_full_test(void)
{
	uint8_t buf[256], ki[KEY_BIN_LEN], kic[KEY_BIN_LEN], kid[KEY_BIN_LEN];
	const uint8_t *resolved;
	size_t n;
	int rc;

	printf("TEST: Provision a full SoftSIM profile the nRF91 way: keys in a key store\n");
	reset_tree();
	memset(keystore, 0, sizeof(keystore));

	rc = nrf91_style_provision(profile_full);
	printf("Provisioning return value: %d\n", rc);
	assert(rc == 0);

	/* The files hold references where the keys were, and the real OPc */
	check_ef("A001 Ki slot: reference", "/3f00/a001", A001_BIN_LEN, 0, "04000000000000000000000000000000");
	check_ef("A001 OPc", "/3f00/a001", A001_BIN_LEN, KEY_BIN_LEN, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
	check_ef("A001 flag", "/3f00/a001", A001_BIN_LEN, 2 * KEY_BIN_LEN, "00");
	check_ef("A004 header", "/3f00/a004", A004_BIN_LEN, 0, "b00011060101");
	check_ef("A004 KIC slot: reference", "/3f00/a004", A004_BIN_LEN, A004_BIN_HEADER_SIZE,
		 "05000000000000000000000000000000");
	check_ef("A004 KID slot: reference", "/3f00/a004", A004_BIN_LEN, A004_BIN_HEADER_SIZE + KEY_BIN_LEN,
		 "06000000000000000000000000000000");
	check_ef("ICCID", "/3f00/2fe2", ICCID_BIN_LEN, 0, "98001032547698103214");
	check_ef("IMSI", "/3f00/7ff0/6f07", IMSI_BIN_LEN, 0, "080910101032540636");
	check_ef("A003 PIN1", "/3f00/a003", A003_BIN_LEN, PIN_BIN_OFFSET, "36383638ffffffff");

	/* The real keys are in the key store, and in no file */
	hex_to_bytes("000102030405060708090a0b0c0d0e0f", ki, sizeof(ki));
	hex_to_bytes("11111111111111111111111111111111", kic, sizeof(kic));
	hex_to_bytes("22222222222222222222222222222222", kid, sizeof(kid));
	assert(keystore[KS_KI].present && memcmp(keystore[KS_KI].key, ki, KEY_BIN_LEN) == 0);
	assert(keystore[KS_KIC].present && memcmp(keystore[KS_KIC].key, kic, KEY_BIN_LEN) == 0);
	assert(keystore[KS_KID].present && memcmp(keystore[KS_KID].key, kid, KEY_BIN_LEN) == 0);
	n = read_raw("/3f00/a001", buf, sizeof(buf));
	assert(!contains(buf, n, ki, KEY_BIN_LEN));
	n = read_raw("/3f00/a004", buf, sizeof(buf));
	assert(!contains(buf, n, kic, KEY_BIN_LEN) && !contains(buf, n, kid, KEY_BIN_LEN));
	printf("Ki, KIC and KID in the key store, in no file\n");

	/* What the card code hands the crypto resolves to the stored key */
	n = read_raw("/3f00/a001", buf, sizeof(buf));
	resolved = keystore_resolve(&buf[0]);
	assert(resolved && memcmp(resolved, ki, KEY_BIN_LEN) == 0);
	n = read_raw("/3f00/a004", buf, sizeof(buf));
	resolved = keystore_resolve(&buf[A004_BIN_HEADER_SIZE]);
	assert(resolved && memcmp(resolved, kic, KEY_BIN_LEN) == 0);
	resolved = keystore_resolve(&buf[A004_BIN_HEADER_SIZE + KEY_BIN_LEN]);
	assert(resolved && memcmp(resolved, kid, KEY_BIN_LEN) == 0);
	printf("Key slot references resolve to the stored keys\n");
}

static void nrf91_style_no_ota_keys_test(void)
{
	uint8_t buf[256];
	size_t n, i;
	int rc;

	printf("TEST: Provision a SoftSIM profile without KIC or KID the nRF91 way\n");
	reset_tree();
	/* OTA keys left over from a previous profile */
	keystore[KS_KIC].present = true;
	keystore[KS_KID].present = true;

	rc = nrf91_style_provision(BASE_TAGS);
	printf("Provisioning return value: %d\n", rc);
	assert(rc == 0);
	assert(keystore[KS_KI].present);
	assert(!keystore[KS_KIC].present && !keystore[KS_KID].present);
	n = read_raw("/3f00/a004", buf, sizeof(buf));
	assert(n == A004_BIN_LEN);
	for (i = 0; i < n; i++)
		assert(buf[i] == 0xff);
	printf("Stale OTA keys removed from the key store, A004 erased\n");
}

static void nrf91_style_refused_test(void)
{
	uint8_t before[256], after[256];
	uint8_t old_ki[KEY_BIN_LEN];
	size_t nb, na;
	int rc;

	/* A profile without OPc is refused before anything changes: the key store
	 * keeps the previous profile's Ki, and the files stay as they were. */
	printf("TEST: Refuse a SoftSIM profile without OPc the nRF91 way\n");
	reset_tree();
	memset(old_ki, 0x5a, sizeof(old_ki));
	memcpy(keystore[KS_KI].key, old_ki, KEY_BIN_LEN);
	keystore[KS_KI].present = true;
	nb = read_raw("/3f00/a001", before, sizeof(before));

	rc = nrf91_style_provision("0112080910101032540636"
				   "021498001032547698103214"
				   "0420000102030405060708090a0b0c0d0e0f");
	printf("Provisioning return value: %d\n", rc);
	assert(rc == -1);
	assert(keystore[KS_KI].present && memcmp(keystore[KS_KI].key, old_ki, KEY_BIN_LEN) == 0);
	na = read_raw("/3f00/a001", after, sizeof(after));
	assert(na == nb && memcmp(before, after, na) == 0);
	printf("Key store and files untouched\n");

	/* A write that fails after the keys were imported leaves no Ki behind, so
	 * the device reads as not provisioned. EF.IMSI's directory is gone here. */
	printf("TEST: Provision the nRF91 way into storage that refuses the IMSI\n");
	reset_tree();
	assert(unlink(TEST_ROOT "/3f00/7ff0/6f07") == 0);
	assert(unlink(TEST_ROOT "/3f00/7ff0/6f42") == 0);
	assert(rmdir(TEST_ROOT "/3f00/7ff0") == 0);

	rc = nrf91_style_provision(profile_full);
	printf("Provisioning return value: %d\n", rc);
	assert(rc == -1);
	assert(!keystore[KS_KI].present);
	printf("Ki removed from the key store\n");
	mkdir(TEST_ROOT "/3f00/7ff0", 0755);
}

int main(void)
{
	assert(ss_storage_set_path(TEST_ROOT) == 0);
	provision_compact_full_test();
	provision_compact_no_ota_keys_test();
	provision_compact_a003_test();
	nrf91_style_full_test();
	nrf91_style_no_ota_keys_test();
	nrf91_style_refused_test();
	return 0;
}
