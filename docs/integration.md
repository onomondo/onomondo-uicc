# Integration

Consuming this library as a black box — nothing on this page requires editing library
sources.

## The API

[`include/onomondo/softsim/softsim.h`](../include/onomondo/softsim/softsim.h) is the
whole call surface — eight functions. Headers under `src/` are internal.

| Function | Contract |
|---|---|
| `ss_new_ctx()` | Allocate one card context. One context = one card. |
| `ss_free_ctx(ctx)` | Teardown. May write the location files like `ss_reset()`, so tear storage down after it. |
| `ss_reset(ctx)` | Card reset: clears the logical channel, SMS and proactive state. Call on card power-on/off/reset. May write the location files after a remote EF.IMSI change. |
| `ss_atr(ctx, buf, len)` | Writes the ATR, returns its length. Size the buffer for the ISO/IEC 7816-3 §8.1 maximum (TS + 32 = 33 bytes). The ATR declares *no extended Lc/Le* (card-capabilities byte 3, b7=0), matching the fixed 256-byte APDU buffers. |
| `ss_transact(ctx, rsp, rsp_len, req, &req_len)` | T=0 TPDU exchange. `req_len` is in/out: pass what you have (a concatenated stream is legal — input is truncated at 261 = 5-byte header + 256 body), it returns the bytes actually consumed. Requests shorter than the 5-byte header are answered `6700`. |
| `ss_application_apdu_transact(...)` | Same signature, application level: accepts 4-byte case-1 APDUs, auto-issues GET RESPONSE on `61xx` and retries with the corrected length on `6Cxx`. The right entry point for a modem host. |
| `ss_poll(ctx)` | Advances the proactive tasks (SMS-TX, REFRESH). A REFRESH after remote file management goes out with the RFM exchange itself; `ss_poll()` drives its retries and the TERMINAL RESPONSE timeout. Call periodically — the demo host uses 5 s ([`main.c`](../src/softsim/main.c)). |
| `ss_is_suspended(ctx)` | With `CONFIG_USE_EXPERIMENTAL_SUSPEND_COMMAND`: whether the terminal suspended the card (state must be retained across the host's sleep). |

**Buffer contracts** ([`softsim.c`](../src/softsim/uicc/softsim.c),
[`apdu.h`](../src/softsim/uicc/apdu.h)):

- Response buffer ≥ **258** bytes (256-byte body + status word) — both transact
  functions return 0 *without processing* on anything smaller.
- `Le = 0` encodes **256**: full-size response bodies are legal and occur in practice.
  Never clamp Le below 256.
- Misuse guards are `assert()`. `-DNDEBUG` turns them into
  silent corruption — don't ship it unaudited.

**No TX callback.** The card is strictly request/response: pending proactive data
rewrites a successful SW to `91xx` and the terminal FETCHes it as a normal APDU.

**Threading.** No locking anywhere. Serialize every call on a context — including
`ss_poll()` — on one thread or under one lock.

Lifecycle: `ss_new_ctx → ss_atr → { ss_*transact | ss_poll }* → ss_reset (on card
reset) → ss_free_ctx`. Minimal end-to-end example:
[`tests/init/init_test.c`](../tests/init/init_test.c).

## Integration topologies

The API is identical everywhere — what differs is which processor calls it and what
carries reset/APDU to it.

**Radio module** (SiP/SoC with an internal modem plus an application core). The
library runs on the application core; the modem side exposes a software-SIM hook and
forwards reset/APDU over the module-internal IPC. The IPC handler is the
serialization point (the [threading rule](#the-api) applies); storage is the
application core's flash. The same shape works one level down — baseband firmware
calling the API directly in place of its ISO 7816 driver, with storage in modem NVM.

```
┌─ radio module (SiP/SoC) ───────────────────────────────────────────────┐
│  ┌─ modem core ──────┐                    ┌─ application core ──────┐  │
│  │                   │                    │                         │  │
│  │ SIM driver        │    reset / APDU    │ IPC glue                │  │
│  │ (software-SIM     │  ◄──────────────►  │  └─► softsim            │  │
│  │  hook)            │    (module IPC)    │       └─► ss_f* port    │  │
│  │                   │                    │                         │  │
│  └───────────────────┘                    └─────────────────────────┘  │
│                                                        ▼               │
│                                                  module flash          │
└────────────────────────────────────────────────────────────────────────┘
```

**External MCU/MPU** beside an off-the-shelf modem. Two transports:

- The physical SIM pins: the MCU implements the ISO 7816-3 electrical and T=0
  character layer and hands complete TPDUs to `ss_transact` — the library is
  TPDU-level, not PHY. The modem drives the lines at class B/C levels (3 V / 1.8 V,
  modem-powered VCC), which rarely match the MCU's I/O bank: level shifting /
  current-voltage adjustment between modem and MCU is normally required.
- A modem-vendor remote-SIM message protocol (UART/USB): APDUs arrive as messages
  and `ss_application_apdu_transact` fits directly.

This is the only topology where reset is signalled electrically (RST pin or protocol
event → `ss_reset`); storage and keys live entirely on the MCU.

```
┌─ modem ──────────────┐                         ┌─ MCU / MPU ─────────────┐
│                      │                         │                         │
│ SIM driver + PHY     │      7816 pins, T=0     │ 7816 UART glue          │
│ (class B/C levels)   │  ◄───────────────────►  │  └─► ss_transact()      │
│                      │     (level shifting)    │                         │
│                      │                         │ message glue            │
│                      │   remote-SIM messages   │  └─► ss_application_    │
│                      │  ◄───────────────────►  │       apdu_transact()   │
└──────────────────────┘       (UART / USB)      └─────────────────────────┘
                                                              ▼
                                                          MCU flash
```

Both topologies provide [the port surface](#the-port-surface); the external-MCU
topology additionally owns the 7816/transport layer, which is out of scope for this
library.

## Building with CMake

Consume with `add_subdirectory`: tests are auto-disabled for embedded projects
(project-name gate in the root [`CMakeLists.txt`](../CMakeLists.txt)). `install()` is
not usable as shipped — `TARGET_CPU` is never set and no target sets `PUBLIC_HEADER`,
so headers are never installed; link the static archives from the build tree instead.
**Link order matters**: `uicc milenage crypto storage [utils]`.

Options (root `CMakeLists.txt`; echoed at compile time by
[`config.h`](../include/onomondo/softsim/config.h)):

| Option | Effect |
|---|---|
| `CONFIG_USE_SYSTEM_HEAP` | `malloc`/`free` instead of `port_malloc`/`port_free` |
| `CONFIG_USE_LOGS` | `SS_LOGP` is live and links against `ss_logp` — which **you** must provide (see [Logging](#logging)) |
| `CONFIG_COMPACT_STORAGE` | `storage_compact.c` backend, binary `.def`; **drops `fs.c`** (see [Storage](#storage-backends)) |
| `CONFIG_NO_DEFAULT_IMPL` | Drops the default POSIX `fs.c` (and the utils key-load default) |
| `CONFIG_ALT_FILE_SEPARATOR` | `_` instead of `/` in storage paths — flat, directory-less stores |
| `CONFIG_EXTERNAL_CRYPTO_IMPL` | You provide the five functions of [`crypto.h`](../include/onomondo/softsim/crypto.h) |
| `CONFIG_EXTERNAL_KEY_LOAD` | Keys resolved via weak `ss_load_key_external()` at use. Mutually exclusive with the above (`#error`-enforced) |
| `CONFIG_USE_UTILS` | Adds the `utils` lib: profile decode + provisioning |
| `CONFIG_USE_EXPERIMENTAL_SUSPEND_COMMAND` | SUSPEND UICC support |
| `CONFIG_BUILD_LIB_ONLY` | Skips the unix `softsim` demo executable |
| `CONFIG_DISABLE_SMS` | Drops the SMS codec and rx/tx and, with them, RFM/OTA remote commands, AES decrypt, AES-CMAC and the REFRESH they drive (incl. both changed-file lists). CAT stays: TERMINAL PROFILE answers `9000`; an SMS-PP DOWNLOAD envelope answers `6F00`, which TS 31.111 clause 7.1.1.1 maps to an RP-ACK, and logs an error. Leave EF.UST service n°28 set: clearing it makes the terminal store class-2 messages in EF.SMS, which the shipped `files/` tree does not have |
| `CONFIG_ENABLE_SANITIZE` / `CONFIG_BUILD_FUZZERS` | Development builds only |
| `CONFIG_SS_STORAGE_PATH_DEFAULT` (`"./files"`), `CONFIG_SS_STORAGE_PATH_MAX` (`100`) | Storage root and path-length cap |

## The port surface

### File I/O

Ten weak symbols in [`fs.h`](../include/onomondo/softsim/fs.h) — `ss_fopen`,
`ss_fclose`, `ss_fread`, `ss_fwrite`, `ss_file_size`, `ss_delete_file`,
`ss_delete_dir`, `ss_fseek`, `ss_access`, `ss_create_dir` — with stdio semantics.
Default POSIX implementation: [`src/softsim/fs.c`](../src/softsim/fs.c). Two hazards:

- `fs.c` also holds the only definitions of `storage_path`, `ss_storage_set_path()`
  and `ss_storage_get_path()` (declared in
  [`storage.h`](../include/onomondo/softsim/storage.h)). Any build that drops it —
  `CONFIG_COMPACT_STORAGE` *or* `CONFIG_NO_DEFAULT_IMPL` — must provide those three
  as well, not just the ten `ss_f*` functions.
- The default `ss_delete_dir` shells out to `rm -rf` — unix-only by construction.
- Write timing: the MILENAGE SEQ files (`a100`–`a11f`) are updated on every
  AUTHENTICATE. A flash-backed port must sustain frequent small writes and must not
  defer them — a lost SEQ update can replay an authentication vector.

### Heap

Without `CONFIG_USE_SYSTEM_HEAP`, provide `void *port_malloc(size_t)` and
`void port_free(void *)`. `port_free(NULL)` must be a no-op — cleanup paths free
unconditionally ([`mem.h`](../include/onomondo/softsim/mem.h)).

### Logging

With `CONFIG_USE_LOGS`, provide `ss_logp()` against
[`log.h`](../include/onomondo/softsim/log.h) — the reference implementation
([`src/softsim/uicc/log.c`](../src/softsim/uicc/log.c)) is only compiled into test
builds, precisely so hosts write their own. Format strings use C99 length modifiers
(`%zu`); the printf behind your `ss_logp` must support them. Without the option,
`SS_LOGP` compiles to nothing and no symbol is needed.

### Crypto

Software AES is built in (vendored hostap primitives). Two swap points:

- `CONFIG_EXTERNAL_CRYPTO_IMPL` — provide exactly the three functions of
  [`crypto.h`](../include/onomondo/softsim/crypto.h): `ss_utils_aes_encrypt/decrypt`,
  `ss_utils_ota_calc_cc`. With `CONFIG_DISABLE_SMS` only `ss_utils_aes_encrypt` is
  referenced.
- `CONFIG_EXTERNAL_KEY_LOAD` — keep the software crypto, resolve key material through
  the weak `ss_load_key_external()`
  ([`ss_crypto_extension.h`](../include/onomondo/utils/ss_crypto_extension.h)) so the
  filesystem can hold key *references* instead of keys. Current coverage: the AES and
  CC paths (not the MILENAGE K/OPc read from file `a001`).

## Storage backends

| | [`storage.c`](../src/softsim/storage.c) (default) | [`storage_compact.c`](../src/softsim/storage_compact.c) |
|---|---|---|
| `<fid>` / `<fid>.def` encoding | ASCII hex text | raw binary |
| `FCP_MAX_LEN` | 1024 | 200 |
| default `ss_f*` port | POSIX `fs.c` included | dropped — host provides everything |
| intended host | unix filesystem | flash-backed embedded store |

Both address files as `storage_path + /3f00/7ff0/6f07(.def)` (32-bit proprietary FIDs
as 8 hex digits; `CONFIG_ALT_FILE_SEPARATOR` flattens the separators to `_`).

## Provisioning

- The [`files/`](../files) tree **is** the card: identity, keys, PINs and OTA keys are
  files (see [architecture.md](architecture.md#storage-stack)). Ship it to the target
  and point `ss_storage_set_path()` at it (default `./files`).
- ROM images: [`utils/files-c-array/toCArray.py`](../utils/files-c-array/toCArray.py)
  renders `files/` into C arrays (binary flavor for the compact backend, hex for the
  default).
- Personalization writes a subscriber into that tree from a profile string. It needs
  `CONFIG_USE_UTILS`; the API is in
  [`ss_profile.h`](../include/onomondo/utils/ss_profile.h) (decode) and
  [`ss_provision.h`](../include/onomondo/utils/ss_provision.h) (write).

### The profile string

Hex `TAG|LEN|DATA` records: `TAG` and `LEN` are two hex characters each, `DATA` is
`LEN` hex characters. Records may come in any order; unknown tags are skipped.

| Tag | Field | Written to |
|---|---|---|
| `01` | IMSI | EF.IMSI `3f00/7ff0/6f07` |
| `02` | ICCID | EF.ICCID `3f00/2fe2` |
| `03` / `04` | OPc / Ki | `3f00/a001`: Ki, OPc, OPc flag |
| `05` / `06` | KIC / KID | `3f00/a004`, record 1 |
| `07` / `0c` | SMSP / SMSC | EF.SMSP `3f00/7ff0/6f42`, record 1 (SMSC patched inside it) |
| `08` / `09` / `0a` / `0b` | PIN1 / PIN2 / ADM / PUK | `3f00/a003`, the PIN code file |
| `fe` | CRC32 of everything before it | — optional; checked when present |
| `ff` | END | — records after it are ignored |

ICCID, IMSI, Ki and OPc are required. Everything else is optional, and a field the
profile does not carry leaves its EF as it is, with two deliberate exceptions:

- `a004` is always rewritten. It starts erased and gets only the OTA keys the profile
  carries, so a profile without KIC/KID turns OTA off instead of leaving the
  template's keys usable.
- `a003` is patched, never replaced: only the PINs the profile names change. Each new
  PIN or PUK also gets its failed attempt counter reset to 0, so a blocked PIN works
  again with its new value. Everything else in the record headers (enabled flag, max
  tries, key reference) and every counter of a value the profile doesn't set is kept.
  A tree without `a003` is accepted.

### One call

```c
#include <onomondo/utils/ss_provision.h>

if (onomondo_profile_provisioning(profile_string) != 0)
	/* malformed, missing a required field, or a write failed */;
```

Decodes, writes and wipes the decoded keys from RAM. The string `"00"` unbinds the
card instead (see [Unbinding](#unbinding)). Returns `0` on success; on failure, the
parser's `enum ss_profile_err` value for a malformed string, or `-1` (a `NULL`
string included). The reason goes to the log (`CONFIG_USE_LOGS`).

### Decode, edit, write

For a platform that must act on the profile between decoding and writing — typically
moving Ki, KIC and KID into a hardware key store so the filesystem only holds
references to them:

```c
#include <onomondo/utils/ss_profile.h>
#include <onomondo/utils/ss_provision.h>

/* "00" is a command, not a profile: the parser refuses it. */
if (ss_profile_is_unbind(s, strlen(s)))
	return platform_unbind();                        /* see Unbinding */

struct ss_profile p;
uint8_t rc = ss_profile_from_string(strlen(s), s, &p);  /* enum ss_profile_err */
if (rc != SS_PROFILE_OK)
	return rc;                                       /* p is already wiped */

/* Validate first: a refused profile must not replace the keys of the current one. */
if (!ss_profile_has_required_tags(&p)) {        /* ICCID, IMSI, Ki, OPc */
	ss_profile_wipe(&p);
	return -1;
}

/* platform_protect_key() is yours to write; see below. */
int err = platform_protect_key(KI_TAG, p.ki);
if (!err && ss_profile_has_tag(&p, KIC_TAG))
	err = platform_protect_key(KIC_TAG, p.kic);
if (!err && ss_profile_has_tag(&p, KID_TAG))
	err = platform_protect_key(KID_TAG, p.kid);

if (!err)
	err = ss_profile_write_to_fs(&p);    /* writes each field whose tag is set, as found */
if (err)
	platform_forget_key(KI_TAG);         /* keep key store and files consistent */
ss_profile_wipe(&p);                         /* the caller wipes, always */
```

The library defines no key store. `platform_protect_key(tag, field)` stands for
whatever the platform does with a key, in two steps:

1. Take the key out of `field` (`KEY_SIZE` hex characters) and keep it wherever the
   platform keeps keys: a secure element, PSA key slots, a crypto peripheral.
2. Overwrite `field` in place with what the EF should hold instead, as `KEY_SIZE` hex
   characters. That can be a slot number, a key ID, or a handle — anything the
   platform's key loader can map back to the key. The library never reads it; it
   only writes it where the key would have gone.

`platform_forget_key()` undoes step 1 when writing fails, so the device reads as
not provisioned rather than as provisioned with keys that don't match its files.

- Every field in `struct ss_profile` is lower case hex characters, whatever case the
  string used: lower case is the format of the EFs. An edited field must stay lower
  case hex of the same length; the writer stores fields as they are.
- The writer decides on the tags, never on field contents: an edited field is written
  as long as its tag stays set.
- At run time the card code reads the reference from the EF and hands it to the
  crypto; with `CONFIG_EXTERNAL_KEY_LOAD` that is `ss_load_key_external()` (see
  [Crypto](#crypto)), which must resolve it to the key. That path does not cover the
  MILENAGE Ki/OPc read from `a001` yet, so a Ki reference also needs the platform's
  own MILENAGE.
- [`profile_provision_test.c`](../tests/utils/profile_provision_test.c) runs this flow
  against a hypothetical key store, with the record tag as the reference.

### Storage form

Callers always hand over hex; the writer stores each EF in the backend's form: hex
text with the default backend, the bytes it spells with `CONFIG_COMPACT_STORAGE`
(every offset and length halved). `CONFIG_ALT_FILE_SEPARATOR` works with both. The
provisioning tests run against all four combinations.

### Is the card provisioned?

`onomondo_profile_check_provisioned()` returns `1` while EF.IMSI holds a real
subscriber, and `0` when it is missing, short, all zeros, or still the template's
default IMSI (`080910100000000010`).

### Unbinding

Provisioning the string `"00"` removes the subscription instead of loading one.
`onomondo_profile_provisioning("00")` does it, and so does calling
`onomondo_profile_unbind()` directly. A platform with its own provisioning entry point
(the [decode, edit, write](#decode-edit-write) flow) recognises the command with
`ss_profile_is_unbind()`, which takes a length, so the buffer needn't be NUL
terminated. With a key store, its `platform_unbind()` looks like this:

```c
#include <onomondo/utils/ss_profile.h>
#include <onomondo/utils/ss_provision.h>

static int platform_unbind(void)
{
	int err = onomondo_profile_unbind();   /* a failure may already read as not provisioned: retry */
	if (!err)
		err = platform_commit_fs();     /* persist first, if the platform caches files */
	if (!err) {
		platform_forget_key(KI_TAG);    /* the EFs only held references */
		platform_forget_key(KIC_TAG);
		platform_forget_key(KID_TAG);
	}
	return err;
}
```

`platform_commit_fs()` stands for whatever makes the writes durable on a platform
that caches its files (the nRF91 port's `port_commit_fs()`); drop it where writes go
straight to storage. `platform_forget_key()` is the one from
[decode, edit, write](#decode-edit-write).

| EF | After `"00"` |
|---|---|
| EF.IMSI | the template's default IMSI, so `onomondo_profile_check_provisioned()` returns `0` |
| EF.ICCID | all zeros |
| `a001` | Ki and OPc all zeros |
| `a004` | erased (all `f`): OTA off |
| `a003`, EF.SMSP | kept: PINs and SMS settings are not the subscription's |

- Only `"00"` exactly. The parser can never accept it as a profile (a record needs at
  least 4 characters), so no real profile is mistaken for it. Strip line endings
  first, as for a profile: `"00\r\n"` is refused.
- It goes through the same writer as a profile, so the default IMSI is written first:
  an unbind that fails partway still leaves a card that reads as not provisioned.
  Unbinding a card that is not provisioned succeeds.
- A card provisioned again after `"00"` behaves like a fresh one.
- With a key store, the EFs held references, so clearing them leaves the keys in the
  store. Destroy the slots only after the unbind succeeded (and was persisted): a
  failed unbind then still has the keys a retry expects. Make the platform's key
  loader refuse an all-zero reference rather than resolve it to a slot.
- On flash filesystems, old blocks can keep the previous contents until the
  filesystem reuses them. Wiping those, if the threat model needs it, is the port's
  job.
- A modem that caches the SIM, such as the nRF91's, keeps the old identity until it
  reads the SIM again (e.g. `AT+CFUN=4`, then `AT+CFUN=1`).
