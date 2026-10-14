# Integration

Consuming this library as a black box — nothing on this page requires editing library
sources.

## The API

[`include/onomondo/softsim/softsim.h`](../include/onomondo/softsim/softsim.h) is the
whole call surface — eight functions. Headers under `src/` are internal.

| Function | Contract |
|---|---|
| `ss_new_ctx()` | Allocate one card context. One context = one card. |
| `ss_free_ctx(ctx)` | Teardown. |
| `ss_reset(ctx)` | Card reset: clears the logical channel, SMS and proactive state. Call on card power-on/off/reset. |
| `ss_atr(ctx, buf, len)` | Writes the ATR, returns its length. Size the buffer for the ISO/IEC 7816-3 §8.1 maximum (TS + 32 = 33 bytes). The ATR declares *no extended Lc/Le* (card-capabilities byte 3, b7=0), matching the fixed 256-byte APDU buffers. |
| `ss_transact(ctx, rsp, rsp_len, req, &req_len)` | T=0 TPDU exchange. `req_len` is in/out: pass what you have (a concatenated stream is legal — input is truncated at 261 = 5-byte header + 256 body), it returns the bytes actually consumed. Requests shorter than the 5-byte header are answered `6700`. |
| `ss_application_apdu_transact(...)` | Same signature, application level: accepts 4-byte case-1 APDUs, auto-issues GET RESPONSE on `61xx` and retries with the corrected length on `6Cxx`. The right entry point for a modem host. |
| `ss_poll(ctx)` | Advances the proactive tasks (SMS-TX, REFRESH). Call periodically — the demo host uses 5 s ([`main.c`](../src/softsim/main.c)). |
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
| `CONFIG_DISABLE_SMS` | Drops the SMS codec and rx/tx and, with them, RFM/OTA remote commands, 3DES and the REFRESH they drive (incl. both changed-file lists). CAT stays: TERMINAL PROFILE answers `9000`; an SMS-PP DOWNLOAD envelope answers `6F00`, which TS 31.111 clause 7.1.1.1 maps to an RP-ACK, and logs an error. Leave EF.UST service n°28 set: clearing it makes the terminal store class-2 messages in EF.SMS, which the shipped `files/` tree does not have |
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

Software AES/DES is built in (vendored hostap primitives). Two swap points:

- `CONFIG_EXTERNAL_CRYPTO_IMPL` — provide exactly the five functions of
  [`crypto.h`](../include/onomondo/softsim/crypto.h): `ss_utils_aes_encrypt/decrypt`,
  `ss_utils_3des_encrypt/decrypt`, `ss_utils_ota_calc_cc`. With `CONFIG_DISABLE_SMS` only
  the two AES functions are referenced.
- `CONFIG_EXTERNAL_KEY_LOAD` — keep the software crypto, resolve key material through
  the weak `ss_load_key_external()`
  ([`ss_crypto_extension.h`](../include/onomondo/utils/ss_crypto_extension.h)) so the
  filesystem can hold key *references* instead of keys. Current coverage: the AES and
  CC paths (not 3DES OTA, not the MILENAGE K/OPc read from file `a001`).

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
- Personalization: a hex `TAG|LEN|DATA` profile string (tags in
  [`ss_profile.h`](../include/onomondo/utils/ss_profile.h)) fed to
  `onomondo_profile_provisioning()`
  ([`ss_provision.h`](../include/onomondo/utils/ss_provision.h), needs
  `CONFIG_USE_UTILS`) overwrites ICCID, IMSI, keys and SMSP in an existing tree.
- ROM images: [`utils/files-c-array/toCArray.py`](../utils/files-c-array/toCArray.py)
  renders `files/` into C arrays (binary flavor for the compact backend, hex for the
  default).
