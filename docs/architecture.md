# Architecture

The code view, for people changing this library.

## Build targets

| Target | Sources | Role |
|---|---|---|
| `uicc` | [`src/softsim/uicc/`](../src/softsim/uicc) | The card: APDU codec + dispatch, filesystem, PIN, authentication glue, CAT, OTA |
| `milenage` | [`src/softsim/milenage/`](../src/softsim/milenage) | 3GPP AKA f1–f5*, plus the USIM-side SQN check (`milenage_usim.c`) |
| `crypto` | [`src/softsim/crypto/`](../src/softsim/crypto) | Vendored AES and DES primitives (hostap/wpa_supplicant) |
| `storage` | [`src/softsim/`](../src/softsim) | Persistence backend: `storage.c` *or* `storage_compact.c`, plus the default POSIX port `fs.c` when applicable |
| `utils` (`CONFIG_USE_UTILS`) | [`utils/`](../utils) | Profile decoding and provisioning — off the spec path |
| `softsim` (exe, skipped by `CONFIG_BUILD_LIB_ONLY`) | [`src/softsim/main.c`](../src/softsim/main.c) | vsmartcard/VPCD TCP host (port `0x8C7B`), demo only |

Static archives with no declared interdependencies — link order matters:
`uicc milenage crypto storage [utils]` ([`src/softsim/CMakeLists.txt`](../src/softsim/CMakeLists.txt)).

### Naming traps

- Two `fs.c`: [`src/softsim/uicc/fs.c`](../src/softsim/uicc/fs.c) is the **card**
  filesystem (select, records, EF.ARR lookup); [`src/softsim/fs.c`](../src/softsim/fs.c)
  is the default POSIX implementation of the `ss_f*` **host port** declared in
  [`fs.h`](../include/onomondo/softsim/fs.h).
- Two `crypto.h`: [`include/onomondo/softsim/crypto.h`](../include/onomondo/softsim/crypto.h)
  is the library's crypto contract; [`src/softsim/crypto/crypto.h`](../src/softsim/crypto/crypto.h)
  is the verbatim hostap wrapper header.
- `softsim` the *executable* is `main.c`; the *API implementation* is
  [`src/softsim/uicc/softsim.c`](../src/softsim/uicc/softsim.c), inside lib `uicc`.

## Core state

One [`struct ss_context`](../src/softsim/uicc/context.h) per card:

```
ss_context
├── lchan: ss_lchan                the one and only logical channel (uicc_lchan.h)
│   ├── pin_verfied[256]           indexed by key reference; the typo is the field name.
│   │                              Read only through uicc_pin.c; setup_ctx_from_tar is
│   │                              the one sanctioned direct writer.
│   ├── fs_path                    selected path as a list of ss_file, MF first
│   ├── adf_path                   last selected ADF
│   ├── current_record             record pointer for record-oriented EFs
│   └── last_apdu (+ keep flag)    backing store for GET RESPONSE
├── proactive: ss_proactive_ctx    TERMINAL PROFILE, pending FETCH data, SMS RX/TX,
│                                  REFRESH state (proactive.h)
├── fs_chg_filelist                changed-file accumulator, 2000 B = 100 × 20-byte
│                                  paths (fs_chg.h); feeds REFRESH
├── fs_chg_record / fs_chg_is_borrowed
└── is_suspended
```

[`struct ss_apdu`](../src/softsim/uicc/apdu.h): fixed `cmd[256]`/`rsp[256]`, `lc`
*includes the Le byte* for case-4 commands (and may exceed that in remote commands),
`processed_bytes` tells the dispatcher how much of a multi-command buffer was consumed.

Two constructors in `softsim.c`: `ss_new_ctx()` for the terminal-facing card and
`ss_new_reporting_ctx()` for the throwaway [OTA context](#the-rfm-inner-context).

## APDU flow

`ss_transact()` / `ss_application_apdu_transact()`
([`softsim.c`](../src/softsim/uicc/softsim.c)) → `apdu_transact()`:

1. CLA checks: secure-messaging bits → `6882`, unknown CLA → `6E00`.
2. GET RESPONSE is special-cased before the table — it needs `lchan->last_apdu`.
3. `ss_command_match()` on `(cla & cla_mask, ins)` against the table in
   [`command.c`](../src/softsim/uicc/command.c); no match → `6D00`.
4. The handler runs after command-case validation; pending proactive data rewrites a
   successful SW to `91xx`.
5. On an unsuccessful SW (except `6Cxx`) the previously selected path is restored from
   a backup taken before dispatch (`softsim.c`, search `backup_path`).

## Storage stack

```
uicc/fs.c ── ss_storage_* ── storage.c | storage_compact.c ── ss_f* ── host
(card FS)    (storage.h)     (backend, build-time choice)     (fs.h)
```

On the host side of the backend, a DF is a directory and an EF is two entries:
`<fid>` (content) and `<fid>.def` (the FCP). `storage.c` writes both as ASCII hex
text; `storage_compact.c` writes binary. Paths are `%04x` per hop (`%08x` for 32-bit
FIDs), rooted at `storage_path`; `CONFIG_ALT_FILE_SEPARATOR` swaps `/` for `_`
(flat, directory-less stores).

Proprietary files use 32-bit FIDs, unreachable by SELECT (which takes 16-bit FIDs):

| FID | Content | Layout reference |
|---|---|---|
| `a001` | K (16 B), OP or OPc (16 B), flag (1 B; `01` = OP, derive OPc) | `get_key_data()` in [`uicc_auth.c`](../src/softsim/uicc/uicc_auth.c) |
| `a003` | PIN records: state + retry counters | [`uicc_pin.c`](../src/softsim/uicc/uicc_pin.c) |
| `a004` | OTA key records: `TAR(3) MSL(1) KIC-ind(1) KID-ind(1) KIC(16) KID(16)` | header comment in [`uicc_remote_cmd.c`](../src/softsim/uicc/uicc_remote_cmd.c) |
| `a005` | OTA counters: 5-byte CNTR per TAR | `get_cntr_from_tar()` in `uicc_remote_cmd.c` |
| `a100`–`a11f`, `a120` | 32 SEQ buckets (8 B big-endian each) + delta | `get_seq_data()` in `uicc_auth.c` |
| `5f100001` | per-DF SFI→FID registry, 31 × 2-byte records, record index = SFI | [`sfi.c`](../src/softsim/uicc/sfi.c) |

Quirk: every `0xa1xx` file resolves to the single `a100.def`
(`gen_abs_host_path()` in [`storage.c`](../src/softsim/storage.c)).

## The RFM inner context

`process_commands()` ([`uicc_remote_cmd.c`](../src/softsim/uicc/uicc_remote_cmd.c))
executes OTA command strings on a second context from `ss_new_reporting_ctx()`, which
*borrows* the outer context's `fs_chg_filelist` (`fs_chg_is_borrowed`). File changes
recorded there surface later as a REFRESH proactive command
([`uicc_refresh.c`](../src/softsim/uicc/uicc_refresh.c) ←
[`fs_chg.c`](../src/softsim/uicc/fs_chg.c)).

## Testing

**Golden transcripts.** Most suites run a plain-C `main()`, redirect stdout, and
`cmake -E compare_files --ignore-eol` against a committed `.ok` file. Consequence:
changing log output breaks goldens; the fix is regenerate, review the diff, commit.
`BUILD_TESTING` changes the build: it adds `log.c` to lib `uicc` and defines
`CONFIG_USE_LOGS` ([`src/softsim/uicc/CMakeLists.txt`](../src/softsim/uicc/CMakeLists.txt))
and force-defines `CONFIG_USE_SYSTEM_HEAP` ([root `CMakeLists.txt`](../CMakeLists.txt)).
Tests never build when the repo is consumed via `add_subdirectory` (project-name gate).

| Suite(s) | Covers |
|---|---|
| `init`, `app_transact` | End-to-end APDU transcripts (modem boot; extended-length encodings) |
| `apdu`, `fcp`, `btlv`, `ctlv`, `tlv8` | Wire-format codecs |
| `access` | Access rules, incl. a guard against an `-DNDEBUG` bootstrap-bypass regression |
| `pin`, `read_binary` | Command behavior over the real APDU path |
| `ota`, `envelope`, `des` | OTA padding counts; end-to-end ENVELOPE → remote command; DES vectors. Skipped with `CONFIG_DISABLE_OTA` |
| `sms` | Skipped with `CONFIG_DISABLE_SMS` |
| `opt_out` | Only with `CONFIG_DISABLE_OTA` / `CONFIG_DISABLE_SMS`: CAT alive, OTA short message answered per TS 31.111 |
| `aes` | Crypto vectors |
| `utils`, `storage`, `list` | Helpers, storage-path edge cases, intrusive list |
| `suspend` | Only with `CONFIG_USE_EXPERIMENTAL_SUSPEND_COMMAND=y` |
| `key_scrub` | Linux-only; wraps `free()` to prove K/OPc never reach the allocator in the clear |
| `sfi_check.sh` | SFI registry records match the FCP `88` tags in `files/` |

**Interactive rig.** The `softsim` executable speaks VPCD; drive it with
pySim-shell or pcsc-tools per the [README](../README.md) Getting Started.
[`gscriptor/`](../gscriptor) holds raw-APDU scripts (select, read/update, PIN,
create/delete, OTA SMS) for pcsc-tools' gscriptor — an APDU cookbook against the
running card. [`utils/files-creation/`](../utils/files-creation) holds the pySim
scripts that built `files/` on a blank card; each `create_ef` line cites its
TS 102 221 clause and access-condition byte.
