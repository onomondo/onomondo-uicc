# KLEE targets

Symbolic execution of the parsers and command handlers that sit on a trust
boundary. Where the fuzzer (`tests/fuzz`) throws random bytes and waits for a
crash, KLEE solves the branch conditions and reports the **exact APDU byte
sequence** that drives a given path -- or proves no such sequence exists, which
a fuzzer can never do.

Not built by default. Requires a KLEE toolchain, so everything runs in the
`klee/klee` container.

## Two targets

| Target | Entry point | Guarantee |
|---|---|---|
| Parser | `ss_apdu_parse_exhaustive()` | **Exhaustive** per input length. Libc-free (logs compiled out), so KLEE needs no libc model. |
| Card path | `ss_application_apdu_transact()` | **Directed, time-bounded.** The class/instruction header is pinned per command and only the DATA field is symbolic, so one run explores one handler. Not a proof -- see "Known limits". |

The card-path target links the whole library against an in-memory `ss_f*`
backend (`src/softsim/fs_ram.c`) seeded from `utils/files-c-array`, so the card
image lives in RAM: no `fopen`, and each forked path gets its own copy-on-write
filesystem.

## Running it

```sh
docker run --rm --platform linux/amd64 \
  -v "$PWD:/src:ro" -v /tmp/klee-out:/out -w /src klee/klee:3.0 \
  bash /src/tests/klee/run.sh /out                    # parser sweep + verdict diff
```

`--platform linux/amd64` is only needed off x86-64 (the image is amd64-only); on
an Apple-silicon host enable Docker Desktop's "Use Rosetta for x86/amd64
emulation" -- the full parser sweep still finishes in about a minute. The repo
is mounted read-only: the script writes only under `/out`.

Other invocations:

```sh
bash tests/klee/run.sh /out apdu 264                  # one length, checked against expected.txt
bash tests/klee/run.sh /out transact select           # full card path for one command
bash tests/klee/run.sh /out transact envelope          # ... the BER-TLV / OTA gateway
```

`run.sh` prints one verdict line per length/command to stdout and the exact
witness APDU for every saved test case to stderr, e.g.

```
len=6: assert@klee_apdu.c:63 ptr@apdu.c:122 ptr@memcpy.c:17
  len=6 test000001.ktest: ffffffff02ff        # short Case 4, reads one byte past a 6-byte APDU
transact:select: no errors (exhaustive)
  transact:select test000006.ktest: 00a40004023f00   # the file id that selects the MF
```

## The verdict contract (`expected.txt`)

`klee(1)` exits 0 even when it finds errors, so the error files it writes are the
signal, not the exit code. `run.sh` distils each run to one line -- a sorted list
of `type@file:line`, or `no errors (exhaustive)`, or `TIMEOUT` (a run that halts
on `--max-time` is never reported as clean, because a halt voids the
exhaustiveness claim) -- and diffs the parser sweep against `expected.txt`. Any
drift fails the run. This is the golden regression check: editing the parser must
state its effect on the verdict, exactly as the `.ok` files do for the unit
tests.

`expected.txt` records the parser's behaviour with the bounds fixes on `master`
underneath. Every length is clean; two of them are worth reading off it:

- **`len=264` is `no errors (exhaustive)` because of one clause.** `Lc = 257`
  clears the data-field bound, and the copy stays inside the allocation while
  writing one byte past `cmd[256]` into `rsp[0]` -- so nothing faults and only
  `assert(apdu.lc <= sizeof(apdu.cmd))` catches it. Drop the
  `lc > sizeof(apdu->cmd)` clause from the parser and this line flips to
  `assert@klee_apdu.c:61`. That is the proof the clause is load-bearing rather
  than belt-and-braces, and no fuzzer can supply it: 264 is the only length that
  reaches the case.
- **`len=6..10` is clean because the `out:` guard clamps `processed_bytes`.** A
  short Case 4 derives it from the declared `Lc` as `5 + lc + 1`, which runs
  past the request. Drop the clamp and these five lines flip to
  `assert@klee_apdu.c:63`; the witness at `len=7` is `ffffffff03ffff`, which
  would report `processed_bytes = 9` for a 7-byte buffer.

Regenerate the file from a fresh run whenever the parser changes; the diff is
the evidence of what the change closed or opened.

## CI

The `klee` job runs the parser sweep and the backend self-test in the
`klee/klee` container on every PR. Unlike the `fuzz` search, this is not a
time-boxed run: the sweep is deterministic and ~1 min, so it belongs on the PR
path next to the `fuzz-corpus` replay. The golden check is green when the
verdict matches `expected.txt`, and turns red when the parser behaves
differently without `expected.txt` being regenerated -- which is the point.

## Known limits

- **The card path is not exhaustive.** Reachable states are bounded by
  `--max-time`, and only the DATA field is symbolic (the header is pinned to one
  command). A clean card-path run means "no error in the part of the tree
  explored", not "no error exists". The parser target carries the exhaustive
  guarantee; the card path is directed exploration. `select` completes in
  seconds and its witnesses are the exact file ids that select each EF (e.g.
  `00a40004023f00` -> the MF); `envelope` reaches the BER-TLV decoder and does
  not complete in the budget.
- **A symbolic TLV length becomes a symbolic allocation size, which KLEE
  concretizes.** `envelope` reports `model@utils.h:39`: `ss_buf_alloc()` is
  called with `16 + <a symbolic length byte>`, and KLEE cannot allocate a
  symbolic-sized object, so it concretizes and warns. This is a property of the
  tool, not a defect in the decoder -- treat `model@...` verdicts as "KLEE gave
  up on this path", not as findings.
- **A witness's bytes are not part of the golden check.** They go to stderr for
  humans: an STP/Z3 update can pick a different satisfying model at the same KLEE
  version, so only the `type@file:line` verdict is diffed.
- **`--libc=uclibc` for the card path, `none` for the parser.** The parser pulls
  in only `memcpy`/`memset`/`malloc`/`assert`; the storage layer additionally
  needs `snprintf`/`strtoul`, hence uclibc there. Keep `CONFIG_USE_LOGS` off in
  both -- logging routes through `vsnprintf` on every path and would both need a
  libc and bloat the state space.
