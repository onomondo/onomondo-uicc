# Fuzz targets

libFuzzer harnesses for the parsers that sit on a trust boundary: the two APDU
entry points (bytes from the modem) and the provisioning profile blob (bytes
from a factory tool, an AT command or a FOTA payload).

Not built by default. Requires clang.

## Two modes, one binary

| Mode | Command | When |
|---|---|---|
| Corpus replay | `<target> <corpus> -runs=0` | Every PR, as `ctest` cases `fuzz_*_corpus`. Deterministic, well under a second. A fixed crash whose reproducer is in the corpus stays fixed. |
| Searching | `<target> <corpus> -max_total_time=N` | The release-please release PR and manual dispatch. See the `fuzz` job in `.github/workflows/fuzz.yml`. |

Fuzzing on every PR buys nothing: the run is time-boxed, so it either repeats
what the corpus already covers or reports something unrelated to the change
under review.

## Running it

Everything runs in a container.

```sh
docker run --rm -v "$PWD:/src:ro" -v /tmp/ssfuzz:/out -e CC=clang \
  -w /src ubuntu:24.04 bash -c '
    apt-get update && apt-get install -y cmake ninja-build clang libclang-rt-18-dev llvm-18 python3
    cmake -S /src -B /out/build -G Ninja \
      -DBUILD_TESTING=y -DCONFIG_BUILD_FUZZERS=y -DCONFIG_USE_UTILS=y -DCONFIG_USE_SYSTEM_HEAP=y
    cmake --build /out/build
    cd /out/build && ctest --output-on-failure -R "_corpus\$"   # corpus replay
    ./tests/fuzz/fuzz_apdu_t0 ./tests/fuzz/corpus/apdu -max_total_time=600 -max_len=261
  '
```

`libclang-rt-18-dev` is not optional: `apt-get install clang` alone ships no
sanitizer runtimes, and the link fails with `libclang_rt.asan-<arch>.a: No such
file`. The GitHub `ubuntu-24.04` runner happens to preinstall them, a plain
container does not.

`llvm-18` carries `llvm-symbolizer`. Without it an ASan report is frame
addresses and `BuildId` lines with no function or source location, which makes
a finding almost impossible to triage. UBSan is unaffected -- it embeds the
source location at compile time.

Pass `-artifact_prefix=<dir>/` when searching. Without it libFuzzer drops
`crash-*` / `leak-*` reproducer files into the current directory, which is
usually the repository.

A search also writes every input it keeps back into the first corpus directory
on its command line, so searching `corpus/apdu` directly grows the seed set the
`ctest` replay then reads. Copy the directory first if you want the replay to
keep replaying the generated seeds and nothing else.

## Targets

| Target | Entry point | Notes |
|---|---|---|
| `fuzz_apdu_t0` | `ss_transact()` | The T=0 / VPCD path. Copies a fixed-size header. |
| `fuzz_apdu_app` | `ss_application_apdu_transact()` | The path the nRF modem glue calls. Parses via `ss_apdu_parse_exhaustive()`. |
| `fuzz_apdu_parse` | `ss_apdu_parse_exhaustive()` | The wire-format parser directly, no card behind it. |
| `fuzz_profile` | `ss_profile_from_string()` | Needs `-DCONFIG_USE_UTILS=y`. |

Both APDU harnesses share `fuzz_apdu.c`, compiled once per entry point with
`-DFUZZ_ENTRY=<symbol>`; the two functions take the same arguments but do not
share a parser.

`fuzz_apdu_parse` exists because the entry points truncate requests to 260
bytes before parsing, so no input driven through them can reach the parser's
extended-Lc arithmetic past that limit -- `Lc = 257` (a 264-byte request) is
the first length that clears the data-field bound and would overrun `cmd[]`.
That overrun lands in `rsp[]`, the adjacent member of the same struct, so ASan
never faults on it; the harness instead asserts two post-conditions after each
parse: `lc` fits `cmd[]`, and `processed_bytes` does not exceed the request.
The corpus pins witnesses at the boundary lengths (over-claiming short Lc at
6-10 bytes, extended Lc 255/256/257 at 262-264 bytes), so weakening either
guard in the parser fails the deterministic corpus replay on the next PR.

The seed corpus is generated at build time by `gen_corpus.py` from two
transcripts the suite already maintains, so it tracks them rather than drifting
from them: `tests/init/init_test.c` for short-form modem initialisation, and
`tests/app_transact/app_transact_test.c` for the extended-length encodings.
Extended length is selected by a single zero byte at offset 4, so an extended
seed is what puts `fuzz_apdu_app` inside those branches from the first
execution instead of leaving it to find the encoding by mutation.

## Known limits

- **The staged EF tree is shared between executions.** Each input gets a fresh
  `ss_context`, but the on-disk filesystem persists for the life of the
  process, so a crash that depends on an earlier input having written to it
  will not replay standalone. The upgrade path is an in-memory storage backend
  behind `CONFIG_NO_DEFAULT_IMPL`.
- **LeakSanitizer only exists on Linux.** Leak findings will never appear on a
  macOS host; this is one of the reasons the workflow is container-only.
- **If ASan aborts at startup** with `Shadow memory range interleaves with an
  existing memory mapping`, that is the Ubuntu 24.04 ASLR entropy clash, not a
  bug in the harness. Run the container with `--privileged`, or set
  `vm.mmap_rnd_bits=28` in the Docker VM.
