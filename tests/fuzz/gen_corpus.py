#!/usr/bin/env python3
# Copyright (c) 2026 Onomondo ApS. All rights reserved.
# SPDX-License-Identifier: GPL-3.0-only

"""Generate libFuzzer seed corpora.

The APDU seeds are lifted from the transcripts the test suite already
maintains, so the corpus tracks them instead of drifting from them:
tests/init/init_test.c covers modem initialisation in short form, and
tests/app_transact/app_transact_test.c carries the extended-length encodings,
including the STATUS with an extended Le that the nRF9151 sends. The profile
seeds are built from the TLV layout documented in
include/onomondo/utils/ss_profile.h.

Without a seed corpus the fuzzer spends its budget rediscovering the wire
format instead of exploring behind it; see README.md for the rationale.
"""

import argparse
import hashlib
import pathlib
import re

# Quoted, even-length, pure-hex string literals. In these transcripts those are
# all APDU vectors (the apdus[] arrays plus init_test.c's short-APDU cases);
# format strings and byte arrays do not match.
HEX_LITERAL = re.compile(r'"((?:[0-9a-fA-F]{2})+)"')


def write_seeds(out_dir, blobs):
    """Write one file per distinct blob, named by content hash."""
    out_dir.mkdir(parents=True, exist_ok=True)
    for stale in out_dir.glob("*.bin"):
        stale.unlink()

    written = 0
    for blob in {bytes(b) for b in blobs}:
        name = hashlib.sha1(blob).hexdigest()[:16] + ".bin"
        (out_dir / name).write_bytes(blob)
        written += 1
    return written


def apdu_seeds(transcripts):
    seeds = []
    for transcript in transcripts:
        text = pathlib.Path(transcript).read_text()
        found = [bytes.fromhex(m) for m in HEX_LITERAL.findall(text)]
        if not found:
            raise SystemExit(f"{transcript}: no APDU hex literals found -- has the transcript moved?")
        seeds += found

    # Boundary lengths around the fixed 5-byte header copy in ss_transact().
    # Cheap to include and they are where the length arithmetic goes wrong.
    seeds += [b"", b"\x00", b"\x00\xa4\x00\x0c", b"\x00\xa4\x00\x0c\x02"]

    # Witnesses for fuzz_apdu_parse's post-conditions. Short Case 3/4 requests
    # whose Lc over-claims the buffer pin the processed_bytes clamp (len 6-10);
    # extended-Lc requests at the exact fit and one past it (Lc 255/256/257,
    # len 262/263/264) pin the cmd[] bound. The entry-point targets truncate
    # the long ones, which is harmless.
    seeds += [b"\xff\xff\xff\xff" + bytes([lc]) + b"\xff" * (lc - 1) for lc in range(2, 7)]
    seeds += [b"\x00\xa4\x00\x04\x00" + lc.to_bytes(2, "big") + b"\xff" * lc for lc in (255, 256, 257)]
    return seeds


def profile_seeds():
    def tlv(tag, payload):
        # Both tag and length are themselves hex-encoded in this format.
        return f"{tag:02x}{len(payload):02x}{payload}"

    key = "000102030405060708090A0B0C0D0E0F"
    complete = (
        tlv(0x01, "080910101032540636")   # IMSI
        + tlv(0x02, "98001032547698103214")  # ICCID
        + tlv(0x03, "0" * 32)             # OPc
        + tlv(0x04, key)                  # Ki
        + tlv(0x05, key)                  # KIC
        + tlv(0x06, key)                  # KID
    )

    return [
        complete.encode(),
        (complete + "ff00").encode(),          # explicit END tag
        tlv(0x01, "080910101032540636").encode(),  # single record
        b"",                                    # the degenerate length
    ]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--transcript", required=True, action="append", metavar="PATH",
                    help="C file holding an apdus[] array of hex literals; repeatable")
    ap.add_argument("--out", required=True, type=pathlib.Path)
    args = ap.parse_args()

    n_apdu = write_seeds(args.out / "apdu", apdu_seeds(args.transcript))
    n_profile = write_seeds(args.out / "profile", profile_seeds())
    print(f"fuzz corpus: {n_apdu} apdu seeds, {n_profile} profile seeds -> {args.out}")


if __name__ == "__main__":
    main()
