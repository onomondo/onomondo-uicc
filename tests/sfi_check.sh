#!/bin/sh
# Self-check for the USIM SFI assignments (TS 31.102): the pre-baked lookup
# table and the FCP SFI elements must agree, and the two files a modem
# addresses by SFI during EPS attach must be reachable.
set -eu
D="$(dirname "$0")/../files/3f00/7ff0"
tbl=$(cat "$D/5f100001")

rec() { # rec <sfi-decimal> -> 4-char FID
	echo "$tbl" | cut -c"$((($1 - 1) * 4 + 1))-$(($1 * 4))"
}

[ "$(rec 3)" = 6fad ]   # SFI 03 = EF_AD (TS 31.102 4.2.18)
[ "$(rec 30)" = 6fe3 ]  # SFI 1E = EF_EPSLOCI (TS 31.102 4.2.91)
[ "$(rec 11)" = 6f7e ]  # SFI 0B = EF_LOCI, pre-existing entry untouched

# FCP tag 88 carries SFI<<3 (TS 102 221 11.1.1.4.8)
case "$(cat "$D/6fe3.def")" in *8801f0) ;; *) exit 1 ;; esac
case "$(cat "$D/6fad.def")" in *880118) ;; *) exit 1 ;; esac

echo "sfi_check: OK"
