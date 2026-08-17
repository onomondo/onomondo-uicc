#!/bin/bash
# Copyright (c) 2026 Onomondo ApS. All rights reserved.
# SPDX-License-Identifier: GPL-3.0-only
#
# KLEE driver for onomondo-uicc. Runs inside the klee/klee container; see
# README.md. CMake keeps the "what" (which lengths/commands are tests); this
# script keeps the "how" (bitcode flags, KLEE flags, verdict extraction),
# because none of that fits an add_test() cleanly.
#
# Usage:
#   run.sh <outdir>                 full parser sweep, diff against expected.txt
#   run.sh <outdir> apdu <len>      one length, check against its expected line
#
# klee(1) exits 0 even when it finds errors, so the error files it writes -- not
# the exit code -- are the signal. A run that halts on --max-time is reported as
# TIMEOUT and never as "no errors": a halt voids the exhaustiveness claim.

set -euo pipefail

out=$1
mode=${2:-sweep}
src=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)

# The parser is libc-free with logs off, so KLEE needs no libc model. -O0 keeps
# the arithmetic (and the File:/Line: in error reports) faithful; -disable-O0-optnone
# leaves the door open for --optimize without forcing it. _FORTIFY_SOURCE=0 is
# required: it stops clang emitting __memcpy_chk/__memset_chk, so the copies stay
# as llvm.memcpy, which KLEE lowers to a per-byte bounds-checked loop. NO
# -fsanitize (mutually exclusive with KLEE) and NO CONFIG_USE_LOGS (drags in printf).
CFLAGS=(-emit-llvm -c -g -O0 -Xclang -disable-O0-optnone
	-D_FORTIFY_SOURCE=0 -DCONFIG_USE_SYSTEM_HEAP
	-I"$src" -I"$src/include")

KLEE_FLAGS=(--libc=none --search=dfs --only-output-states-covering-new
	--warnings-only-to-file "--max-time=${KLEE_MAX_TIME:-120}s")

LENGTHS=(4 5 6 7 8 9 10 261 262 263 264)

# Compile the parser once; it does not depend on the length.
build_apdu_lib() {
	clang "${CFLAGS[@]}" -o "$out/apdu.bc" "$src/src/softsim/uicc/apdu.c"
}

# Turn one KLEE output directory into a single verdict string.
#   <error files present>  -> "type@file:line ..." (sorted, unique)
#   <run halted early>     -> "TIMEOUT" (or "<findings> (partial)")
#   <clean and complete>   -> "no errors (exhaustive)"
# A halt is read from KLEE's own log, not from info/warnings, whose command
# echo contains the literal --max-time flag and would match a naive grep.
verdict() {
	local kout=$1 log=$2 errs findings halted=

	grep -qE 'HaltTimer invoked|halting execution' "$log" 2>/dev/null && halted=1

	errs=$(find "$kout" -maxdepth 1 -name '*.err' 2>/dev/null | sort)
	if [ -n "$errs" ]; then
		findings=$(
			for e in $errs; do
				local type file line
				type=$(basename "$e" .err)
				type=${type##*.}
				file=$(awk -F': ' '/^File:/ {print $2; exit}' "$e")
				line=$(awk -F': ' '/^Line:/ {print $2; exit}' "$e")
				echo "$type@$(basename "${file:-?}"):${line:-?}"
			done | sort -u | tr '\n' ' '
		)
		findings=${findings% }
		[ -n "$halted" ] && findings="$findings (partial)"
		echo "$findings"
		return
	fi

	[ -n "$halted" ] && { echo "TIMEOUT"; return; }
	echo "no errors (exhaustive)"
}

# Dump the exact bytes of every witness KLEE saved, to stderr, for humans.
witnesses() {
	local kout=$1 label=$2 t hex
	for t in "$kout"/*.ktest; do
		[ -e "$t" ] || continue
		hex=$(ktest-tool "$t" 2>/dev/null |
			awk '/: hex :/ {sub(/.*hex : 0x/, ""); gsub(/ /, ""); print; exit}')
		[ -n "$hex" ] && echo "  $label $(basename "$t"): $hex" >&2
	done
}

run_apdu() {
	local len=$1 kout="$out/klee-apdu-$len"
	clang "${CFLAGS[@]}" -DKLEE_APDU_LEN="$len" -o "$out/h-$len.bc" "$src/tests/klee/klee_apdu.c"
	llvm-link -o "$out/apdu-$len.bc" "$out/h-$len.bc" "$out/apdu.bc"
	rm -rf "$kout"
	klee "${KLEE_FLAGS[@]}" --output-dir="$kout" "$out/apdu-$len.bc" \
		>"$out/klee-apdu-$len.log" 2>&1 || true
	witnesses "$kout" "len=$len"
	verdict "$kout" "$out/klee-apdu-$len.log"
}

expected_for() { grep "^len=$1:" "$src/tests/klee/expected.txt" | head -1; }

# --- full card path (ss_application_apdu_transact) --------------------------
# Unlike the parser, this needs a libc model (storage.c uses snprintf/strtoul)
# and the whole library, linked against the in-memory fs backend instead of
# fs.c. It is a directed, time-bounded exploration -- not a golden check -- so
# it prints its verdict and witnesses rather than diffing expected.txt.
run_transact() {
	local cmd=$1 macro kout="$out/klee-transact-$1" bcdir="$out/bc-$1" f
	case "$cmd" in
	select) macro=KLEE_CMD_SELECT ;;
	verify_pin) macro=KLEE_CMD_VERIFY_PIN ;;
	envelope) macro=KLEE_CMD_ENVELOPE ;;
	*)
		echo "unknown transact command: $cmd" >&2
		exit 2
		;;
	esac

	rm -rf "$bcdir" "$kout"
	mkdir -p "$bcdir"

	# The whole library minus the pieces the RAM backend and lib-only build
	# replace. Excluded by path, not basename: src/softsim/fs.c is the host
	# porting layer fs_ram.c replaces, but src/softsim/uicc/fs.c is the
	# filesystem-semantics layer (ss_fs_init/ss_fs_select) that must stay.
	local srcs
	srcs=$(find "$src/src/softsim" -name '*.c' \
		! -path '*/src/softsim/fs.c' \
		! -path '*/src/softsim/main.c' \
		! -path '*/src/softsim/storage_compact.c')
	srcs="$srcs $src/tests/klee/klee_transact.c $src/utils/files-c-array/ss_static_files_hex.c"

	local n=0
	for f in $srcs; do
		clang "${CFLAGS[@]}" -DCONFIG_NO_DEFAULT_IMPL "-D$macro" \
			-o "$bcdir/$n.bc" "$f"
		n=$((n + 1))
	done
	llvm-link -o "$out/transact-$cmd.bc" "$bcdir"/*.bc

	# uclibc, not none: the storage layer needs snprintf/strtoul/strncpy.
	klee --libc=uclibc --search=dfs --only-output-states-covering-new \
		--warnings-only-to-file "--max-time=${KLEE_MAX_TIME:-120}s" \
		--output-dir="$kout" "$out/transact-$cmd.bc" \
		>"$out/klee-transact-$cmd.log" 2>&1 || true
	witnesses "$kout" "transact:$cmd"
	verdict "$kout" "$out/klee-transact-$cmd.log"
}

mkdir -p "$out"

case "$mode" in
apdu)
	len=$3
	build_apdu_lib
	got="len=$len: $(run_apdu "$len")"
	echo "$got"
	want=$(expected_for "$len" || true)
	if [ -n "$want" ] && [ "$got" != "$want" ]; then
		echo "MISMATCH: expected [$want]" >&2
		exit 1
	fi
	;;
sweep)
	build_apdu_lib
	: >"$out/verdicts.txt"
	for len in "${LENGTHS[@]}"; do
		echo "len=$len: $(run_apdu "$len")" | tee -a "$out/verdicts.txt"
	done
	if [ -f "$src/tests/klee/expected.txt" ]; then
		echo "--- diff against expected.txt (empty = pass) ---" >&2
		diff "$src/tests/klee/expected.txt" "$out/verdicts.txt"
	else
		echo "no expected.txt yet; copy $out/verdicts.txt to tests/klee/expected.txt" >&2
	fi
	;;
transact)
	echo "transact:$3: $(run_transact "$3")"
	;;
*)
	echo "unknown mode: $mode" >&2
	exit 2
	;;
esac
