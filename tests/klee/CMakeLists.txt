# Copyright (c) 2026 Onomondo ApS. All rights reserved.
# SPDX-License-Identifier: GPL-3.0-only
#
# KLEE symbolic-execution targets. Added only under -DCONFIG_BUILD_KLEE=y, which
# implies a KLEE toolchain (clang emitting bitcode, llvm-link, klee); run it in
# the klee/klee container as README.md describes.
#
# The bitcode build, KLEE invocation and verdict extraction live in run.sh, not
# here: none of that maps onto add_executable/add_test, and keeping it in one
# script is far easier to maintain than reconstructing it across custom commands.
# CMake only decides which lengths and commands are registered as ctests.

set(klee_out ${CMAKE_CURRENT_BINARY_DIR}/out)
set(run ${CMAKE_CURRENT_SOURCE_DIR}/run.sh)

# The parser sweep: exhaustive per length, deterministic, ~1 min total. run.sh
# diffs the verdicts against expected.txt and fails on any drift, so this is the
# golden regression check -- the analogue of the fuzz corpus replay.
add_test(NAME klee_apdu COMMAND bash ${run} ${klee_out}-apdu)

# The full card path. Directed and time-bounded (see README "Known limits"), so
# this is a smoke test that the harness still reaches the handlers, not a golden
# check. SELECT completes exhaustively in seconds; the heavier commands
# (verify_pin, envelope) are runnable the same way for deeper exploration.
add_test(NAME klee_transact_select COMMAND bash ${run} ${klee_out}-select transact select)

# Native check for the in-memory backend -- no KLEE, just clang -- so fs_ram.c
# is exercised wherever this subdirectory is built.
add_executable(fs_ram_selftest
	fs_ram_selftest.c
	${PROJECT_SOURCE_DIR}/src/softsim/fs_ram.c
	${PROJECT_SOURCE_DIR}/utils/files-c-array/ss_static_files_hex.c
)
target_include_directories(fs_ram_selftest PRIVATE
	${PROJECT_SOURCE_DIR}
	${PROJECT_SOURCE_DIR}/include
)
add_test(NAME fs_ram_selftest COMMAND fs_ram_selftest)
