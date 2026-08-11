# Copyright (c) 2026 Onomondo ApS. All rights reserved.
# SPDX-License-Identifier: GPL-3.0-only
#
# Added only under -DCONFIG_BUILD_KLEE=y. This commit brings the in-memory ss_f*
# backend and its native check; the KLEE harnesses that use it follow.

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
