# Copyright (c) 2026 Onomondo ApS. All rights reserved.
# SPDX-License-Identifier: GPL-3.0-only

add_executable(fs_chg_pack_path_test fs_chg_pack_path_test.c)

include_directories(${PROJECT_SOURCE_DIR})
include_directories(${PROJECT_SOURCE_DIR}/include)

target_link_libraries(fs_chg_pack_path_test uicc)

add_test(NAME fs_chg_pack_path_test COMMAND $<TARGET_FILE:fs_chg_pack_path_test>)
