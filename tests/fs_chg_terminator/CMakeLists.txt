# Copyright (c) 2026 Onomondo ApS. All rights reserved.
# SPDX-License-Identifier: GPL-3.0-only

add_executable(fs_chg_terminator_test fs_chg_terminator_test.c)

include_directories(${PROJECT_SOURCE_DIR})
include_directories(${PROJECT_SOURCE_DIR}/include)

target_link_libraries(fs_chg_terminator_test uicc)

add_test(NAME fs_chg_terminator_test COMMAND sh -c "$<TARGET_FILE:fs_chg_terminator_test> > ${CMAKE_CURRENT_BINARY_DIR}/fs_chg_terminator_test.out 2>&1")
add_test(NAME fs_chg_terminator_test_compare COMMAND ${CMAKE_COMMAND} -E compare_files --ignore-eol ${CMAKE_CURRENT_BINARY_DIR}/fs_chg_terminator_test.out ${CMAKE_CURRENT_SOURCE_DIR}/fs_chg_terminator_test.ok)
set_tests_properties(fs_chg_terminator_test_compare PROPERTIES DEPENDS fs_chg_terminator_test)
