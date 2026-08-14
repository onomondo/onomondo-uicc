# Copyright (c) 2026 Onomondo ApS. All rights reserved.
# SPDX-License-Identifier: GPL-3.0-only

add_executable(select_test select_test.c)

include_directories(${PROJECT_SOURCE_DIR})
include_directories(${PROJECT_SOURCE_DIR}/include)

target_link_libraries(select_test uicc milenage crypto storage $<$<TARGET_EXISTS:utils>:utils>)

# Snapshot files/ at configure time, as tests/app_transact and tests/envelope
# do: suites that run from the source root write into ${CMAKE_SOURCE_DIR}/files
# during the run, so a copy taken while ctest is running can capture their edits.
file(COPY ${CMAKE_SOURCE_DIR}/files DESTINATION ${CMAKE_CURRENT_BINARY_DIR}/pristine)

# Refresh from that snapshot before each run, so a stray write cannot reach the
# source tree and repeated runs start from the same state.
add_test(NAME select_test_setup
    COMMAND ${CMAKE_COMMAND} -E copy_directory
        ${CMAKE_CURRENT_BINARY_DIR}/pristine/files
        ${CMAKE_CURRENT_BINARY_DIR}/files
)
set_tests_properties(select_test_setup PROPERTIES FIXTURES_SETUP select_files)

add_test(NAME select_test
    COMMAND sh -c "$<TARGET_FILE:select_test> > ${CMAKE_CURRENT_BINARY_DIR}/select_test.out")
set_tests_properties(select_test PROPERTIES
    FIXTURES_REQUIRED select_files
    WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR})

add_test(NAME select_test_compare
    COMMAND ${CMAKE_COMMAND} -E compare_files --ignore-eol
        ${CMAKE_CURRENT_BINARY_DIR}/select_test.out
        ${CMAKE_CURRENT_SOURCE_DIR}/select_test.ok)
set_tests_properties(select_test_compare PROPERTIES DEPENDS select_test)
