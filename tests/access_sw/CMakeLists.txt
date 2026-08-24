# Copyright (c) 2026 Onomondo ApS. All rights reserved.
# SPDX-License-Identifier: GPL-3.0-only

add_executable(access_sw_test access_sw_test.c)

include_directories(${PROJECT_SOURCE_DIR})
include_directories(${PROJECT_SOURCE_DIR}/include)

target_link_libraries(access_sw_test uicc milenage crypto storage $<$<TARGET_EXISTS:utils>:utils>)

# The test enables PIN1, so it runs on a private copy of the filesystem
# instead of the one in the source tree, refreshed before each run so
# repeated ctest invocations start from the same state.
file(COPY ${CMAKE_SOURCE_DIR}/files DESTINATION ${CMAKE_CURRENT_BINARY_DIR}/pristine)

add_test(NAME access_sw_test_setup
    COMMAND ${CMAKE_COMMAND} -E copy_directory
        ${CMAKE_CURRENT_BINARY_DIR}/pristine/files
        ${CMAKE_CURRENT_BINARY_DIR}/files
)
set_tests_properties(access_sw_test_setup PROPERTIES FIXTURES_SETUP access_sw_files)

add_test(NAME access_sw_test COMMAND sh -c "$<TARGET_FILE:access_sw_test> > ${CMAKE_CURRENT_BINARY_DIR}/access_sw_test.out 2>&1")
set_tests_properties(access_sw_test PROPERTIES
    FIXTURES_REQUIRED access_sw_files
    WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR})

add_test(NAME access_sw_test_compare COMMAND ${CMAKE_COMMAND} -E compare_files --ignore-eol ${CMAKE_CURRENT_BINARY_DIR}/access_sw_test.out ${CMAKE_CURRENT_SOURCE_DIR}/access_sw_test.ok)
set_tests_properties(access_sw_test_compare PROPERTIES DEPENDS access_sw_test)
