# Copyright (c) 2026 Onomondo ApS. All rights reserved.
# SPDX-License-Identifier: GPL-3.0-only

add_executable(create_file_test create_file_test.c)

include_directories(${PROJECT_SOURCE_DIR})
include_directories(${PROJECT_SOURCE_DIR}/include)

target_link_libraries(create_file_test uicc milenage crypto storage $<$<TARGET_EXISTS:utils>:utils>)

# The test creates and deletes files, so it runs on a private copy of the
# filesystem instead of the one in the source tree. The copy is removed and
# made again before each run, so files left behind by a failed run do not
# carry over.
file(COPY ${CMAKE_SOURCE_DIR}/files DESTINATION ${CMAKE_CURRENT_BINARY_DIR}/pristine)

add_test(NAME create_file_test_clean
    COMMAND ${CMAKE_COMMAND} -E rm -rf ${CMAKE_CURRENT_BINARY_DIR}/files
)
add_test(NAME create_file_test_setup
    COMMAND ${CMAKE_COMMAND} -E copy_directory
        ${CMAKE_CURRENT_BINARY_DIR}/pristine/files
        ${CMAKE_CURRENT_BINARY_DIR}/files
)
set_tests_properties(create_file_test_clean PROPERTIES FIXTURES_SETUP create_file_files)
set_tests_properties(create_file_test_setup PROPERTIES
    FIXTURES_SETUP create_file_files
    DEPENDS create_file_test_clean)

# Pass/fail is decided by assert() in the test itself, no output comparison.
add_test(NAME create_file_test COMMAND create_file_test)
set_tests_properties(create_file_test PROPERTIES
    FIXTURES_REQUIRED create_file_files
    WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR})
