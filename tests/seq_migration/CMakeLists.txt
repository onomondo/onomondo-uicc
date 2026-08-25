# Copyright (c) 2026 Onomondo ApS. All rights reserved.
# SPDX-License-Identifier: GPL-3.0-only

# Skipped under CONFIG_EXTERNAL_KEY_LOAD like tests/envelope: the AUTN this
# test generates assumes the profile's raw key material.
if(NOT CONFIG_EXTERNAL_KEY_LOAD)

add_executable(seq_migration_test seq_migration_test.c)

include_directories(${PROJECT_SOURCE_DIR})
include_directories(${PROJECT_SOURCE_DIR}/include)
# milenage.h includes crypto/common.h relative to src/softsim
include_directories(${PROJECT_SOURCE_DIR}/src/softsim)

target_link_libraries(seq_migration_test uicc milenage crypto storage $<$<TARGET_EXISTS:utils>:utils>)

# The test rewrites the file system into the legacy SEQ layout and migrates
# it, so it runs on a private copy refreshed before each run.
file(COPY ${CMAKE_SOURCE_DIR}/files DESTINATION ${CMAKE_CURRENT_BINARY_DIR}/pristine)

add_test(NAME seq_migration_test_setup
    COMMAND ${CMAKE_COMMAND} -E copy_directory
        ${CMAKE_CURRENT_BINARY_DIR}/pristine/files
        ${CMAKE_CURRENT_BINARY_DIR}/files
)
set_tests_properties(seq_migration_test_setup PROPERTIES FIXTURES_SETUP seq_migration_files)

add_test(NAME seq_migration_test COMMAND seq_migration_test)
set_tests_properties(seq_migration_test PROPERTIES
    FIXTURES_REQUIRED seq_migration_files
    WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR})

endif()
