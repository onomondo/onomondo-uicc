# Copyright (c) 2026 Onomondo ApS. All rights reserved.
# SPDX-License-Identifier: GPL-3.0-only

add_executable(create_file_test create_file_test.c)

include_directories(${PROJECT_SOURCE_DIR})
include_directories(${PROJECT_SOURCE_DIR}/include)

target_link_libraries(create_file_test uicc milenage crypto storage $<$<TARGET_EXISTS:utils>:utils>)

# Runs on a private copy of the filesystem in case a broken access check lets the file through.
file(COPY ${CMAKE_SOURCE_DIR}/files DESTINATION ${CMAKE_CURRENT_BINARY_DIR})

add_test(NAME create_file_test COMMAND create_file_test WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR})
