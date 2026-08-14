# Copyright (c) 2026 Onomondo ApS. All rights reserved.
# SPDX-License-Identifier: GPL-3.0-only

add_executable(select_test select_test.c)

include_directories(${PROJECT_SOURCE_DIR})
include_directories(${PROJECT_SOURCE_DIR}/include)

target_link_libraries(select_test uicc milenage crypto storage $<$<TARGET_EXISTS:utils>:utils>)

# Read-only: SELECT, STATUS and READ RECORD only, so it runs on the filesystem
# in the source tree without a private copy.
add_test(NAME select_test COMMAND sh -c "$<TARGET_FILE:select_test> > ${CMAKE_CURRENT_BINARY_DIR}/select_test.out 2>&1")
set_tests_properties(select_test PROPERTIES WORKING_DIRECTORY ${CMAKE_SOURCE_DIR})
add_test(NAME select_test_compare COMMAND ${CMAKE_COMMAND} -E compare_files --ignore-eol ${CMAKE_CURRENT_BINARY_DIR}/select_test.out ${CMAKE_CURRENT_SOURCE_DIR}/select_test.ok)
set_tests_properties(select_test_compare PROPERTIES DEPENDS select_test)
