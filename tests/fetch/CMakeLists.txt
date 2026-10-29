# Copyright (c) 2026 Onomondo ApS. All rights reserved.
# SPDX-License-Identifier: GPL-3.0-only

add_executable(fetch_test fetch_test.c)

include_directories(${PROJECT_SOURCE_DIR})
include_directories(${PROJECT_SOURCE_DIR}/include)

target_link_libraries(fetch_test uicc milenage crypto storage $<$<TARGET_EXISTS:utils>:utils>)

# No file writes, so it runs on the source tree's files/.
add_test(NAME fetch_test COMMAND sh -c "$<TARGET_FILE:fetch_test> > ${CMAKE_CURRENT_BINARY_DIR}/fetch_test.out 2>&1")
set_tests_properties(fetch_test PROPERTIES WORKING_DIRECTORY ${CMAKE_SOURCE_DIR})
add_test(NAME fetch_test_compare COMMAND ${CMAKE_COMMAND} -E compare_files --ignore-eol ${CMAKE_CURRENT_BINARY_DIR}/fetch_test.out ${CMAKE_CURRENT_SOURCE_DIR}/fetch_test.ok)
set_tests_properties(fetch_test_compare PROPERTIES DEPENDS fetch_test)
