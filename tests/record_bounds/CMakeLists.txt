# Copyright (c) 2026 Onomondo ApS. All rights reserved.
# SPDX-License-Identifier: GPL-3.0-only

add_executable(record_bounds_test record_bounds_test.c)

include_directories(${PROJECT_SOURCE_DIR})
include_directories(${PROJECT_SOURCE_DIR}/include)

target_link_libraries(record_bounds_test uicc milenage crypto storage $<$<TARGET_EXISTS:utils>:utils>)

add_test(NAME record_bounds_test COMMAND sh -c "$<TARGET_FILE:record_bounds_test> > ${CMAKE_CURRENT_BINARY_DIR}/record_bounds_test.out 2>&1")
set_tests_properties(record_bounds_test PROPERTIES WORKING_DIRECTORY ${CMAKE_SOURCE_DIR})
add_test(NAME record_bounds_test_compare COMMAND ${CMAKE_COMMAND} -E compare_files --ignore-eol ${CMAKE_CURRENT_BINARY_DIR}/record_bounds_test.out ${CMAKE_CURRENT_SOURCE_DIR}/record_bounds_test.ok)
set_tests_properties(record_bounds_test_compare PROPERTIES DEPENDS record_bounds_test)
