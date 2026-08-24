# Copyright (c) 2026 Onomondo ApS. All rights reserved.
# SPDX-License-Identifier: GPL-3.0-only

add_executable(read_on_df_test read_on_df_test.c)

include_directories(${PROJECT_SOURCE_DIR})
include_directories(${PROJECT_SOURCE_DIR}/include)

target_link_libraries(read_on_df_test uicc milenage crypto storage $<$<TARGET_EXISTS:utils>:utils>)

add_test(NAME read_on_df_test COMMAND sh -c "$<TARGET_FILE:read_on_df_test> > ${CMAKE_CURRENT_BINARY_DIR}/read_on_df_test.out 2>&1")
set_tests_properties(read_on_df_test PROPERTIES WORKING_DIRECTORY ${CMAKE_SOURCE_DIR})
add_test(NAME read_on_df_test_compare COMMAND ${CMAKE_COMMAND} -E compare_files --ignore-eol ${CMAKE_CURRENT_BINARY_DIR}/read_on_df_test.out ${CMAKE_CURRENT_SOURCE_DIR}/read_on_df_test.ok)
set_tests_properties(read_on_df_test_compare PROPERTIES DEPENDS read_on_df_test)
