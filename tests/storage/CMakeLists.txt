# Copyright (c) 2024 Onomondo ApS. All rights reserved.
# SPDX-License-Identifier: GPL-3.0-only

add_executable(storage_test storage_test.c)

include_directories(${PROJECT_SOURCE_DIR})
include_directories(${PROJECT_SOURCE_DIR}/include)

target_link_libraries(storage_test uicc storage)

add_test(NAME storage_test COMMAND sh -c "$<TARGET_FILE:storage_test> > storage_test.out")

add_test(NAME storage_test_compare
		 COMMAND ${CMAKE_COMMAND} -E compare_files --ignore-eol
				 ${CMAKE_CURRENT_BINARY_DIR}/storage_test.out
				 ${CMAKE_CURRENT_SOURCE_DIR}/storage_test.ok
)

set_tests_properties(storage_test_compare PROPERTIES DEPENDS storage_test)
