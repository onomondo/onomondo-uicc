# Copyright (c) 2026 Onomondo ApS. All rights reserved.
# SPDX-License-Identifier: GPL-3.0-only

add_executable(access_test access_test.c)

include_directories(${PROJECT_SOURCE_DIR})
include_directories(${PROJECT_SOURCE_DIR}/include)

target_link_libraries(access_test uicc storage)

add_test(NAME access_test COMMAND sh -c "$<TARGET_FILE:access_test> > access_test.out")

add_test(NAME access_test_compare
		 COMMAND ${CMAKE_COMMAND} -E compare_files --ignore-eol
				 ${CMAKE_CURRENT_BINARY_DIR}/access_test.out
				 ${CMAKE_CURRENT_SOURCE_DIR}/access_test.ok
)

set_tests_properties(access_test_compare PROPERTIES DEPENDS access_test)
