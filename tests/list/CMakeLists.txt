# Copyright (c) 2024 Onomondo ApS. All rights reserved.
# SPDX-License-Identifier: GPL-3.0-only

add_executable(list_test list_test.c)

include_directories(${PROJECT_SOURCE_DIR})
include_directories(${PROJECT_SOURCE_DIR}/include)

add_test(NAME list_test COMMAND sh -c "$<TARGET_FILE:list_test> > list_test.out")

add_test(NAME list_test_compare
		 COMMAND ${CMAKE_COMMAND} -E compare_files --ignore-eol
				 ${CMAKE_CURRENT_BINARY_DIR}//list_test.out
				 ${CMAKE_CURRENT_SOURCE_DIR}/list_test.ok
)
