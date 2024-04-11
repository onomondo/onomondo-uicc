# Copyright (c) 2024 Onomondo ApS. All rights reserved.
# SPDX-License-Identifier: GPL-3.0-only

add_executable(aes_test aes_test.c)

include_directories(${PROJECT_SOURCE_DIR})
include_directories(${PROJECT_SOURCE_DIR}/include)
target_link_libraries(aes_test uicc crypto $<$<TARGET_EXISTS:utils>:utils>)

add_test(NAME aes_test COMMAND sh -c "$<TARGET_FILE:aes_test> > aes_test.out")

add_test(NAME aes_test_compare
		 COMMAND ${CMAKE_COMMAND} -E compare_files --ignore-eol
				 ${CMAKE_CURRENT_BINARY_DIR}/aes_test.out
				 ${CMAKE_CURRENT_SOURCE_DIR}/aes_test.ok
)

message(STATUS "${CMAKE_CURRENT_BINARY_DIR}")
