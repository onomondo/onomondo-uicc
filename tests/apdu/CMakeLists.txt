# Copyright (c) 2024 Onomondo ApS. All rights reserved.
# SPDX-License-Identifier: GPL-3.0-only

add_executable(apdu_test apdu_test.c)

include_directories(${PROJECT_SOURCE_DIR})
include_directories(${PROJECT_SOURCE_DIR}/include)

target_link_libraries(apdu_test uicc)

add_test(NAME apdu_test COMMAND sh -c "$<TARGET_FILE:apdu_test> > apdu_test.out")

add_test(NAME apdu_test_compare
		 COMMAND ${CMAKE_COMMAND} -E compare_files --ignore-eol
				 ${CMAKE_CURRENT_BINARY_DIR}/apdu_test.out
				 ${CMAKE_CURRENT_SOURCE_DIR}/apdu_test.ok
)

