# Copyright (c) 2024 Onomondo ApS. All rights reserved.
# SPDX-License-Identifier: GPL-3.0-only

add_executable(utils_test utils_test.c)

include_directories(${PROJECT_SOURCE_DIR})
include_directories(${PROJECT_SOURCE_DIR}/include)

target_link_libraries(utils_test uicc)

add_test(NAME utils_test COMMAND sh -c "$<TARGET_FILE:utils_test> > utils_test.out")

add_test(NAME utils_test_compare
		 COMMAND ${CMAKE_COMMAND} -E compare_files --ignore-eol
				 ${PROJECT_SOURCE_DIR}/build/tests/utils/utils_test.out
				 ${CMAKE_CURRENT_SOURCE_DIR}/utils_test.ok
)
