# Copyright (c) 2024 Onomondo ApS. All rights reserved.
# SPDX-License-Identifier: GPL-3.0-only

add_executable(btlv_test btlv_test.c)

include_directories(${PROJECT_SOURCE_DIR})
include_directories(${PROJECT_SOURCE_DIR}/include)

target_link_libraries(btlv_test uicc)

add_test(NAME btlv_test COMMAND sh -c "$<TARGET_FILE:btlv_test> > btlv_test.out 2>&1")

add_test(NAME btlv_test_compare
		 COMMAND ${CMAKE_COMMAND} -E compare_files --ignore-eol
				 ${CMAKE_CURRENT_BINARY_DIR}/btlv_test.out
				 ${CMAKE_CURRENT_SOURCE_DIR}/btlv_test.ok
)
set_tests_properties(btlv_test_compare PROPERTIES DEPENDS btlv_test)
