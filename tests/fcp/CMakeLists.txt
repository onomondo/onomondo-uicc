# Copyright (c) 2024 Onomondo ApS. All rights reserved.
# SPDX-License-Identifier: GPL-3.0-only

add_executable(fcp_test fcp_test.c)

include_directories(${PROJECT_SOURCE_DIR})
include_directories(${PROJECT_SOURCE_DIR}/include)

target_link_libraries(fcp_test uicc)

add_test(NAME fcp_test COMMAND sh -c "$<TARGET_FILE:fcp_test> > fcp_test.out")

add_test(NAME fcp_test_compare
		 COMMAND ${CMAKE_COMMAND} -E compare_files --ignore-eol
				 ${CMAKE_CURRENT_BINARY_DIR}/fcp_test.out
				 ${CMAKE_CURRENT_SOURCE_DIR}/fcp_test.ok
)
