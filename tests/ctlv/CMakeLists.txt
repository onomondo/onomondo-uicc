# Copyright (c) 2024 Onomondo ApS. All rights reserved.
# SPDX-License-Identifier: GPL-3.0-only

add_executable(ctlv_test ctlv_test.c)

include_directories(${PROJECT_SOURCE_DIR})
include_directories(${PROJECT_SOURCE_DIR}/include)

target_link_libraries(ctlv_test uicc)

add_test(NAME ctlv_test COMMAND sh -c "$<TARGET_FILE:ctlv_test> > ctlv_test.out 2>&1")

add_test(NAME ctlv_test_compare
		 COMMAND ${CMAKE_COMMAND} -E compare_files --ignore-eol
				 ${CMAKE_CURRENT_BINARY_DIR}/ctlv_test.out
				 ${CMAKE_CURRENT_SOURCE_DIR}/ctlv_test.ok
)
set_tests_properties(ctlv_test_compare PROPERTIES DEPENDS ctlv_test)
