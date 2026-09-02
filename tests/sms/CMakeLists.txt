# Copyright (c) 2024 Onomondo ApS. All rights reserved.
# SPDX-License-Identifier: GPL-3.0-only

add_executable(sms_test sms_test.c)

include_directories(${PROJECT_SOURCE_DIR})
include_directories(${PROJECT_SOURCE_DIR}/include)

target_link_libraries(sms_test uicc)

add_test(NAME sms_test COMMAND sh -c "$<TARGET_FILE:sms_test> > sms_test.out")

add_test(NAME sms_test_compare
		 COMMAND ${CMAKE_COMMAND} -E compare_files --ignore-eol
				 ${CMAKE_CURRENT_BINARY_DIR}/sms_test.out
				 ${CMAKE_CURRENT_SOURCE_DIR}/sms_test.ok
)

add_executable(sms_concat_ignore_test sms_concat_ignore_test.c)

target_link_libraries(sms_concat_ignore_test uicc milenage crypto storage $<$<TARGET_EXISTS:utils>:utils>)

add_test(NAME sms_concat_ignore_test COMMAND sms_concat_ignore_test)

add_executable(sms_concat_ref0_test sms_concat_ref0_test.c)

target_link_libraries(sms_concat_ref0_test uicc milenage crypto storage $<$<TARGET_EXISTS:utils>:utils>)

add_test(NAME sms_concat_ref0_test COMMAND sms_concat_ref0_test)
