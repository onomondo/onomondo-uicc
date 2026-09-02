# Copyright (c) 2026 Onomondo ApS. All rights reserved.
# SPDX-License-Identifier: GPL-3.0-only

add_executable(opt_out_test opt_out_test.c)

target_link_libraries(opt_out_test uicc milenage crypto storage $<$<TARGET_EXISTS:utils>:utils>)

file(COPY ${CMAKE_SOURCE_DIR}/files DESTINATION ${CMAKE_CURRENT_BINARY_DIR})
add_test(NAME opt_out_test
	 COMMAND sh -c "$<TARGET_FILE:opt_out_test> > ${CMAKE_CURRENT_BINARY_DIR}/opt_out_test.out 2>&1")
set_tests_properties(opt_out_test PROPERTIES WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR})

# The compiled-out subsystem must name its own fix in the log.
if(CONFIG_DISABLE_SMS)
	set(opt_out_log "clear EF.UST service 28")
else()
	set(opt_out_log "OTA is compiled out")
endif()
add_test(NAME opt_out_test_log COMMAND grep -q "${opt_out_log}" ${CMAKE_CURRENT_BINARY_DIR}/opt_out_test.out)
set_tests_properties(opt_out_test_log PROPERTIES DEPENDS opt_out_test)
