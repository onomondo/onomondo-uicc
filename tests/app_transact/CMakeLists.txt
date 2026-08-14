# Copyright (c) 2024 Onomondo ApS. All rights reserved.
# SPDX-License-Identifier: GPL-3.0-only

add_executable(app_apdu_test app_transact_test.c)

include_directories(${PROJECT_SOURCE_DIR}/include)

target_link_libraries(app_apdu_test uicc milenage crypto storage $<$<TARGET_EXISTS:utils>:utils>)

# Snapshot files/ at configure time, as tests/key_scrub does: suites that run
# from the source root (tests/pin, tests/utils) write into ${CMAKE_SOURCE_DIR}/files
# during the run, so a copy taken while ctest is running can capture their edits.
file(COPY ${CMAKE_SOURCE_DIR}/files DESTINATION ${CMAKE_CURRENT_BINARY_DIR}/pristine)

# Refresh from that snapshot before each run, as tests/envelope does: this
# transcript ends in an UPDATE RECORD and an earlier READ RECORD of the same file
# would otherwise return what the previous run wrote.
add_test(NAME app_apdu_test_setup
	 COMMAND ${CMAKE_COMMAND} -E copy_directory
		 ${CMAKE_CURRENT_BINARY_DIR}/pristine/files
		 ${CMAKE_CURRENT_BINARY_DIR}/files
)
set_tests_properties(app_apdu_test_setup PROPERTIES FIXTURES_SETUP app_apdu_files)

# Only stdout is captured: SS_LOGP writes to stderr and logs heap pointers.
add_test(NAME app_apdu_test
	 COMMAND sh -c "$<TARGET_FILE:app_apdu_test> > ${CMAKE_CURRENT_BINARY_DIR}/app_transact_test.out")
set_tests_properties(app_apdu_test PROPERTIES
	FIXTURES_REQUIRED app_apdu_files
	WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR})

add_test(NAME app_apdu_test_compare
	 COMMAND ${CMAKE_COMMAND} -E compare_files --ignore-eol
		 ${CMAKE_CURRENT_BINARY_DIR}/app_transact_test.out
		 ${CMAKE_CURRENT_SOURCE_DIR}/app_transact_test.ok
)
