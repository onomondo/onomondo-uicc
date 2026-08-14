# Copyright (c) 2024 Onomondo ApS. All rights reserved.
# SPDX-License-Identifier: GPL-3.0-only

add_executable(init_test init_test.c)

include_directories(${PROJECT_SOURCE_DIR})
include_directories(${PROJECT_SOURCE_DIR}/include)

target_link_libraries(init_test uicc milenage crypto storage $<$<TARGET_EXISTS:utils>:utils>)

add_test(NAME init_test COMMAND sh -c "$<TARGET_FILE:init_test> > ${CMAKE_CURRENT_BINARY_DIR}/init_test.out")

# The suite reads and writes ./files, so it runs on a private copy of the
# filesystem instead of the one in the source tree.
file(COPY ${CMAKE_SOURCE_DIR}/files DESTINATION ${CMAKE_CURRENT_BINARY_DIR})

set_tests_properties(init_test PROPERTIES WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR})

add_test(NAME init_test_compare
	 COMMAND ${CMAKE_COMMAND} -E compare_files --ignore-eol
		 ${CMAKE_CURRENT_BINARY_DIR}/init_test.out
		 ${CMAKE_CURRENT_SOURCE_DIR}/init_test.ok
)
