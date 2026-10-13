# Copyright (c) 2026 Onomondo ApS. All rights reserved.
# SPDX-License-Identifier: GPL-3.0-only

# storage_compact.c is not part of any library in this build configuration
# (the storage library carries storage.c), so compile it directly, backed by
# the default filesystem implementation, to give the compact read path host
# coverage.
add_executable(storage_compact_test storage_compact_test.c
	${PROJECT_SOURCE_DIR}/src/softsim/storage_compact.c
	${PROJECT_SOURCE_DIR}/src/softsim/fs.c
)

include_directories(${PROJECT_SOURCE_DIR})
include_directories(${PROJECT_SOURCE_DIR}/include)

target_link_libraries(storage_compact_test uicc)

add_test(NAME storage_compact_test
	COMMAND sh -c "$<TARGET_FILE:storage_compact_test> > ${CMAKE_CURRENT_BINARY_DIR}/storage_compact_test.out"
)
set_tests_properties(storage_compact_test PROPERTIES WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR})

add_test(NAME storage_compact_test_compare
	COMMAND ${CMAKE_COMMAND} -E compare_files --ignore-eol
		${CMAKE_CURRENT_BINARY_DIR}/storage_compact_test.out
		${CMAKE_CURRENT_SOURCE_DIR}/storage_compact_test.ok
)
set_tests_properties(storage_compact_test_compare PROPERTIES DEPENDS storage_compact_test)
