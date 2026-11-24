# Copyright (c) 2026 Onomondo ApS. All rights reserved.
# SPDX-License-Identifier: GPL-3.0-only

add_executable(file_id_test file_id_test.c)

include_directories(${PROJECT_SOURCE_DIR})
include_directories(${PROJECT_SOURCE_DIR}/include)

target_link_libraries(file_id_test uicc milenage crypto storage $<$<TARGET_EXISTS:utils>:utils>)

# The test updates EF.ARR and creates files, so every run starts from a fresh private copy
# of the filesystem, taken at configure time.
file(COPY ${CMAKE_SOURCE_DIR}/files DESTINATION ${CMAKE_CURRENT_BINARY_DIR}/pristine)

add_test(NAME file_id_test COMMAND sh -c "rm -rf files && cp -R pristine/files files && $<TARGET_FILE:file_id_test> > file_id_test.out 2>&1")
set_tests_properties(file_id_test PROPERTIES WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR})
add_test(NAME file_id_test_compare COMMAND ${CMAKE_COMMAND} -E compare_files --ignore-eol ${CMAKE_CURRENT_BINARY_DIR}/file_id_test.out ${CMAKE_CURRENT_SOURCE_DIR}/file_id_test.ok)
set_tests_properties(file_id_test_compare PROPERTIES DEPENDS file_id_test)
