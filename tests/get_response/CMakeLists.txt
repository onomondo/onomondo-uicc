# Copyright (c) 2026 Onomondo ApS. All rights reserved.
# SPDX-License-Identifier: GPL-3.0-only

add_executable(get_response_test get_response_test.c)

include_directories(${PROJECT_SOURCE_DIR})
include_directories(${PROJECT_SOURCE_DIR}/include)

target_link_libraries(get_response_test uicc milenage crypto storage $<$<TARGET_EXISTS:utils>:utils>)

add_test(NAME get_response_test COMMAND get_response_test)
set_tests_properties(get_response_test PROPERTIES WORKING_DIRECTORY ${CMAKE_SOURCE_DIR})
