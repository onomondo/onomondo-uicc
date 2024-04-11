# Copyright (c) 2024 Onomondo ApS. All rights reserved.
# SPDX-License-Identifier: GPL-3.0-only

add_executable(ota_test ota_test.c)

include_directories(${PROJECT_SOURCE_DIR})
include_directories(${PROJECT_SOURCE_DIR}/include)

target_link_libraries(ota_test uicc crypto $<$<TARGET_EXISTS:utils>:utils>)

add_test(NAME ota_test COMMAND sh -c "$<TARGET_FILE:ota_test> > ota_test.out")

add_test(NAME ota_test_compare
         COMMAND ${CMAKE_COMMAND} -E compare_files --ignore-eol
                 ${CMAKE_CURRENT_BINARY_DIR}/ota_test.out
                 ${CMAKE_CURRENT_SOURCE_DIR}/ota_test.ok
)
