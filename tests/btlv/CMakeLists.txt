# Copyright (c) 2024 Onomondo ApS. All rights reserved.
# SPDX-License-Identifier: GPL-3.0-only

add_executable(btlv_test btlv_test.c)

include_directories(${PROJECT_SOURCE_DIR})
include_directories(${PROJECT_SOURCE_DIR}/include)

target_link_libraries(btlv_test uicc)

add_test(NAME btlv_test COMMAND sh -c "$<TARGET_FILE:btlv_test> > btlv_test.out")
