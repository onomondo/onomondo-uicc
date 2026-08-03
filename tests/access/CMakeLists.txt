# Copyright (c) 2026 Onomondo ApS. All rights reserved.
# SPDX-License-Identifier: GPL-3.0-only

add_executable(access_test access_test.c)

include_directories(${PROJECT_SOURCE_DIR})
include_directories(${PROJECT_SOURCE_DIR}/include)

target_link_libraries(access_test uicc storage)

add_test(NAME access_test COMMAND sh -c "$<TARGET_FILE:access_test> > access_test.out")
