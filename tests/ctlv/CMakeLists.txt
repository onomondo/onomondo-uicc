# Copyright (c) 2024 Onomondo ApS. All rights reserved.
# SPDX-License-Identifier: GPL-3.0-only

add_executable(ctlv_test ctlv_test.c)

include_directories(${PROJECT_SOURCE_DIR})
include_directories(${PROJECT_SOURCE_DIR}/include)

target_link_libraries(ctlv_test uicc)

add_test(NAME ctlv_test COMMAND sh -c "$<TARGET_FILE:ctlv_test> > ctlv_test.out")
