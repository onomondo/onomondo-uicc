# Copyright (c) 2024 Onomondo ApS. All rights reserved.
# SPDX-License-Identifier: GPL-3.0-only

add_executable(sms_test sms_test.c)

include_directories(${PROJECT_SOURCE_DIR})
include_directories(${PROJECT_SOURCE_DIR}/include)

target_link_libraries(sms_test uicc)

add_test(NAME sms_test COMMAND sh -c "$<TARGET_FILE:sms_test> > sms_test.out")
