# Copyright (c) 2024 Onomondo ApS. All rights reserved.
# SPDX-License-Identifier: GPL-3.0-only

add_executable(tlv8_test tlv8_test.c)

include_directories(${PROJECT_SOURCE_DIR})
include_directories(${PROJECT_SOURCE_DIR}/include)

target_link_libraries(tlv8_test uicc)

add_test(NAME tlv8_test COMMAND sh -c "$<TARGET_FILE:tlv8_test> > tlv8_test.out")
