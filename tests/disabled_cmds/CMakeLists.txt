# Copyright (c) 2026 Onomondo ApS. All rights reserved.
# SPDX-License-Identifier: GPL-3.0-only

add_executable(disabled_cmds_test disabled_cmds_test.c)

include_directories(${PROJECT_SOURCE_DIR})
include_directories(${PROJECT_SOURCE_DIR}/include)

target_link_libraries(disabled_cmds_test uicc milenage crypto storage $<$<TARGET_EXISTS:utils>:utils>)

add_test(NAME disabled_cmds_test COMMAND disabled_cmds_test)
