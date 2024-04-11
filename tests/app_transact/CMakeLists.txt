# Copyright (c) 2024 Onomondo ApS. All rights reserved.
# SPDX-License-Identifier: GPL-3.0-only

add_executable(app_apdu_test app_transact_test.c)

include_directories(${PROJECT_SOURCE_DIR}/include)

target_link_libraries(app_apdu_test uicc milenage crypto storage $<$<TARGET_EXISTS:utils>:utils>)

