# Copyright (c) 2024 Onomondo ApS. All rights reserved.
# SPDX-License-Identifier: GPL-3.0-only

add_subdirectory(crypto)
add_subdirectory(milenage)
add_subdirectory(uicc)

add_library(storage STATIC storage.c)

target_include_directories(storage PUBLIC ${CMAKE_SOURCE_DIR}/include)
