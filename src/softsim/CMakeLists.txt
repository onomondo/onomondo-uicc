# Copyright (c) 2024 Onomondo ApS. All rights reserved.
# SPDX-License-Identifier: GPL-3.0-only

add_subdirectory(crypto)
add_subdirectory(milenage)
add_subdirectory(uicc)

add_library(storage STATIC storage.c fs.c)
target_include_directories(storage PUBLIC ${CMAKE_SOURCE_DIR}/include)

add_executable(softsim main.c)
target_link_libraries(softsim uicc milenage crypto storage $<$<TARGET_EXISTS:utils>:utils>)

