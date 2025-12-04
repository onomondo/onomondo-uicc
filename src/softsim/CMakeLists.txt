# Copyright (c) 2024 Onomondo ApS. All rights reserved.
# SPDX-License-Identifier: GPL-3.0-only

add_subdirectory(crypto)
add_subdirectory(milenage)
add_subdirectory(uicc)

add_library(storage STATIC storage.c
                           $<$<NOT:$<BOOL:${CONFIG_NO_DEFAULT_IMPL}>>:fs.c>)
target_include_directories(storage PUBLIC ${PROJECT_SOURCE_DIR}/include)

if(NOT CONFIG_BUILD_LIB_ONLY)
  add_executable(softsim main.c)
  target_link_libraries(softsim uicc milenage crypto storage $<$<TARGET_EXISTS:utils>:utils>)
endif()

