# Copyright (c) 2024 Onomondo ApS. All rights reserved.
# SPDX-License-Identifier: GPL-3.0-only

add_subdirectory(crypto)
add_subdirectory(milenage)
add_subdirectory(uicc)

if(CONFIG_COMPACT_STORAGE)
  set(storage_sources storage_compact.c)
else()
  set(storage_sources storage.c)
  if(NOT CONFIG_NO_DEFAULT_IMPL)
    list(APPEND storage_sources fs.c)
  endif()
endif()

add_library(storage STATIC ${storage_sources})

target_include_directories(storage PUBLIC ${PROJECT_SOURCE_DIR}/include)

if(NOT CONFIG_BUILD_LIB_ONLY)
  add_executable(softsim main.c)
  target_link_libraries(softsim uicc milenage crypto storage $<$<TARGET_EXISTS:utils>:utils>)
endif()
