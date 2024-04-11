# Copyright (c) 2024 Onomondo ApS. All rights reserved.
# SPDX-License-Identifier: GPL-3.0-only

set(utils_collection
	ss_profile.c
)

if(CONFIG_EXTERNAL_KEY_LOAD)
  set(utils_collection ${utils_collection} ss_crypto_extension.c)
endif()

add_library(utils STATIC ${utils_collection})

target_include_directories(utils
	PUBLIC
		${CMAKE_SOURCE_DIR}/include
)
