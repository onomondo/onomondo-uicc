# Copyright (c) 2024 Onomondo ApS. All rights reserved.
# SPDX-License-Identifier: GPL-3.0-only

add_library(utils STATIC ss_profile.c)

target_include_directories(utils
	PUBLIC
		${CMAKE_SOURCE_DIR}/include
)
