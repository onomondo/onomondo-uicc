# Copyright (c) 2024 Onomondo ApS. All rights reserved.
# SPDX-License-Identifier: GPL-3.0-only

add_library(milenage 
	STATIC 
		milenage.c 
		milenage_usim.c
)

target_include_directories(milenage
	PUBLIC
		${PROJECT_SOURCE_DIR}/include
	PRIVATE
		${CMAKE_CURRENT_SOURCE_DIR} ${CMAKE_CURRENT_SOURCE_DIR}/../
)
