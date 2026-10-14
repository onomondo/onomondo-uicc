# Copyright (c) 2024 Onomondo ApS. All rights reserved.
# SPDX-License-Identifier: GPL-3.0-only

add_library(crypto 
	STATIC
		aes-encblock.c
		aes-internal-dec.c
		aes-internal-enc.c
		aes-internal.c
		aes-wrap.c
		des-internal.c
		# Milenage's AES block (aes-encblock.c) calls ss_utils_aes_encrypt in every build
		../uicc/utils_aes.c
)

target_include_directories(crypto
	PUBLIC
		${PROJECT_SOURCE_DIR}/include
	PRIVATE
		${CMAKE_CURRENT_SOURCE_DIR} ${CMAKE_CURRENT_SOURCE_DIR}/..
)
