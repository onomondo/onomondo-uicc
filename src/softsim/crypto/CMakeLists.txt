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
)

target_include_directories(crypto
	PUBLIC
		${PROJECT_SOURCE_DIR}/include
	PRIVATE
		${CMAKE_CURRENT_SOURCE_DIR}
)

# aes-encblock.c calls ss_utils_aes_encrypt, implemented in the uicc library,
# which in turn uses the AES core from this library. Declaring the cycle makes
# CMake repeat the two archives on consumer link lines, so member extraction
# works no matter which side the linker meets first.
target_link_libraries(crypto PRIVATE uicc)
