# Copyright (c) 2024 Onomondo ApS. All rights reserved.
# SPDX-License-Identifier: GPL-3.0-only

cmake_minimum_required(VERSION 3.13...3.19 FATAL_ERROR)

project(softsim
		VERSION 1.0.0
		LANGUAGES C
)

option(CONFIG_ENABLE_SANITIZE "Build with -fsanitize=address -fsanitize=undefined")
option(CONFIG_USE_SYSTEM_HEAP "Use free/malloc instead of port_free/port_malloc")
option(CONFIG_USE_LOGS "Set SS_LOGP macro to link against ss_logp")
option(CONFIG_USE_EXPERIMENTAL_SUSPEND_COMMAND "Building with experimental support for suspend")
option(CONFIG_EXTERNAL_CRYPTO_IMPL "Use external crypto implementations")
option(CONFIG_EXTERNAL_KEY_LOAD "Use crypto exstension for loading keys")
option(CONFIG_USE_UTILS "Use the extra functionality found in the collective utils folder")
option(CONFIG_NO_DEFAULT_IMPL "build with no default implementation")
option(CONFIG_BUILD_LIB_ONLY "build libraries only")

if(CONFIG_USE_SYSTEM_HEAP)
	add_compile_definitions(CONFIG_USE_SYSTEM_HEAP)
endif()

if(CONFIG_USE_LOGS)
	add_compile_definitions(CONFIG_USE_LOGS)
endif()

if(CONFIG_USE_EXPERIMENTAL_SUSPEND_COMMAND)
	add_compile_definitions(CONFIG_USE_EXPERIMENTAL_SUSPEND_COMMAND)
endif()

if(CONFIG_EXTERNAL_CRYPTO_IMPL AND CONFIG_EXTERNAL_KEY_LOAD)
	message(FATAL_ERROR "CONFIG_EXTERNAL_CRYPTO_IMPL and CONFIG_EXTERNAL_KEY_LOAD should not be used together")
endif()

if(CONFIG_EXTERNAL_CRYPTO_IMPL)
	message(STATUS "Using external crypto implementation")
	add_compile_definitions(CONFIG_EXTERNAL_CRYPTO_IMPL)
endif()

if(CONFIG_EXTERNAL_KEY_LOAD)
	add_compile_definitions(CONFIG_EXTERNAL_KEY_LOAD)
endif()

if(CONFIG_ENABLE_SANITIZE)
	add_compile_options(-fsanitize=address -fsanitize=undefined)
	add_link_options(-fsanitize=address -fsanitize=undefined)
endif()

add_subdirectory(src)

if(CONFIG_USE_UTILS)
	add_subdirectory(utils)
endif()

install(TARGETS storage uicc milenage crypto
		CONFIGURATIONS Debug
		ARCHIVE DESTINATION ${CMAKE_SOURCE_DIR}/lib_${TARGET_CPU}/Debug
		PUBLIC_HEADER DESTINATION ${CMAKE_SOURCE_DIR}/lib_${TARGET_CPU}/include
)

install(TARGETS storage uicc milenage crypto
		CONFIGURATIONS Release
		ARCHIVE DESTINATION ${CMAKE_SOURCE_DIR}/lib_${TARGET_CPU}/Release/
		PUBLIC_HEADER DESTINATION ${CMAKE_SOURCE_DIR}/lib_${TARGET_CPU}/include
)

install(TARGETS storage uicc milenage crypto
		CONFIGURATIONS MinSizeRel
		ARCHIVE DESTINATION ${CMAKE_SOURCE_DIR}/lib_${TARGET_CPU}/ReleaseOs/
		PUBLIC_HEADER DESTINATION ${CMAKE_SOURCE_DIR}/lib_${TARGET_CPU}/include
)

if(CMAKE_PROJECT_NAME STREQUAL PROJECT_NAME AND BUILD_TESTING)
	add_compile_definitions(CONFIG_USE_SYSTEM_HEAP)
	include(CTest)
	add_subdirectory(tests)
endif()
