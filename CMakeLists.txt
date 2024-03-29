# Copyright (c) 2024 Onomondo ApS. All rights reserved.
# SPDX-License-Identifier: GPL-3.0-only

cmake_minimum_required(VERSION 3.13...3.19 FATAL_ERROR)

project(softsim
		VERSION 1.0.0
		LANGUAGES C
)

option(CONFIG_USE_SYSTEM_HEAP "Use free/malloc instead of port_free/port_malloc" OFF)

if(CONFIG_USE_SYSTEM_HEAP)
	add_compile_definitions(-DCONFIG_USE_SYSTEM_HEAP)
endif()

add_subdirectory(src)

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
	include(CTest)
	add_subdirectory(tests)
endif()
