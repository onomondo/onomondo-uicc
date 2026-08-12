# Copyright (c) 2026 Onomondo ApS. All rights reserved.
# SPDX-License-Identifier: GPL-3.0-only

add_executable(atr_test atr_test.c)

include_directories(${PROJECT_SOURCE_DIR})
include_directories(${PROJECT_SOURCE_DIR}/include)

target_link_libraries(atr_test uicc milenage crypto storage $<$<TARGET_EXISTS:utils>:utils>)

# The test reads files/3f00/2f00.def to check the ATR's EF.DIR access claim
# against the actual file structure, so it runs from the project root.
add_test(NAME atr_test COMMAND atr_test)
set_tests_properties(atr_test PROPERTIES WORKING_DIRECTORY ${CMAKE_SOURCE_DIR})
