# Copyright (c) 2026 Onomondo ApS. All rights reserved.
# SPDX-License-Identifier: GPL-3.0-only

# --wrap is a GNU ld feature and the test reads the released block through
# malloc_usable_size(), so this suite is Linux-only. CI runs there; a developer
# on another platform just does not get this one test.
#
# Skipped under CONFIG_EXTERNAL_KEY_LOAD for the same reason as tests/envelope:
# that configuration expects the integrator to supply ss_load_key_external(), and
# CI only appends a stub to three specific test binaries. AUTHENTICATE does not
# use the external loader, so the leg would add no coverage here anyway.
if(CMAKE_SYSTEM_NAME STREQUAL "Linux" AND CONFIG_USE_SYSTEM_HEAP AND NOT CONFIG_EXTERNAL_KEY_LOAD)
    add_executable(key_scrub_test key_scrub_test.c)

    include_directories(${PROJECT_SOURCE_DIR})
    include_directories(${PROJECT_SOURCE_DIR}/include)

    target_link_libraries(key_scrub_test uicc milenage crypto storage
        $<$<TARGET_EXISTS:utils>:utils> -Wl,--wrap=free)

    # Copy files/ at configure time, not from a ctest fixture: with
    # CONFIG_USE_UTILS the suite's own profile_provision_test rewrites the source
    # tree mid-run (it zeroes OPc in files/3f00/a001), so a copy taken during the
    # run can capture a mutated profile. This test only reads its copy.
    file(COPY ${CMAKE_SOURCE_DIR}/files DESTINATION ${CMAKE_CURRENT_BINARY_DIR})

    add_test(NAME key_scrub_test COMMAND $<TARGET_FILE:key_scrub_test>)
    set_tests_properties(key_scrub_test PROPERTIES
        WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR})
endif()
