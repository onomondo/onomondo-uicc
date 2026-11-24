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
    ss_add_test(key_scrub_test FILES NO_OK LIBS uicc milenage crypto storage $<$<TARGET_EXISTS:utils>:utils> -Wl,--wrap=free)
endif()
