# Copyright (c) 2026 Onomondo ApS. All rights reserved.
# SPDX-License-Identifier: GPL-3.0-only

ss_add_test(envelope_test FILES STDERR LIBS uicc milenage crypto storage $<$<TARGET_EXISTS:utils>:utils>)

# Skip when using external key loading — the default profile OTA packet was
# encrypted with keys stored in files/; the identity stub used for
# CONFIG_EXTERNAL_KEY_LOAD produces different crypto output.
if(CONFIG_EXTERNAL_KEY_LOAD)
    set_tests_properties(envelope_test PROPERTIES DISABLED TRUE)
endif()
