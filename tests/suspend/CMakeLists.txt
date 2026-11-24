# Copyright (c) 2026 Onomondo ApS. All rights reserved.
# SPDX-License-Identifier: GPL-3.0-only

ss_add_test(suspend_test STDERR LIBS uicc milenage crypto storage $<$<TARGET_EXISTS:utils>:utils>)
if(NOT CONFIG_USE_EXPERIMENTAL_SUSPEND_COMMAND)
    set_tests_properties(suspend_test PROPERTIES DISABLED TRUE)
endif()
