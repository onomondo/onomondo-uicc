# Copyright (c) 2026 Onomondo ApS. All rights reserved.
# SPDX-License-Identifier: GPL-3.0-only

ss_add_test(fs_chg_terminator_test STDERR LIBS uicc milenage crypto storage $<$<TARGET_EXISTS:utils>:utils>)
