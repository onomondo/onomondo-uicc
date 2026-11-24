# Copyright (c) 2024 Onomondo ApS. All rights reserved.
# SPDX-License-Identifier: GPL-3.0-only

# Only stdout is captured: SS_LOGP writes to stderr and logs heap pointers.
ss_add_test(app_transact_test FILES LIBS uicc milenage crypto storage $<$<TARGET_EXISTS:utils>:utils>)
