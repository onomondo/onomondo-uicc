# Copyright (c) 2026 Onomondo ApS. All rights reserved.
# SPDX-License-Identifier: GPL-3.0-only

ss_add_test(terminal_response_test FILES STDERR LIBS uicc milenage crypto storage $<$<TARGET_EXISTS:utils>:utils>)
