# Copyright (c) 2024 Onomondo ApS. All rights reserved.
# SPDX-License-Identifier: GPL-3.0-only

ss_add_test(init_test FILES LIBS uicc milenage crypto storage $<$<TARGET_EXISTS:utils>:utils>)
