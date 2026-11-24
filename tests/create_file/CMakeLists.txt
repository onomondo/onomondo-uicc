# Copyright (c) 2026 Onomondo ApS. All rights reserved.
# SPDX-License-Identifier: GPL-3.0-only

ss_add_test(create_file_test FILES NO_OK LIBS uicc milenage crypto storage $<$<TARGET_EXISTS:utils>:utils>)
