# Copyright (c) 2024 Onomondo ApS. All rights reserved.
# SPDX-License-Identifier: GPL-3.0-only

ss_add_test(sms_test LIBS uicc storage)
ss_add_test(sms_concat_ignore_test NO_OK LIBS uicc milenage crypto storage $<$<TARGET_EXISTS:utils>:utils>)
ss_add_test(sms_concat_ref0_test NO_OK LIBS uicc milenage crypto storage $<$<TARGET_EXISTS:utils>:utils>)
