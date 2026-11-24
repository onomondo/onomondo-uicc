# Copyright (c) 2026 Onomondo ApS. All rights reserved.
# SPDX-License-Identifier: GPL-3.0-only

ss_add_test(opt_out_test FILES STDERR NO_OK LIBS uicc milenage crypto storage $<$<TARGET_EXISTS:utils>:utils>)

# The compiled-out subsystem must say so in the log.
add_test(NAME opt_out_test_log COMMAND grep -q "SMS is compiled out" ${CMAKE_CURRENT_BINARY_DIR}/opt_out_test.run/opt_out_test.out)
set_tests_properties(opt_out_test PROPERTIES FIXTURES_SETUP opt_out_log)
set_tests_properties(opt_out_test_log PROPERTIES FIXTURES_REQUIRED opt_out_log)

# The gate must keep the OTA-only AES (decrypt, CMAC) out of the link too.
add_test(NAME opt_out_test_link
	 COMMAND sh -c "nm $<TARGET_FILE:opt_out_test> | grep -q 'ss_utils_aes_encrypt$' && ! nm $<TARGET_FILE:opt_out_test> | grep -qE '(aes_decrypt_init|ss_utils_aes_cc_setup)$'")
