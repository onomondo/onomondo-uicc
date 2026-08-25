# Copyright (c) 2024 Onomondo ApS. All rights reserved.
# SPDX-License-Identifier: GPL-3.0-only

# Enable testing for current directory and below.
enable_testing()

add_subdirectory(access)
add_subdirectory(aes)
add_subdirectory(apdu)
add_subdirectory(app_transact)
add_subdirectory(btlv)
add_subdirectory(ctlv)
add_subdirectory(des)
add_subdirectory(envelope)
add_subdirectory(fcp)
add_subdirectory(list)
add_subdirectory(ota)
add_subdirectory(sms)
add_subdirectory(storage)
add_subdirectory(tlv8)
add_subdirectory(utils)
add_subdirectory(pin)
add_subdirectory(read_binary)
add_subdirectory(suspend)
add_subdirectory(init)
add_subdirectory(seq_migration)

add_test(NAME sfi_check COMMAND sh ${CMAKE_CURRENT_SOURCE_DIR}/sfi_check.sh)
add_subdirectory(key_scrub)

if(CONFIG_BUILD_FUZZERS)
	add_subdirectory(fuzz)
endif()
