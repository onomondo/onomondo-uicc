# Copyright (c) 2024 Onomondo ApS. All rights reserved.
# SPDX-License-Identifier: GPL-3.0-only

# Enable testing for current directory and below.
enable_testing()

add_subdirectory(access)
add_subdirectory(access_sw)
add_subdirectory(aes)
add_subdirectory(apdu)
if(NOT CONFIG_DISABLE_PROACTIVE)
	# replays captured terminal traces that include TERMINAL PROFILE, which
	# answers 6D00 when the CAT commands are compiled out
	add_subdirectory(app_transact)
endif()
add_subdirectory(btlv)
add_subdirectory(ctlv)
if(NOT CONFIG_DISABLE_OTA)
	add_subdirectory(des)
	add_subdirectory(ota)
endif()
if(NOT (CONFIG_DISABLE_OTA OR CONFIG_DISABLE_SMS OR CONFIG_DISABLE_REFRESH OR CONFIG_DISABLE_PROACTIVE))
	# exercises the whole ENVELOPE -> SMS -> remote command -> REFRESH chain
	add_subdirectory(envelope)
endif()
add_subdirectory(fcp)
add_subdirectory(list)
add_subdirectory(record_bounds)
add_subdirectory(record_current)
if(NOT CONFIG_DISABLE_SMS)
	add_subdirectory(sms)
endif()
if(CONFIG_DISABLE_PROACTIVE)
	add_subdirectory(disabled_cmds)
endif()
add_subdirectory(storage)
add_subdirectory(tlv8)
add_subdirectory(utils)
add_subdirectory(pin)
add_subdirectory(read_binary)
add_subdirectory(read_on_df)
add_subdirectory(select)
add_subdirectory(suspend)
if(NOT CONFIG_DISABLE_PROACTIVE)
	# same TERMINAL PROFILE trace constraint as app_transact above
	add_subdirectory(init)
endif()

add_test(NAME sfi_check COMMAND sh ${CMAKE_CURRENT_SOURCE_DIR}/sfi_check.sh)
add_subdirectory(key_scrub)

if(CONFIG_BUILD_FUZZERS)
	add_subdirectory(fuzz)
endif()
