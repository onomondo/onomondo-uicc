# Copyright (c) 2024 Onomondo ApS. All rights reserved.
# SPDX-License-Identifier: GPL-3.0-only

set(uicc_collection
	access.c
	apdu.c
	btlv_enc.c
	btlv_dec.c
	btlv_utils.c
	ctlv.c
	command.c
	df_name.c
	fcp.c
	file.c
	fs.c
	fs_chg.c
	fs_utils.c
	uicc_lchan.c
	sfi.c
	sms.c
	sw.c
	softsim.c
	tlv8.c
	uicc_admin.c
	uicc_auth.c
	uicc_cat.c
	uicc_sms_rx.c
	uicc_sms_tx.c
	uicc_remote_cmd.c
	uicc_file_ops.c
	uicc_pin.c
	uicc_refresh.c
	utils.c
	utils_ota.c
	utils_3des.c
	utils_aes.c
	proactive.c
	uicc_suspend.c
)

# Drop opted-out subsystems entirely so their code and data leave the library.
# utils_aes.c stays: the crypto library uses ss_utils_aes_encrypt.
if(CONFIG_DISABLE_OTA)
	list(REMOVE_ITEM uicc_collection uicc_remote_cmd.c utils_ota.c utils_3des.c)
endif()
if(CONFIG_DISABLE_SMS)
	list(REMOVE_ITEM uicc_collection sms.c uicc_sms_rx.c uicc_sms_tx.c)
endif()
if(CONFIG_DISABLE_REFRESH)
	list(REMOVE_ITEM uicc_collection fs_chg.c uicc_refresh.c)
endif()
if(CONFIG_DISABLE_PROACTIVE)
	list(REMOVE_ITEM uicc_collection proactive.c uicc_cat.c)
endif()

# Add log.c to get fcp_test working with CTest. It has otherwise been removed from the
# uicc_collection to allow users to implement log.c themselves by default.
if(BUILD_TESTING)
	set(uicc_collection ${uicc_collection} log.c)
	add_compile_definitions(CONFIG_USE_LOGS)
endif()

# Combine UICC with or without testing required files
add_library(uicc STATIC ${uicc_collection})

target_include_directories(uicc
	PUBLIC
		${PROJECT_SOURCE_DIR}/include
	PRIVATE
		${CMAKE_CURRENT_SOURCE_DIR} ${CMAKE_CURRENT_SOURCE_DIR}/../
)

# Other half of the uicc <-> crypto static-library cycle (see crypto/CMakeLists.txt).
target_link_libraries(uicc PRIVATE crypto)
