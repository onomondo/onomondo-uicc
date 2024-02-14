# Copyright (c) 2024 Onomondo ApS. All rights reserved.
# SPDX-License-Identifier: GPL-3.0-only

AM_CPPFLAGS = \
	$(all_includes) \
	-I$(top_srcdir)/include \
	-I$(top_builddir) \
	-I$(top_srcdir)/src/softsim \
	$(NULL)

AM_CFLAGS = \
	-Wall \
	$(NULL)

AM_LDFLAGS = \
	$(NULL)

noinst_LIBRARIES = libuicc.a

libuicc_a_SOURCES = \
	access.c \
	apdu.c \
	btlv_enc.c \
	btlv_dec.c \
	btlv_utils.c \
	ctlv.c \
	command.c \
	df_name.c \
	fcp.c \
	file.c \
	fs.c \
	fs_chg.c \
	fs_utils.c \
	uicc_lchan.c \
	log.c \
	sfi.c \
	sms.c \
	sw.c \
	softsim.c \
	tlv8.c \
	uicc_admin.c \
	uicc_auth.c \
	uicc_cat.c \
	uicc_sms_rx.c \
	uicc_sms_tx.c \
	uicc_remote_cmd.c \
	uicc_file_ops.c \
	uicc_pin.c \
	uicc_refresh.c \
	utils.c \
	utils_3des.c \
	utils_aes.c \
	utils_ota.c \
	proactive.c \
	$(NULL)

noinst_HEADERS = \
	access.h \
	apdu.h \
	btlv.h \
	ctlv.h \
	command.h \
	df_name.h \
	context.h \
	fcp.h \
	fs_chg.h \
	fs_utils.h \
	uicc_lchan.h \
	sfi.h \
	sms.h \
	sw.h \
	tlv8.h \
	uicc_admin.h \
	uicc_auth.h \
	uicc_cat.h \
	uicc_sms_rx.h \
	uicc_sms_tx.h \
	uicc_remote_cmd.h \
	uicc_file_ops.h \
	uicc_ins.h \
	uicc_pin.h \
	uicc_refresh.h \
	utils_3des.h \
	utils_aes.h \
	utils_ota.h \
	proactive.h \
	$(NULL)
