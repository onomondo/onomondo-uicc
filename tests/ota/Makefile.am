# Copyright (c) 2024 Onomondo ApS. All rights reserved.
# SPDX-License-Identifier: GPL-3.0-only

AM_CPPFLAGS = \
	$(all_includes) \
	-I$(top_srcdir)/include \
	$(NULL)

AM_CFLAGS = \
	-Wall \
	-ggdb3 \
	$(NULL)

EXTRA_DIST = \
	ota_test.ok \
	$(NULL)

noinst_PROGRAMS = \
	ota_test \
	$(NULL)

ota_test_SOURCES = \
	ota_test.c \
	$(NULL)

ota_test_LDADD = \
	$(top_srcdir)/src/softsim/uicc/libuicc.a \
	$(top_srcdir)/src/softsim/crypto/libcrypto.a \
	$(NULL)
