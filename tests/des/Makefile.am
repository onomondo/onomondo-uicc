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
	des_test.ok \
	$(NULL)

noinst_PROGRAMS = \
	des_test \
	$(NULL)

des_test_SOURCES = \
	des_test.c \
	$(NULL)

des_test_LDADD = \
	$(top_srcdir)/src/softsim/uicc/libuicc.a \
	$(top_srcdir)/src/softsim/crypto/libcrypto.a \
	$(NULL)
