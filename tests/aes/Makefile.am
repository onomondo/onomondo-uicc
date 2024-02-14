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
	aes_test.ok \
	$(NULL)

noinst_PROGRAMS = \
	aes_test \
	$(NULL)

aes_test_SOURCES = \
	aes_test.c \
	$(NULL)

aes_test_LDADD = \
	$(top_srcdir)/src/softsim/uicc/libuicc.a \
	$(top_srcdir)/src/softsim/crypto/libcrypto.a \
	$(NULL)
