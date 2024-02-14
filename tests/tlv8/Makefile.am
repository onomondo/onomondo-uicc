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
	tlv8_test.ok \
	$(NULL)

noinst_PROGRAMS = \
	tlv8_test \
	$(NULL)

tlv8_test_SOURCES = \
	tlv8_test.c \
	$(NULL)

tlv8_test_LDADD = \
	$(top_srcdir)/src/softsim/uicc/libuicc.a \
	$(NULL)
