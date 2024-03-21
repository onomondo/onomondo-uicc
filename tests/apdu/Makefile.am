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
	apdu_test.ok \
	$(NULL)

noinst_PROGRAMS = \
	apdu_test \
	$(NULL)

apdu_test_SOURCES = \
	apdu_test.c \
	$(NULL)

apdu_test_LDADD = \
	$(top_srcdir)/src/softsim/uicc/libuicc.a \
	$(NULL)
