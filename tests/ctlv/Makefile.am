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
	ctlv_test.ok \
	$(NULL)

noinst_PROGRAMS = \
	ctlv_test \
	$(NULL)

ctlv_test_SOURCES = \
	ctlv_test.c \
	$(NULL)

ctlv_test_LDADD = \
	$(top_srcdir)/src/softsim/uicc/libuicc.a \
	$(NULL)
