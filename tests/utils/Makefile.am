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
	utils_test.ok \
	$(NULL)

noinst_PROGRAMS = \
	utils_test \
	$(NULL)

utils_test_SOURCES = \
	utils_test.c \
	$(NULL)

utils_test_LDADD = \
	$(top_srcdir)/src/softsim/uicc/libuicc.a \
	$(NULL)
