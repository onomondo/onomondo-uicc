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
	list_test.ok \
	$(NULL)

noinst_PROGRAMS = \
	list_test \
	$(NULL)

list_test_SOURCES = \
	list_test.c \
	$(NULL)

list_test_LDADD = \
	$(NULL)
