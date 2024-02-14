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

noinst_LIBRARIES = libmilenage.a

libmilenage_a_SOURCES = \
	milenage.c \
	milenage_usim.c \
	$(NULL)

noinst_HEADERS = \
	milenage.h \
	milenage_usim.h \
	$(NULL)
