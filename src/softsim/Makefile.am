# Copyright (c) 2024 Onomondo ApS. All rights reserved.
# SPDX-License-Identifier: GPL-3.0-only

SUBDIRS = uicc \
	  crypto \
	  milenage \
	  .

AM_CPPFLAGS = \
	$(all_includes) \
	-I$(top_srcdir)/include \
	-I$(top_builddir) \
	$(NULL)

AM_CFLAGS = \
	-Wall \
	$(NULL)

AM_LDFLAGS = \
	$(NULL)

bin_PROGRAMS = \
	softsim \
	$(NULL)

softsim_SOURCES = \
	storage.c \
	main.c \
	$(NULL)

noinst_HEADERS = \
	$(NULL)

softsim_LDADD = \
	uicc/libuicc.a \
	milenage/libmilenage.a \
	crypto/libcrypto.a \
	$(NULL)
