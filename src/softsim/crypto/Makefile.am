# Copyright (c) 2024 Onomondo ApS. All rights reserved.
# SPDX-License-Identifier: GPL-3.0-only

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

noinst_LIBRARIES = libcrypto.a

libcrypto_a_SOURCES = \
	aes-encblock.c \
	aes-internal-dec.c \
	aes-internal-enc.c \
	aes-internal.c \
	aes-wrap.c \
	des-internal.c

noinst_HEADERS = \
	aes.h \
	aes_i.h \
	aes_wrap.h \
	common.h \
	crypto.h \
	des_i.h \
	includes.h
