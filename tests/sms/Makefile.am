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
	sms_test.ok \
	$(NULL)

noinst_PROGRAMS = \
	sms_test \
	$(NULL)

sms_test_SOURCES = \
	sms_test.c \
	$(NULL)

sms_test_LDADD = \
	$(top_srcdir)/src/softsim/uicc/libuicc.a \
	$(NULL)
