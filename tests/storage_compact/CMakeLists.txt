# Copyright (c) 2026 Onomondo ApS. All rights reserved.
# SPDX-License-Identifier: GPL-3.0-only

# storage_compact.c is not part of any library in this build configuration
# (the storage library carries storage.c), so compile it directly, backed by
# the default filesystem implementation, to give the compact read path host
# coverage.
ss_add_test(storage_compact_test LIBS uicc SOURCES
	${PROJECT_SOURCE_DIR}/src/softsim/storage_compact.c
	${PROJECT_SOURCE_DIR}/src/softsim/fs.c
)
