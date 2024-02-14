/*
 * Copyright (c) 2024 Onomondo ApS. All rights reserved.
 * 
 * SPDX-License-Identifier: GPL-3.0-only 
 */

#pragma once

#include <onomondo/softsim/list.h>
#include <stdint.h>
struct ss_buf;
struct ss_fcp_file_descr;

/** A handle to a file that has been accessed far enough to ensure that it is
 * present and has its `fcp_file_descr` loaded.
 *
 * Initialized handles are, through their lists, always part of a chain down to
 * the MF (in their .list.previous).
 *
 * When an `ss_file` is created through a "select" operation, all its indirect
 * details (`aid`, `fci`, `fcp_decoded`) are present, both in the file and its
 * parents. (`fcp_file_descr` is always present).
 *
 * The `access` property is not populated in "select" operations, but through
 * the dedicated \ref ss_access_populate, which is invoked from the commands
 * implementing selection for the terminal.
 *
 * Handles created through other operations (mainly in internal use) may have
 * NULL pointers in these places.
 */
struct ss_file {
	struct ss_list list;
	uint32_t fid;
	struct ss_buf *aid;	/* also called 'DF name' */
	struct ss_buf *fci; /* The full file control information (FCI) in encoded form.
	                     *
	                     * This is the full data sent in response to SELECT
	                     * calls; while ISO-IEC 7816-4 allows different
	                     * information in here (eg. FMD), TS 102 221 usually only
	                     * expects FCP data here. */
	struct ss_list *fcp_decoded; /* The decoded form of the FCP that is part of the file control information */
	struct ss_fcp_file_descr *fcp_file_descr;
	struct ss_list *access; /**< The access rule governing file operations for
	                         * the SE that selected the file (or general access if
	                         * no SE apply). A value of NULL indicates that no
	                         * access rules have (or could be) loaded. */
};

struct ss_file *ss_get_file_from_path(const struct ss_list *path);
struct ss_file *ss_get_parent_file_from_path(const struct ss_list *path);
