/*
 * Copyright (c) 2024 Onomondo ApS. All rights reserved.
 *
 * SPDX-License-Identifier: GPL-3.0-only
 *
 * Author: Philipp Maier
 */

#include <onomondo/softsim/file.h>
#include <onomondo/softsim/list.h>
#include <onomondo/softsim/log.h>

/*! Get file struct from a path (tip of the path).
 *  \param[in] path path to the file.
 *  \returns file on success, NULL on failure. */
struct ss_file *ss_get_file_from_path(const struct ss_list *path)
{
	if (ss_list_empty(path))
		return NULL;
	return SS_LIST_GET(path->previous, struct ss_file, list);
}

/*! Get parent file struct from a path (tip of the path minus one file).
 *  \param[in] path path to the file.
 *  \returns file on success, NULL on failure. */
struct ss_file *ss_get_parent_file_from_path(const struct ss_list *path)
{
	if (ss_list_empty(path))
		return NULL;

	/* When the path is only one file long, we end up at the beginning of
	 * the list again, which means there is no parent we could return. */
	if (path->previous->previous == path)
		return NULL;

	return SS_LIST_GET(path->previous->previous, struct ss_file, list);
}
