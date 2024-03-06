/*
 * Copyright (c) 2024 Onomondo ApS. All rights reserved.
 * 
 * SPDX-License-Identifier: GPL-3.0-only 
 */

#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <errno.h>
#include <assert.h>
#include <onomondo/softsim/utils.h>
#include <onomondo/softsim/file.h>
#include <onomondo/softsim/list.h>
#include <onomondo/softsim/log.h>
#include "fs_chg.h"

struct ss_file_blacklist {
	size_t path_len;
	char path[SS_FS_CHG_PATH_MAXLEN];
};

/* Some files serve special internal purposes even though they have 16 bit file
 * identifiers. We don't want the terminal to be notified about file changes
 * in those files even when there is a file change */
const static struct ss_file_blacklist blacklist[] = {
	{ .path_len = 4, .path = "\x3F\x00\xA0\x01" },
	{ .path_len = 4, .path = "\x3F\x00\xA0\x02" },
	{ .path_len = 4, .path = "\x3F\x00\xA0\x03" },
	{ .path_len = 4, .path = "\x3F\x00\xA0\x04" },
};

/* Check if a path is blacklisted */
static bool path_in_blacklist(const uint8_t *path, size_t path_len)
{
	size_t i;

	for (i = 0; i < SS_ARRAY_SIZE(blacklist); i++) {
		if (blacklist[i].path_len != path_len)
			continue;
		if (memcmp(blacklist[i].path, path, path_len) == 0)
			return true;
	}

	return false;
}

/* See also ETSI TS 102 223, section 8.18 */
static int pack_path(uint8_t result[SS_FS_CHG_PATH_MAXLEN], const struct ss_list *path)
{
	struct ss_file *path_cursor;
	uint8_t *result_ptr = result;

	if (ss_list_empty(path))
		return -EINVAL;

	memset(result, 0, SS_FS_CHG_PATH_MAXLEN);

	/* A FID consists of two bytes, so we expect a buffer size that is
	 * divisible by 2 */
	assert(SS_FS_CHG_PATH_MAXLEN % 2 == 0);

	SS_LIST_FOR_EACH(path, path_cursor, struct ss_file, list) {
		/* Exclude internal files */
		if (path_cursor->fid > 0xFFFF)
			return -EINVAL;

		/* Record path */
		if (result_ptr - result > SS_FS_CHG_PATH_MAXLEN)
			return -EINVAL;
		*result_ptr = (path_cursor->fid >> 8) & 0xff;
		result_ptr++;
		*result_ptr = path_cursor->fid & 0xff;
		result_ptr++;
	}

	if (result_ptr - result + 2 > SS_FS_CHG_PATH_MAXLEN)
		return -EINVAL;

	/* Append 0x3f00 at the end of the path. This ending serves as a
	 * termination and delimeter symbol */
	*result_ptr = 0x3F;
	result_ptr++;
	*result_ptr = 0x00;
	result_ptr++;

	return result_ptr - result;
}

/*! Dump filelist contents.
 *  \param[in] filelist buffer with list of file pathes (ETSI TS 102 223, section 8.18)
 *  \param[in] indent indentation level of the generated output.
 *  \param[in] log_subsys log subsystem to generate the output for.
 *  \param[in] log_level log level to generate the output for. */
void ss_fs_chg_dump(const uint8_t filelist[SS_FS_CHG_BUF_SIZE], uint8_t indent, enum log_subsys subsys,
		    enum log_level level)
{
	unsigned int i;
	const uint8_t *files = filelist;
	uint16_t fid;
	char path_prn[SS_FS_CHG_PATH_MAXLEN * 2 + SS_FS_CHG_PATH_MAXLEN / 2 + 1];
	char *path_prn_ptr;
	char indent_str[256];

	memset(indent_str, ' ', indent);
	indent_str[indent] = '\0';

	/* Advance to the end of the list */
	files++;
	for (i = 0; i < filelist[0]; i++) {
		path_prn_ptr = path_prn;

		/* Make sure the path starts with MF */
		fid = *files << 8;
		files++;
		fid |= *files;
		files++;
		if ((fid & 0xFF00) != 0x3F00) {
			SS_LOGP(subsys, level, "Filelist invalid, path does not begin with 0x3FXX (MF)\n");
			return;
		}

		do {
			snprintf(path_prn_ptr, sizeof(path_prn) - (path_prn_ptr - path_prn), "/%04x", fid);
			path_prn_ptr += 5;

			fid = *files << 8;
			files++;
			if (files - filelist > SS_FS_CHG_BUF_SIZE) {
				SS_LOGP(subsys, level, "Filelist invalid, end of path not detected!");
				return;
			}
			fid |= *files;
			files++;
			if (files - filelist > SS_FS_CHG_BUF_SIZE) {
				SS_LOGP(subsys, level, "Filelist invalid, end of path not detected!");
				return;
			}

		} while ((fid & 0xFF00) != 0x3F00);

		SS_LOGP(subsys, level, "%s%s\n", indent_str, path_prn);

		files -= 2;
	}
}

/*! Add path to file list.
 *  \param[in] filelist buffer with list of file pathes (ETSI TS 102 223, section 8.18)
 *  \param[in] path path to reset.
 *  \returns 0 on success, 1 when the buffer is 1/2 full, -ENOMEM when the buffer is full, -EINVAL on failure. */
int ss_fs_chg_add(uint8_t filelist[SS_FS_CHG_BUF_SIZE], const struct ss_list *path)
{
	uint8_t *files = filelist;
	uint16_t fid;
	unsigned int i;
	size_t bytes_free;
	uint8_t path_packed[SS_FS_CHG_PATH_MAXLEN];
	int path_packed_len;
	bool add = true;

	/* We expect a result of at least two byte, which would be just 0x3f00 */
	path_packed_len = pack_path(path_packed, path);
	if (path_packed_len < 2)
		return -EINVAL;

	/* Chack wehther the file is a blacklisted file */
	if (path_in_blacklist(path_packed, path_packed_len - 2))
		add = false;

	/* skip memory location where the number of files is stored */
	files++;

	/* Advance to the end of the list */
	for (i = 0; i < filelist[0]; i++) {
		/* Check whether the file is already known */
		if (files - filelist < SS_FS_CHG_BUF_SIZE - path_packed_len &&
		    memcmp(path_packed, files, path_packed_len) == 0)
			add = false;

		/* Make sure the path starts with MF */
		fid = *files << 8;
		files++;
		fid |= *files;
		files++;
		if ((fid & 0xFF00) != 0x3F00)
			return -EINVAL;

		do {
			fid = *files << 8;
			files++;
			if (files - filelist > SS_FS_CHG_BUF_SIZE)
				return -EINVAL;
			fid |= *files;
			files++;
			if (files - filelist > SS_FS_CHG_BUF_SIZE)
				return -EINVAL;
		} while ((fid & 0xFF00) != 0x3F00);
		files -= 2;
	}

	/* Check if there is still enough memory to store the new entry, inform
	 * the caller when we are out of memory */
	bytes_free = SS_FS_CHG_BUF_SIZE - (files - filelist);
	if (bytes_free < path_packed_len)
		return -ENOMEM;

	/* Store path in list and increment number of files, but only if the
	 * path is not already in the list. */
	if (add) {
		memcpy(files, path_packed, path_packed_len);
		filelist[0]++;
	}

	/* Warn caller that the memory is soon full and action must be taken
	 * (sending REFRESH via CAT overdue) */
	if (bytes_free < SS_FS_CHG_PATH_MAXLEN * 2)
		return 1;

	return 0;
}

/*! Get filelist length in bytes.
 *  \param[in] filelist buffer with list of file pathes (ETSI TS 102 223, section 8.18)
 *  \returns length of filelist, -EINVAL on failure. */
int ss_fs_chg_len(const uint8_t filelist[SS_FS_CHG_BUF_SIZE])
{
	const uint8_t *files = filelist;
	uint16_t fid;
	unsigned int i;

	/* skip memory location where the number of files is stored */
	files++;

	/* Advance to the end of the list */
	for (i = 0; i < filelist[0]; i++) {
		/* Make sure the path starts with MF */
		fid = *files << 8;
		files++;
		fid |= *files;
		files++;
		if ((fid & 0xFF00) != 0x3F00)
			return -EINVAL;

		do {
			fid = *files << 8;
			files++;
			if (files - filelist > SS_FS_CHG_BUF_SIZE)
				return -EINVAL;
			fid |= *files;
			files++;
			if (files - filelist > SS_FS_CHG_BUF_SIZE)
				return -EINVAL;
		} while (fid != 0x3F00);
		files -= 2;
	}

	return files - filelist;
}
