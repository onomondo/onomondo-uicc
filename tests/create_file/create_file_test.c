/*
 * Copyright (c) 2026 Onomondo ApS. All rights reserved.
 *
 * SPDX-License-Identifier: GPL-3.0-only
 *
 * CREATE FILE cleanup: when the select that follows a successful create
 * fails, ss_uicc_admin_cmd_create_file() removes the new file again with
 * ss_fs_delete_child(). At that point the tip of the path is the parent DF,
 * so the cleanup must delete the child only and leave the parent and the
 * path untouched. The select failure is forced by overwriting the child's
 * definition with an FCP that does not decode.
 *
 * All checks are assert()s; the test aborts on the first failing one.
 */

#undef NDEBUG
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <onomondo/softsim/file.h>
#include <onomondo/softsim/list.h>
#include <onomondo/softsim/mem.h>
#include <onomondo/softsim/softsim.h>
#include <onomondo/softsim/storage.h>
#include <onomondo/softsim/utils.h>
#include "src/softsim/uicc/fs.h"

/* silence library logs, results are checked with assert() only */
extern uint32_t ss_log_mask;

#define FID_MF 0x3f00
#define FID_DF 0x7f99 /* parent DF, created by the test */
#define FID_EF 0x6f01 /* child EF */
#define FID_SUB_DF 0x5f01 /* child DF */

/* The outer length byte is filled in by create() */
#define DF_FCP "62008202782183027f998a01058b032f060fc60990012083010183010a"
#define EF_FCP "62008202412183026f018a01058b036f060580020004"
#define SUB_DF_FCP "62008202782183025f018a01058b032f060fc60990012083010183010a"

/* Transparent EF 2F70 under the MF, 4 bytes, no SFI (22 bytes, '62' header added per case) */
#define EF2F70_FCP "8202412183022f708a01058b032f0610800200048800"

static int create(struct ss_list *path, const char *fcp_hex)
{
	uint8_t fcp[128];
	size_t len = ss_binary_from_hexstr(fcp, sizeof(fcp), fcp_hex);

	fcp[1] = len - 2;
	return ss_fs_create(path, fcp, len);
}

/* Number of files in the path, MF included */
static size_t path_depth(const struct ss_list *path)
{
	const struct ss_list *e;
	size_t n = 0;

	for (e = path->next; e != path; e = e->next)
		n++;
	return n;
}

/* Read the definition of a child of the DF at the tip of the path straight
 * from storage, without selecting it. Works with every storage backend. */
static int child_def_exists(struct ss_list *path, uint32_t fid)
{
	struct ss_file child;
	int rc;

	memset(&child, 0, sizeof(child));
	child.fid = fid;
	ss_list_put(path, &child.list);
	rc = ss_storage_get_file_def(path);
	ss_list_remove(&child.list);
	ss_buf_free(child.fci);
	return rc == 0;
}

/* Overwrite the definition of a child with one byte that is not valid
 * BER-TLV, so that the next select of that child fails. */
static void corrupt_child_def(struct ss_list *path, uint32_t fid)
{
	struct ss_file child;
	uint8_t junk = 0x00;

	memset(&child, 0, sizeof(child));
	child.fid = fid;
	child.fci = ss_buf_alloc_and_cpy(&junk, 1);
	ss_list_put(path, &child.list);
	assert(ss_storage_update_def(path) == 0);
	ss_list_remove(&child.list);
	ss_buf_free(child.fci);
}

/* Create a child, break it, and run the create_file error path on it. */
static void create_select_fail_cleanup(struct ss_list *path, const char *name, uint32_t fid, const char *fcp_hex)
{
	size_t depth;

	/* name the case up front, assert() itself only prints the failed expression */
	fprintf(stderr, "TEST: %s\n", name);

	assert(ss_get_file_from_path(path)->fid == FID_DF);
	depth = path_depth(path);

	assert(create(path, fcp_hex) == 0);
	assert(child_def_exists(path, fid));

	corrupt_child_def(path, fid);
	assert(ss_fs_select(path, fid) < 0);

	/* failed select leaves the parent at the tip */
	assert(ss_get_file_from_path(path)->fid == FID_DF);
	assert(path_depth(path) == depth);

	/* this is what ss_uicc_admin_cmd_create_file() does here */
	assert(ss_fs_delete_child(path, fid) == 0);

	/* path unchanged, child gone */
	assert(ss_get_file_from_path(path)->fid == FID_DF);
	assert(path_depth(path) == depth);
	assert(!child_def_exists(path, fid));

	/* the parent DF must still be there (look it up from the MF) */
	assert(ss_fs_select(path, FID_MF) == 0);
	assert(child_def_exists(path, FID_DF));
	assert(ss_fs_select(path, FID_DF) == 0);
}

static uint16_t transact(struct ss_context *ctx, const char *hex)
{
	uint8_t cmd[300];
	uint8_t rsp[300];
	size_t cmd_len = ss_binary_from_hexstr(cmd, sizeof(cmd), hex);
	size_t rsp_len = ss_application_apdu_transact(ctx, rsp, sizeof(rsp), cmd, &cmd_len);

	assert(rsp_len >= 2);
	return (uint16_t)((rsp[rsp_len - 2] << 8) | rsp[rsp_len - 1]);
}

/* CREATE FILE checks the template before access, so no ADM is needed: padding inside it is
 * refused with 6A80, and the same template without padding reaches the access check (69xx). */
static void create_padded_template(void)
{
	struct ss_context *ctx;

	fprintf(stderr, "TEST: padded template refused\n");

	ctx = ss_new_ctx();
	ss_reset(ctx);

	assert(transact(ctx, "00e000001a6218" EF2F70_FCP "ffff") == 0x6a80);
	assert(transact(ctx, "00e00000186216" EF2F70_FCP) >> 8 == 0x69);

	ss_free_ctx(ctx);
}

int main(void)
{
	struct ss_list path;

	ss_log_mask = 0;

	ss_fs_init(&path);
	assert(ss_get_file_from_path(&path)->fid == FID_MF);

	/* fresh parent DF, so the test never touches the shipped files */
	assert(create(&path, DF_FCP) == 0);
	assert(ss_fs_select(&path, FID_DF) == 0);

	create_select_fail_cleanup(&path, "EF child: delete after failed select", FID_EF, EF_FCP);
	create_select_fail_cleanup(&path, "DF child: delete after failed select", FID_SUB_DF, SUB_DF_FCP);

	/* leave the private filesystem copy as it was */
	assert(ss_get_file_from_path(&path)->fid == FID_DF);
	assert(ss_storage_delete(&path) == 0);
	ss_path_reset(&path);

	create_padded_template();

	return 0;
}
