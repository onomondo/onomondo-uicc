/*
 * Copyright (c) 2024 Onomondo ApS. All rights reserved.
 *
 * SPDX-License-Identifier: GPL-3.0-only
 *
 * Author: Philipp Maier
 */

#include <stdbool.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <onomondo/softsim/utils.h>
#include <onomondo/softsim/mem.h>
#include <onomondo/softsim/file.h>
#include "btlv.h"
#include "fcp.h"

const struct ber_tlv_desc bertlv_tree_descr[] = { {
							  .id = 1,
							  .id_parent = 0,
							  .title = "fcp_template",
							  .tag_encoded = 0x62,
						  },
						  {
							  .id = 2,
							  .id_parent = 1,
							  .title = "file_descriptor",
							  .tag_encoded = 0x82,
						  },
						  {
							  .id = 2,
							  .id_parent = 1,
							  .title = "DF_name",
							  .tag_encoded = 0x84,
						  },
						  {
							  .id = 3,
							  .id_parent = 1,
							  .title = "file_identifier",
							  .tag_encoded = 0x83,
						  },
						  {
							  .id = 4,
							  .id_parent = 1,
							  .title = "proprietary_info",
							  .tag_encoded = 0xA5,
						  },
						  {
							  .id = 4,
							  .id_parent = 4,
							  .title = "uicc_characteristics",
							  .tag_encoded = 0x80,
						  },
						  {
							  .id = 4,
							  .id_parent = 4,
							  .title = "application_power_consumption",
							  .tag_encoded = 0x81,
						  },
						  {
							  .id = 4,
							  .id_parent = 4,
							  .title = "minimum_app_clock_freq",
							  .tag_encoded = 0x82,
						  },
						  {
							  .id = 4,
							  .id_parent = 4,
							  .title = "available_memory",
							  .tag_encoded = 0x83,
						  },
						  {
							  .id = 4,
							  .id_parent = 4,
							  .title = "file_details",
							  .tag_encoded = 0x84,
						  },
						  {
							  .id = 4,
							  .id_parent = 4,
							  .title = "reserved_file_size",
							  .tag_encoded = 0x85,
						  },
						  {
							  .id = 4,
							  .id_parent = 4,
							  .title = "maximum_file_size",
							  .tag_encoded = 0x86,
						  },
						  {
							  .id = 4,
							  .id_parent = 4,
							  .title = "suported_system_commands",
							  .tag_encoded = 0x87,
						  },
						  {
							  .id = 4,
							  .id_parent = 4,
							  .title = "specific_uicc_env_cond",
							  .tag_encoded = 0x88,
						  },
						  {
							  .id = 4,
							  .id_parent = 4,
							  .title = "p2p_cat_secured_apdu",
							  .tag_encoded = 0x89,
						  },
						  {
							  .id = 4,
							  .id_parent = 1,
							  .title = "life_cycle_status_int",
							  .tag_encoded = 0x8A,
						  },
						  {
							  .id = 4,
							  .id_parent = 1,
							  .title = "security_attrib_ref_expanded",
							  .tag_encoded = 0xAB,
						  },
						  {
							  .id = 4,
							  .id_parent = 1,
							  .title = "security_attrib_compact",
							  .tag_encoded = 0x8C,
						  },
						  {
							  .id = 4,
							  .id_parent = 1,
							  .title = "security_attrib_expanded",
							  .tag_encoded = 0x8B,
						  },
						  {
							  .id = 4,
							  .id_parent = 1,
							  .title = "pin_status_template_do",
							  .tag_encoded = 0xC6,
						  },
						  {
							  .id = 4,
							  .id_parent = 1,
							  .title = "file_size",
							  .tag_encoded = 0x80,
						  },
						  {
							  .id = 4,
							  .id_parent = 1,
							  .title = "total_file_size",
							  .tag_encoded = 0x81,
						  },
						  {
							  .id = 4,
							  .id_parent = 1,
							  .title = "short_file_id",
							  .tag_encoded = 0x88,
						  },
						  {
							  .id = 0,
						  } };

/*! Get a btlv description with the most important FCP information elements.
 *  \returns description for use with ss_btlv_decode(). */
const struct ber_tlv_desc *ss_fcp_get_descr(void)
{
	return bertlv_tree_descr;
}

/*! Decode file descriptor.
 *  \param[out] user provided memory to store parsed file descriptor.
 *  \param[in] encoded representation of the file descriptor.
 *  \returns 0 on success -EINVAL on failure. */
int ss_fcp_dec_file_descr(struct ss_fcp_file_descr *fd, const struct ss_buf *fd_encoded)
{
	uint8_t fd_byte;

	memset(fd, 0, sizeof(*fd));

	/* A file descriptor is at least 2 bytes long. It consists of the file
	 * descriptor byte and a data coding byte. Both are mandatory, even
	 * though the data coding byte is always 0x21 and ignored by the
	 * terminal */
	if (fd_encoded->len < 2)
		return -EINVAL;

	/* See also: ETSI TS 102 221, Table 11.5 */
	fd_byte = fd_encoded->data[0];

	/* Sharable file ? */
	fd->shareable = (fd_byte >> 7) & 1;

	/* File type */
	fd->type = (fd_byte >> 3) & 0x07;

	/* Structure */
	if ((fd_byte & 0xbf) == 0x39)
		fd->structure = SS_FCP_BTLV;
	else {
		fd->structure = fd_byte & 0x07;
	}

	/* See also: ETSI TS 102 221, Section 11.1.1.4.3 */
	if (fd->structure == SS_FCP_LINEAR_FIXED || fd->structure == SS_FCP_CYCLIC) {
		if (fd_encoded->len < 5)
			return -EINVAL;
		fd->record_len = fd_encoded->data[2] << 8;
		fd->record_len |= fd_encoded->data[3];
		fd->number_of_records = fd_encoded->data[4];
	}

	return 0;
}

/*! Generate file descriptor.
 *  \param[in] fd user provided memory with file descriptor struct.
 *  \returns buffer with generated file descriptor on success NULL on failure. */
struct ss_buf *ss_fcp_gen_file_descr(const struct ss_fcp_file_descr *fd)
{
	struct ss_buf *result;

	if (fd->structure == SS_FCP_LINEAR_FIXED || fd->structure == SS_FCP_CYCLIC) {
		result = ss_buf_alloc(5);
		memset(result->data, 0, 5);
	} else {
		result = ss_buf_alloc(2);
		memset(result->data, 0, 2);
	}

	if (fd->shareable)
		result->data[0] |= 0x40;

	/* See also: ETSI TS 102 221, Table 11.5 */
	result->data[0] |= fd->type << 3;
	result->data[0] |= fd->structure;

	/* Data coding byte */
	result->data[1] = 0x21;

	/* Record oriented file */
	if (fd->structure == SS_FCP_LINEAR_FIXED || fd->structure == SS_FCP_CYCLIC) {
		result->data[2] = fd->record_len >> 8;
		result->data[3] = fd->record_len & 0xff;
		result->data[4] = fd->number_of_records;
	}

	return result;
}

/*! Generate an FCP template to be used with internal files.
 *  \param[in] fd user provided memory with file descriptor struct.
 *  \param[in] fid file ID.
 *  \param[in] file_size size of the file, if not already specified in fd.
 *  \returns buffer with generated file fcp on success NULL on failure. */
struct ss_buf *ss_fcp_gen(const struct ss_fcp_file_descr *fd, uint32_t fid, size_t file_size)
{
	/* NOTE: This file generates a file control parameter template (FCP)
	 * that fullfills minimal requirements. The function is intended to
	 * be used when creating internal (hidden) files. (When creating files
	 * using the CREATE FILE command, the FCP template is provided from
	 * outside.) */

	struct ss_list *fcp;
	struct ss_buf *fd_encoded;
	struct ber_tlv_ie *fcp_template;
	uint8_t fid_array[4];
	size_t fid_len;
	uint8_t file_size_array[4];
	size_t file_size_len;
	struct ss_buf *result;

	fcp = SS_ALLOC(struct ss_list);
	ss_list_init(fcp);

	fcp_template = ss_btlv_new_ie_constr(fcp, "fcp", 0x62);

	/* File descriptor */
	fd_encoded = ss_fcp_gen_file_descr(fd);
	if (!fd_encoded)
		return NULL;
	ss_btlv_new_ie(fcp_template->nested, "file_descriptor", 0x82, fd_encoded->len, fd_encoded->data);
	ss_buf_free(fd_encoded);

	/* FID */
	fid_len = 2;
	if (fid > 0xffff)
		fid_len = 4;
	ss_array_from_uint32(fid_array, fid_len, fid);
	ss_btlv_new_ie(fcp_template->nested, "file_identifier", 0x83, fid_len, fid_array);

	/* File size */
	if (fd->structure == SS_FCP_LINEAR_FIXED || fd->structure == SS_FCP_CYCLIC) {
		file_size = fd->record_len * fd->number_of_records;
	}
	file_size_len = ss_optimal_len_for_uint32(file_size);
	ss_array_from_uint32(file_size_array, file_size_len, file_size);
	ss_btlv_new_ie(fcp_template->nested, "file_size", 0x80, file_size_len, file_size_array);

	result = ss_btlv_encode_to_ss_buf(fcp);
	ss_btlv_free(fcp);

	return result;
}

/* True if all bytes are 0xFF. ss_btlv_decode tolerates such padding after
 * the last IE, so the lookup must as well. */
static bool is_padding(const uint8_t *data, size_t len)
{
	size_t i;

	for (i = 0; i < len; i++) {
		if (data[i] != 0xff)
			return false;
	}
	return true;
}

/* Append an IE to the FCP template of file->fci. */
int ss_fcp_add_ie(struct ss_file *file, uint32_t tag, const struct ss_buf *value)
{
	struct ber_tlv_hdr tmpl, ie;
	size_t pos = 0, content_len, hdr_len;
	struct ss_buf *fci;
	uint8_t *p;

	if (!file || !file->fci || !file->fci->data || !value)
		return -EINVAL;

	if (tag > 0xff || (tag & 0x1f) == 0x1f || value->len > 0x7f)
		return -EINVAL;

	if (ss_btlv_parse_hdr(&tmpl, file->fci->data, file->fci->len) < 0 ||
	    tmpl.tag_encoded != TS_102_221_IEI_FCP_TMPL)
		return -EINVAL;

	/* find end of TLV content */
	while (pos < tmpl.value_len && ss_btlv_parse_hdr(&ie, tmpl.value + pos, tmpl.value_len - pos) == 0)
		pos += ie.total_len;

	if (!is_padding(tmpl.value + pos, tmpl.value_len - pos))
		return -EINVAL;

	content_len = pos + 2 + value->len; /* new content length = old content length + new IE length */
	if (content_len > 0xff)
		return -EINVAL;
	hdr_len = content_len < 0x80 ? 2 : 3;

	fci = ss_buf_try_alloc(hdr_len + content_len);
	if (!fci)
		return -ENOMEM;

	p = fci->data;
	*p++ = TS_102_221_IEI_FCP_TMPL;
	if (hdr_len == 3)
		*p++ = 0x81;
	*p++ = (uint8_t)content_len;
	memcpy(p, tmpl.value, pos); /* copy old content */

	p += pos;
	*p++ = (uint8_t)tag;
	*p++ = (uint8_t)value->len;
	memcpy(p, value->data, value->len); /* copy new content */

	ss_buf_free(file->fci);
	file->fci = fci;
	return 0;
}

/*! Find a top-level IE in the FCP template (62) of an encoded FCI, without allocating.
 *  \pre fci has passed ss_fcp_normalize(). ss_fs_select() does this when it
 *       loads a file. The lookup stops at the first match and does not check
 *       the IEs after it.
 *  \param[in] fci encoded FCI, including the 62 envelope. Not const: callers
 *             may patch the value in place through out.
 *  \param[in] tag single-byte BER-TLV tag; a multi-byte start (low bits 1f)
 *             never matches and returns -ENOENT.
 *  \param[in] min_len minimum value length; shorter counts as missing.
 *  \param[out] out view of the value inside fci. Do not free. Only valid
 *              until fci is changed or freed.
 *  \returns 0 if found, -ENOENT if missing or too short, -EINVAL if malformed. */
int ss_fcp_get_tag_min_len(struct ss_buf *fci, uint8_t tag, size_t min_len, struct ss_buf *out)
{
	struct ber_tlv_hdr tmpl;
	struct ber_tlv_hdr ie;
	size_t pos = 0;

	if (out) {
		out->data = NULL;
		out->len = 0;
	}
	if (!fci || !fci->data || !out)
		return -EINVAL;

	/* Outer envelope must be the FCP template */
	if (ss_btlv_parse_hdr(&tmpl, fci->data, fci->len) < 0)
		return -EINVAL;
	if (tmpl.tag_encoded != TS_102_221_IEI_FCP_TMPL)
		return -EINVAL;

	/* Walk the children until tag is found */
	while (pos < tmpl.value_len) {
		if (ss_btlv_parse_hdr(&ie, tmpl.value + pos, tmpl.value_len - pos) < 0) {
			if (is_padding(tmpl.value + pos, tmpl.value_len - pos))
				break;
			return -EINVAL;
		}

		/* First match wins */
		if (ie.tag_encoded == tag) {
			if (ie.value_len < min_len)
				return -ENOENT;
			/* ie.value points into fci->data; take the offset to keep it writable */
			out->data = fci->data + (ie.value - fci->data);
			out->len = ie.value_len;
			return 0;
		}

		pos += ie.total_len;
	}

	return -ENOENT;
}

/*! Check that a stored FCI holds a well-formed FCP template and cut it down
 *  to that template.
 *  Other well-formed TLVs around the 62 template and FF
 *  padding at the end are accepted. They are dropped here, so SELECT and
 *  STATUS return the template only. The first 62 wins. Inside the template,
 *  every top-level IE must be well-formed, followed by FF padding only.
 *  Nested IEs (e.g. inside A5) are not checked.
 *  Call once when an fci enters memory; ss_fcp_get_tag_min_len() relies on it.
 *  \param[inout] fci encoded FCI; on success it holds the 62 template only.
 *  \returns 0 if valid, -EINVAL otherwise (fci unchanged). */
int ss_fcp_normalize(struct ss_buf *fci)
{
	struct ber_tlv_hdr hdr, tmpl, ie;
	const uint8_t *tmpl_start = NULL;
	size_t pos = 0;

	if (!fci || !fci->data)
		return -EINVAL;

	/* Top level: well-formed TLVs, then only FF padding. Find the first 62. */
	while (pos < fci->len) {
		if (ss_btlv_parse_hdr(&hdr, fci->data + pos, fci->len - pos) < 0) {
			if (!is_padding(fci->data + pos, fci->len - pos))
				return -EINVAL;
			break;
		}
		if (!tmpl_start && hdr.tag_encoded == TS_102_221_IEI_FCP_TMPL) {
			tmpl_start = fci->data + pos;
			tmpl = hdr;
		}
		pos += hdr.total_len;
	}
	if (!tmpl_start)
		return -EINVAL;

	/* Inside the template: well-formed IEs, then only FF padding. */
	pos = 0;
	while (pos < tmpl.value_len) {
		if (ss_btlv_parse_hdr(&ie, tmpl.value + pos, tmpl.value_len - pos) < 0) {
			if (!is_padding(tmpl.value + pos, tmpl.value_len - pos))
				return -EINVAL;
			break;
		}
		pos += ie.total_len;
	}

	memmove(fci->data, tmpl_start, tmpl.total_len);
	fci->len = tmpl.total_len;
	return 0;
}

/*! Dump decoded file descriptor.
 *  \param[in] fd user provided memory with file descriptor struct.
 *  \param[in] indent indentation level of the generated output.
 *  \param[in] log_subsys log subsystem to generate the output for.
 *  \param[in] log_level log level to generate the output for. */
void ss_fcp_dump_file_descr(const struct ss_fcp_file_descr *fd, uint8_t indent, enum log_subsys log_subsys,
			    enum log_level log_level)
{
	char indent_str[256];

	memset(indent_str, ' ', indent);
	indent_str[indent] = '\0';

	SS_LOGP(log_subsys, log_level, "%sshareable = %s\n", indent_str, fd->shareable ? "true" : "false");

	switch (fd->type) {
	case SS_FCP_WORKING_EF:
		SS_LOGP(log_subsys, log_level, "%stype = \"working EF\"\n", indent_str);
		break;
	case SS_FCP_INTERNAL_EF:
		SS_LOGP(log_subsys, log_level, "%stype = \"internal EF\"\n", indent_str);
		break;
	case SS_FCP_DF_OR_ADF:
		SS_LOGP(log_subsys, log_level, "%stype = \"DF or ADF\"\n", indent_str);
		break;
	default:
		SS_LOGP(log_subsys, log_level, "%stype = %x\n", indent_str, fd->type);
		break;
	}

	switch (fd->structure) {
	case SS_FCP_UNKNOWN:
		SS_LOGP(log_subsys, log_level, "%sstructure = \"unknown\"\n", indent_str);
		break;
	case SS_FCP_TRANSPARENT:
		SS_LOGP(log_subsys, log_level, "%sstructure = \"transparent\"\n", indent_str);
		break;
	case SS_FCP_LINEAR_FIXED:
		SS_LOGP(log_subsys, log_level, "%sstructure = \"linear fixed\"\n", indent_str);
		break;
	case SS_FCP_CYCLIC:
		SS_LOGP(log_subsys, log_level, "%sstructure = \"cyclic\"\n", indent_str);
		break;
	case SS_FCP_BTLV:
		SS_LOGP(log_subsys, log_level, "%sstructure = \"BTLV\"\n", indent_str);
		break;
	default:
		SS_LOGP(log_subsys, log_level, "%sstructure = %x\n", indent_str, fd->structure);
		break;
	}

	if (fd->structure == SS_FCP_LINEAR_FIXED || fd->structure == SS_FCP_CYCLIC) {
		SS_LOGP(log_subsys, log_level, "%srecord_len = %u\n", indent_str, fd->record_len);
		SS_LOGP(log_subsys, log_level, "%snumber_of_records = %u\n", indent_str, fd->number_of_records);
	}
}
