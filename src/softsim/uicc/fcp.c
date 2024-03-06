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

/*! Decode file FCP (file control parameter).
 *  \param[in] pointer to ss_buf object containing the encoded FCP.
 *  \returns decoded FCP on success, NULL on failure. */
struct ss_list *ss_fcp_decode(const struct ss_buf *fcp)
{
	struct ss_list *decoded_fcp;
	decoded_fcp = ss_btlv_decode(fcp->data, fcp->len, ss_fcp_get_descr());
	return decoded_fcp;
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

/*! (Re)-encode the encoded FCP string of a file.
 *  \param[inout] path path to the file.
 *  \returns 0 on success -EINVAL on failure. */
int ss_fcp_reencode(struct ss_file *file)
{
	struct ss_list *fcp;
	struct ber_tlv_ie *fcp_template;
	struct ss_buf *fci;
	int rc = 0;

	/* Generate an FCP template envelope. We have to do that because the
	 * FCP/FCI is stored without the envelope for easier access. */
	fcp = SS_ALLOC(struct ss_list);
	ss_list_init(fcp);
	fcp_template = ss_btlv_new_ie_constr(fcp, "fcp-template", 0x62);

	/* Temporarly attach the FCP to the envelope and re-encode it. */
	ss_btlv_attach_to_constr(fcp_template, file->fcp_decoded);

	fci = ss_btlv_encode_to_ss_buf(fcp);
	if (!fci) {
		rc = -EINVAL;
		goto leave;
	}

	/* Exchange old fci data with re-encoded fci data */
	if (file->fci)
		ss_buf_free(file->fci);
	file->fci = fci;

leave:
	/* Split the FCI away from the envelope and free the envelope part we
	 * have allocated above. */
	ss_btlv_split_off_from_constr(fcp_template);
	ss_btlv_free(fcp);
	return rc;
}

/*! Get DF name from a decoded FCP.
 *  \param[in] fcp_decoded_envelope representation of the file descriptor.
 *  \returns buffer with DF name on success NULL on failure. */
struct ss_buf *ss_fcp_get_df_name(const struct ss_list *fcp_decoded_envelope)
{
	struct ber_tlv_ie *fcp_df_name_ie;

	/*! The returned buffer is the value part of the IE in the TLV tree.
	 *  the caller must not take ownership of the buffer (free it) */

	/* Extract DF Name (if present) */
	fcp_df_name_ie = ss_btlv_get_ie_minlen(fcp_decoded_envelope, TS_102_221_IEI_FCP_DF_NAME, 1);
	if (!fcp_df_name_ie)
		return NULL;

	return fcp_df_name_ie->value;
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
