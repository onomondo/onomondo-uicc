/*
 * Copyright (c) 2024 Onomondo ApS. All rights reserved.
 *
 * SPDX-License-Identifier: GPL-3.0-only
 *
 * Author: Christian Amsüss
 */

#include <stdint.h>
#include <stddef.h>
#include <assert.h>

#include "access.h"
#include "btlv.h"
#include "fs.h"
#include "fs_utils.h"
#include "fcp.h"
#include "uicc_pin.h"
#include "apdu.h"
#include <onomondo/softsim/list.h>
#include <onomondo/softsim/utils.h>

#define ACCESSBYTE_FLAG_PROPRIETARY_HIGHBITS 0x80
#define ACCESSBYTE_MASK_HIGHBITS 0x78

enum arr_ref_type {
	ARR_REF_NONE,	    /**< The FCP contained no access rule reference */
	ARR_REF_IDENTIFIED, /**< A file ID and record number have been identified */
	ARR_REF_UNMATCHING, /**< The file ID was identified, but no data was */
			    /*   available for the given SE ID. (Currently,
			     *   this is the case for all SE ID references, as
			     *   the SE ID is not passed into \ref
			     *   arr_from_fcp). */
};

struct arr_ref {
	enum arr_ref_type type;
	uint16_t file_id;
	uint8_t record_number; /**< Record number inside the file; only valid */
			       /*   for type ARR_REF_IDENTIFIED */
};

const uint8_t FCP_TAG_REFERENCED_FORMAT = 0x8b;
const uint8_t FCP_TAG_SECURITY_ATTRIB_COMPACT = 0x8c;
const uint8_t FCP_TAG_SECURITY_ATTRIB_EXTENDED = 0xab;

/** Extract the access rule reference from the FCP as described in TS 102 221 v15.0.0 Section 9.2.7 */
struct arr_ref arr_from_fcp(struct ss_list *fcp_decoded_envelope)
{
	struct ber_tlv_ie *fcp_decoded_arr;

	struct arr_ref result = { .type = ARR_REF_NONE };

	fcp_decoded_arr = ss_btlv_get_ie(fcp_decoded_envelope, FCP_TAG_REFERENCED_FORMAT);
	if (!fcp_decoded_arr)
		return result;

	if (fcp_decoded_arr->value->len == 3) {
		/* File ID, record number */
		result.type = ARR_REF_IDENTIFIED;
		result.file_id = (fcp_decoded_arr->value->data[0] << 8) | fcp_decoded_arr->value->data[1];
		result.record_number = fcp_decoded_arr->value->data[2];
	} else {
		/* File ID, pairs of SE ID and record numbers */

		/* When support for SE IDs is needed, extend API to pass in an
		 * SE ID from the caller, and set it as IDENTIFIED after
		 * iterating through the SE ID / record number pairs. */
		result.type = ARR_REF_UNMATCHING;
	}

	return result;
}

/** Populate an lchan's selected file's access list
 *
 * \pre The lchan has a selected file.
 * \pre The lchan's current file has its access member unset.
 *
 * \post The lchan's current file has its access member set to the rules that
 *   apply to the lchan (through its SE, but that is currently unimplemented).
 *   These are NULL on a load error, which is treated as 'never allow'.
 *
 * This currently only evaluates access rules through
 * refernces through TS 102 221 V15 section 9.2.7 access rule
 * referencing (EF.ARR). The section 9.2.6 expanded format should be
 * straightforward to add (by leaving out the indirection), and it might be
 * possible to also implement the section 9.2.5 format by expanding it.
 */
void ss_access_populate(struct ss_lchan *lchan)
{
	struct ss_file *selected_file = ss_get_file_from_path(&lchan->fs_path);

	assert(selected_file != NULL);

	/* Access list already populated, so we may return early. */
	if (selected_file->access)
		return;

	struct ss_buf *record;

	/* Check for other security attributes than the supported EF.ARR based ones
	 * -- as we can't evaluate them, they'll lead to rejection.
	 *
	 * These are purely for debugging purposes (since without an EF.ARR
	 * reference, access is denied unconditionally anyway). */
	struct ber_tlv_ie *undecoded_element;
	undecoded_element = ss_btlv_get_ie(selected_file->fcp_decoded, FCP_TAG_SECURITY_ATTRIB_COMPACT);
	if (undecoded_element) {
		SS_LOGP(SACCESS, LERROR, "Compact security attribute present but not implemented.\n");
	}

	undecoded_element = ss_btlv_get_ie(selected_file->fcp_decoded, FCP_TAG_SECURITY_ATTRIB_EXTENDED);
	if (undecoded_element) {
		SS_LOGP(SACCESS, LERROR, "Extended security attribute present but not implemented.\n");
	}

	struct arr_ref arr = arr_from_fcp(selected_file->fcp_decoded);
	switch (arr.type) {
	case ARR_REF_NONE:
		SS_LOGP(SACCESS, LDEBUG, "No access list referenced, denying all access.\n");
		selected_file->access = NULL;
		break;
	case ARR_REF_UNMATCHING:
		SS_LOGP(SACCESS, LERROR, "SE based access list not decoded.\n");
		selected_file->access = NULL;
		break;
	case ARR_REF_IDENTIFIED:
		record = ss_fs_read_relative_file_record(&lchan->fs_path, arr.file_id, arr.record_number);
		if (record != NULL) {
			selected_file->access = ss_btlv_decode(record->data, record->len, NULL);
			ss_buf_free(record);
		}
		SS_LOGP(SACCESS, LDEBUG, "Access referenced into file %04x record %02x, loaded:\n", arr.file_id,
			arr.record_number);
		if (selected_file->access == NULL) {
			SS_LOGP(SACCESS, LDEBUG, "(No valid access condition loaded)\n");
		} else {
			ss_btlv_dump(selected_file->access, 0, SACCESS, LDEBUG);
		}
		break;
	}
}

static bool apdu_matches_am_byte(enum ss_access_intention intention, uint8_t am_byte)
{
	if (intention == SS_ACCESS_INTENTION_OTHER) {
		/* Not covered by this type of rule */
		return false;
	}

	if ((intention & ACCESSBYTE_MASK_HIGHBITS) && (am_byte & ACCESSBYTE_FLAG_PROPRIETARY_HIGHBITS)) {
		/* Intention has standardized high bits set, but the required am_byte does
		 * not even express them */
		return false;
	}

	return intention & am_byte;
}

static bool apdu_matches_sc_byte(struct ss_apdu *apdu, uint8_t sc_byte)
{
	/* FIXME #55: Evaluate precise condition */
	return false;
}

/** Extract the access condition according to TS 102 221 V15.0.0 table 9.3.
 *
 * For example, ADM1 is 0x0A.
 *
 * This extracts only the key ref value, and checks that the access condition
 * (which is a constructed value) is otherwise valid, ie. has both a 1 long key
 * reference (83) IE and a usager qualifer (95) IE with value 01.
 * */
static uint8_t access_condition_extract(struct ss_list *access_condition)
{
	uint8_t result = 0;
	bool usage_qualifier_ok = false;
	bool unexpected_ie = false;

	struct ber_tlv_ie *item;
	SS_LIST_FOR_EACH(access_condition, item, struct ber_tlv_ie, list) {
		if (item->tag_encoded == 0x83 && item->value->len == 1) {
			result = item->value->data[0];
		} else if (item->tag_encoded == 0x95 && item->value->len == 1) {
			usage_qualifier_ok = true;
		} else {
			unexpected_ie = true;
		}
	}

	if (!usage_qualifier_ok || unexpected_ie) {
		result = 0;
	}
	return result;
}

/** Decide whether a command is allowed based on the selected file's access rules.
 *
 * \param[in] apdu The command being executed.
 *   The file accessed through it must be selected in its `lchan`,
 *   which especially means that its `.access` needs to be populated.
 * \param[in] intention The operation the caller is about to perform. While
 *   this is encoded in the APDU already, this reduces duplication across the
 *   code (as the caller alreay knows that it is about to perform a read). This
 *   parameter must be aligned with the \p apdu; depending on how the access
 *   rules are phrased, this function will either use the intention (for
 *   evaluating access mode bytes), or it will use the APDU's CLA, INS and Pn
 *   (for evaluating access mode data objects; currently not implemented).
 *   The intention must also match the \p file's type.
 *
 * If the card is in creation / initialization state (judged by the MF's life
 * cycle, and assumed in absence of an MF), access controls are dispensed, and
 * all access is allowed.
 *
 * \return true if select access is allowed according to the file's access rules.
 *
 * eg. per TS 102 221 V15 9.2.0, SS_SW_ERR_CMD_NOT_ALLOWED_SECURITY_STATUS
 * should indicate that the condition could not be determined, equivalent
 * to ->access=NULL
 */
bool ss_access_check_command(struct ss_apdu *apdu, enum ss_access_intention intention)
{
	struct ss_file *selected_file = ss_get_file_from_path(&apdu->lchan->fs_path);

	/* Before we go to regualr access control, maybe we're in creation /
	 * initialization state -- which is indicated in the master file. */

	if (selected_file == NULL) {
		/* The only currently known situation in which an empty path can ever be
		 * around is when there is no MF yet, and thus the card is in creation /
		 * initialization (personalization) state.
		 *
		 * As an empty path also might result from programming errors, whose
		 * consequences here would be severe (lifting all access restrictions),
		 * this double check is performed to verify that there is indeed no MF
		 * loadable.
		 * */
		struct ss_list check_mf_path = { NULL, NULL };
		ss_fs_init(&check_mf_path);
		assert(ss_get_file_from_path(&apdu->lchan->fs_path) == NULL);

		SS_LOGP(SACCESS, LINFO,
			"MF in creation / initialization state (MF not even present), bypassing authorizations.\n");
		return true;
	}

	/* Go over the end twice to find the DLL's first element */
	struct ss_file *mf = ss_get_file_from_path(apdu->lchan->fs_path.next->next);
	/* If a situation ever comes up where using a path that does not start at the
	 * MF is valid, we can still consider loading the MF as it is done above --
	 * but until there is a legitimate use case, it is most likely a bug. */
	assert(mf->fid == 0x3f00);

	struct ber_tlv_ie *lcsi_do = ss_btlv_get_ie_minlen(mf->fcp_decoded, TS_102_221_IEI_FCP_LIFE_CYCLE_ST, 1);
	if (lcsi_do == NULL || lcsi_do->value->data[0] == 0) {
		/* As above. */
		SS_LOGP(SACCESS, LERROR, "MF's envelope contained no lifecycle information, rejecting all access.\n");
		return false;
	}
	SS_LOGP(SACCESS, LDEBUG, "MF lifecycle is %02x\n", lcsi_do->value->data[0]);
	if (lcsi_do->value->data[0] < 4) {
		SS_LOGP(SACCESS, LINFO,
			"MF in creation / initialization state (as indicated in the MF), bypassing authorizations.\n");
		return true;
	}
	/* FIXME #56: Do we want to check for MF deactivation / termination as well, while we're at it? */

	/* Card is in operational state or later -- performing regular access control. */

	SS_LOGP(SACCESS, LDEBUG, "Checking access to path=%s with intention=%02x\n",
		ss_fs_utils_dump_path(&apdu->lchan->fs_path), intention);

	if (selected_file->access == NULL) {
		SS_LOGP(SACCESS, LERROR, "No valid access rules available, rejecting.\n");
		return false;
	}

	/* Next steps:
	 *
	 * * check at file creation whether referenced file is present.
	 */

	/* Iterate over the rules until a matching AM (Access Mode) is found, then go
	 * through the following SCs to reject if any doesn't match. There is no need
	 * to go back to looking into AMs once at the SC stage: their content "shall
	 * be unique" within the rulle according to TS 102 221 V15.0.0 section 9.2.4.
	 * */

	bool sc_phase = false;
	bool sc_leastone = false; /* Set to verify that at least one SC was
	                           * evaluated. Having one in there is a requirement
	                           * that a rule might violate, and invalid rules
	                           * should lead to rejection (while without this
	                           * check they'd lead to acceptance based on ALL({})
	                           * being true for every question) */
	struct ber_tlv_ie *item;
	SS_LIST_FOR_EACH(selected_file->access, item, struct ber_tlv_ie, list) {
		/* This could also be two loops, one looking for the AM (sc_phase == 0) and
		 * one looking for a matching SC (sc_phase == 1), but the way SS_LIST
		 * iteration works would not have better readability */

		if (!sc_phase) {
			switch (item->tag_encoded) {
			/* The SCs according to ISO/IEC 7816-4:2005(e) table 23 */
			case 0x90:
			case 0x97:
			case 0x9E:
			case 0xA4:
			case 0xB4:
			case 0xB6:
			case 0xB8:
			case 0xA0:
			case 0xA7:
			case 0xAF:
				if (&item->list == selected_file->access) {
					SS_LOGP(SACCESS, LERROR, "Invalid access rule: Starts with an SC\n");
					return false;
				}
				/* Ignore: We didn't match on the preceding AM */
				continue;
			case 0x80:
				if (item->value->len != 1) {
					SS_LOGP(SACCESS, LERROR, "Invalid access rule: AM byte with len != 1\n");
					return false;
				}
				if (apdu_matches_am_byte(intention, item->value->data[0])) {
					SS_LOGP(SACCESS, LDEBUG, "Matched on AM %02x, evaluating SCs.\n",
						item->value->data[0]);
					sc_phase = true;
				}
				continue;
			/* Command headers currently not supported. */
			case 0x81:
			case 0x82:
			case 0x83:
			case 0x84:
			case 0x85:
			case 0x86:
			case 0x87:
			case 0x88:
			case 0x89:
			case 0x8A:
			case 0x8B:
			case 0x8C:
			case 0x8D:
			case 0x8E:
			case 0x8F:
			/* We don't have a proprietary state machine */
			case 0x9C:
				SS_LOGP(SACCESS, LERROR,
					"Access rule with unknown AM %02x. Continuing to look for satisfiable rules.\n",
					item->tag_encoded);
				/* There is no harm in doing this: the rules do not overlap, so if we
         * find something later, nothing in here could have overlapped with it,
         * and if we don't find anything, we reject by default anyway. */
				continue;
			default:
				SS_LOGP(SACCESS, LERROR,
					"Access rule with entry neither AM nor SC tag %02x, aborting.\n",
					item->tag_encoded);
				return false;
			}
		} else {
			switch (item->tag_encoded) {
			/* The SCs according to ISO/IEC 7816-4:2005(e) table 23 */
			case 0x90:
				SS_LOGP(SACCESS, LDEBUG, "Continuing on 'always' SC.\n");
				sc_leastone = true;
				continue;
			case 0x97:
				SS_LOGP(SACCESS, LDEBUG, "Encountered on 'never' SC, rejecting.\n");
				return false;
			case 0x9E:
				if (item->value->len != 1) {
					SS_LOGP(SACCESS, LERROR, "Invalid access rule: SC byte with len != 1\n");
					return false;
				}
				if (apdu_matches_sc_byte(apdu, item->value->data[0])) {
					sc_leastone = true;
					continue;
				} else {
					SS_LOGP(SACCESS, LDEBUG, "SC %02x not matched, rejecting.\n",
						item->value->data[0]);
					return false;
				}
			case 0xA4: {
				uint8_t access_condition = access_condition_extract(item->nested);
				if (access_condition == 0) {
					SS_LOGP(SACCESS, LERROR, "Acccess condition not understood, rejecting.\n");
					return false;
				}
				if (ss_uicc_pin_verified(access_condition, apdu->lchan)) {
					sc_leastone = true;
					continue;
				}
				SS_LOGP(SACCESS, LDEBUG, "Access condition %02x required but pin not verified.\n",
					access_condition);
				return false;
			}
			case 0xB4:
			case 0xB6:
			case 0xB8:
			case 0xA0: /* OR template, not supported */
			case 0xA7: /* NOT template, not supported */
			case 0xAF: /* AND template, not supported, and useless without OR and NOT */
				SS_LOGP(SACCESS, LDEBUG, "Encountered unknown SC %02x, rejecting.\n",
					item->tag_encoded);
				return false;
			/* All known AMs */
			case 0x80:
			case 0x81:
			case 0x82:
			case 0x83:
			case 0x84:
			case 0x85:
			case 0x86:
			case 0x87:
			case 0x88:
			case 0x89:
			case 0x8A:
			case 0x8B:
			case 0x8C:
			case 0x8D:
			case 0x8E:
			case 0x8F:
			case 0x9C:
				/* break from switch and from loop */
				goto end_sc;
			default:
				SS_LOGP(SACCESS, LERROR,
					"Access rule with entry neither AM nor SC tag %02x, aborting.\n",
					item->tag_encoded);
				return false;
			}
		}
	}
	if (!sc_phase) {
		SS_LOGP(SACCESS, LDEBUG, "No AM matched\n");
		return false;
	}

end_sc:
	if (!sc_leastone) {
		SS_LOGP(SACCESS, LERROR, "Not even one SC present after AM, rejecting\n");
		return false;
	}

	SS_LOGP(SACCESS, LDEBUG, "No SC after the AM caused early rejection, accepting\n");
	return true;
}
