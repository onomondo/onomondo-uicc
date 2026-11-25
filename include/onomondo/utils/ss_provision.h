/*
 * Copyright (c) 2024 Onomondo ApS. All rights reserved.
 *
 * SPDX-License-Identifier: GPL-3.0-only
 */

#pragma once

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

struct ss_profile;

/** Decode a profile string and write it to the SoftSIM filesystem.
 *
 *  The default provisioning path: ss_profile_from_string() followed by
 *  ss_profile_write_to_fs(), with the decoded profile cleared afterwards.
 *
 *  The string "00" (see ss_profile_is_unbind()) unbinds the card instead, as
 *  onomondo_profile_unbind() does.
 *
 *  \param[in] profile the TLV hex profile string, or "00"; NUL terminated
 *  \returns 0 on success, a non-zero value on failure */
int onomondo_profile_provisioning(const char *profile);

/** Unbind the card: remove the subscription instead of loading one.
 *
 *  EF.IMSI gets the template's default IMSI, ICCID, Ki and OPc are zeroed, and
 *  A004 is erased, which turns OTA off. The PIN code file and EF.SMSP are kept.
 *  The default IMSI is written first, so an unbind that fails partway still
 *  leaves a card that reads as not provisioned; afterwards
 *  onomondo_profile_check_provisioned() returns 0. Unbinding a card that is not
 *  provisioned succeeds.
 *
 *  With a key store the EFs only held references: destroy the key slots once
 *  this returned 0 (and the platform persisted its filesystem).
 *
 *  \returns 0 on success, -1 on failure */
int onomondo_profile_unbind(void);

/** Write a decoded profile to the SoftSIM filesystem.
 *
 *  For a platform that needs to act between decoding and writing, e.g. to move
 *  Ki, KIC and KID into a key store and leave a reference to each in its field:
 *  decode with ss_profile_from_string(), edit the fields, then call this. A field
 *  is written as it is found -- a key or a reference to one -- and only when its
 *  tag is set in profile->tags, so an edited field keeps its tag.
 *
 *  ICCID, IMSI, Ki and OPc are required. A001 is built from Ki, OPc and the OPc
 *  flag; A004 is erased and given each OTA key the profile carries; the PIN code
 *  file is patched with the PINs the profile carries and otherwise left as it is.
 *  EFs are written as hex, or as the bytes the hex spells with
 *  CONFIG_COMPACT_STORAGE.
 *
 *  The profile is not cleared; the caller wipes it with ss_profile_wipe().
 *
 *  \param[in] profile the decoded, possibly edited, profile
 *  \returns 0 on success, -1 on failure */
int ss_profile_write_to_fs(const struct ss_profile *profile);

/** Check whether a SoftSIM profile is provisioned.
 *
 *  A card counts as provisioned only while EF.IMSI holds a real subscriber: not
 *  the template's default IMSI (also what unbinding with "00" writes), not a
 *  zeroed IMSI, and not a missing or short EF.
 *
 *  \returns 1 if provisioned, 0 otherwise */
int onomondo_profile_check_provisioned(void);

#ifdef __cplusplus
}
#endif
