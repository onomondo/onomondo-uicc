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
 *  \param[in] profile the TLV hex profile string, NUL terminated
 *  \returns 0 on success, -1 on failure */
int onomondo_profile_provisioning(const char *profile);

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

#ifdef __cplusplus
}
#endif
