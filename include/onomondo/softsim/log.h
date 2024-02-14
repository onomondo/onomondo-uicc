/*
 * Copyright (c) 2024 Onomondo ApS. All rights reserved.
 * 
 * SPDX-License-Identifier: GPL-3.0-only 
 */

#pragma once

#include <stdio.h>
#include <stdint.h>

/*! macro to print a log line.
 *  \param[in] subsys log subsystem identifier.
 *  \param[in] level log level identifier.
 *  \param[in] fmt formtstring.
 *  \param[in] args formatstring arguments. */
#define SS_LOGP(subsys, level, fmt, args...) \
	ss_logp(subsys, level, __FILE__, __LINE__, fmt, ## args)

void ss_logp(uint32_t subsys, uint32_t level, const char *file, int line, const char *format, ...)
	__attribute__ ((format (printf, 5, 6)));


enum log_subsys {
	SBTLV,
	SCTLV,
	SVPCD,
	SIFACE,
	SUICC,
	SCMD,
	SLCHAN,
	SFS,
	SSTORAGE,
	SACCESS,
	SADMIN,
	SSFI,
	SDFNAME,
	SFILE,
	SPIN,
	SAUTH,
	SPROACT,
	STLV8,
	SSMS,
	SREMOTECMD,
	SREFRESH,
	_NUM_LOG_SUBSYS
};

enum log_level {
	LERROR,
	LINFO,
	LDEBUG,
	_NUM_LOG_LEVEL
};
