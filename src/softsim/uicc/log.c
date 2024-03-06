/*
 * Copyright (c) 2024 Onomondo ApS. All rights reserved.
 * 
 * SPDX-License-Identifier: GPL-3.0-only 
 */

#include <stdarg.h>
#include <stdio.h>
#include <onomondo/softsim/log.h>
#include <onomondo/softsim/utils.h>

uint32_t ss_log_mask = 0xffffffff;
// clang-format off
/* TODO #64: add a mechanism to modify the log levels at runtime via getopt */
static uint32_t subsys_lvl[_NUM_LOG_SUBSYS] = {
	[SBTLV] = LDEBUG,
	[SCTLV] = LDEBUG,
	[SVPCD] = LINFO,
	[SIFACE] = LDEBUG,
	[SUICC] = LDEBUG,
	[SCMD] = LDEBUG,
	[SLCHAN] = LDEBUG,
	[SFS] = LDEBUG,
	[SSTORAGE] = LDEBUG,
	[SACCESS] = LDEBUG,
	[SADMIN] = LDEBUG,
	[SSFI] = LDEBUG,
	[SDFNAME] = LDEBUG,
	[SFILE] = LDEBUG,
	[SPIN] = LDEBUG,
	[SAUTH] = LDEBUG,
	[SPROACT] = LDEBUG,
	[STLV8] = LDEBUG,
	[SSMS] = LDEBUG,
	[SREMOTECMD] = LDEBUG,
	[SREFRESH] = LDEBUG,
};

static const char *subsys_str[_NUM_LOG_SUBSYS] = {
	[SBTLV]		= "BTLV",
	[SCTLV]		= "CTLV",
	[SVPCD]		= "VPCD",
	[SIFACE]	= "IFACE",
	[SUICC]		= "UICC",
	[SCMD]		= "CMD",
	[SLCHAN]	= "LCHAN",
	[SFS]		= "FS",
	[SSTORAGE]	= "STORAGE",
	[SACCESS]	= "ACCESS",
	[SADMIN]	= "ADMIN",
	[SSFI]		= "SFI",
	[SDFNAME]	= "DFNAME",
	[SFILE]		= "FILE",
	[SPIN]		= "PIN",
	[SAUTH]		= "AUTH",
	[SPROACT]	= "PROACT",
	[SREMOTECMD]	= "REMOTECMD",
	[STLV8]		= "TLV8",
	[SSMS]		= "SMS",
	[SREFRESH]	= "REFRESH",
};
// clang-format on
static const char *level_str[_NUM_LOG_LEVEL] = {
	[LERROR] = "ERROR",
	[LINFO] = "INFO",
	[LDEBUG] = "DEBUG",
};

/*! print a log line (called by IPA_LOGP, do not call directly).
 *  \param[in] subsys log subsystem identifier.
 *  \param[in] level log level identifier.
 *  \param[in] file source file name.
 *  \param[in] line source file line.
 *  \param[in] format formtstring (followed by arguments). */
void ss_logp(uint32_t subsys, uint32_t level, const char *file, int line, const char *format, ...)
{
	va_list ap;

	if (!(ss_log_mask & (1 << subsys)))
		return;

	assert(subsys < SS_ARRAY_SIZE(subsys_lvl));

	if (level > subsys_lvl[subsys])
		return;

	/* TODO #67: print file and line, but make it an optional feature that
	 * can be selected via commandline option. The reason for this is that
	 * the unit-tests may compare the log output against .err files and
	 * even on minor changes we would constantly upset the unit-tests. */

	fprintf(stderr, "%8s %8s ", subsys_str[subsys], level_str[level]);
	va_start(ap, format);
	vfprintf(stderr, format, ap);
	va_end(ap);
}
