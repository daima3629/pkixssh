/* $OpenBSD: log.c,v 1.61 2023/12/06 21:06:48 djm Exp $ */
/*
 * Author: Tatu Ylonen <ylo@cs.hut.fi>
 * Copyright (c) 1995 Tatu Ylonen <ylo@cs.hut.fi>, Espoo, Finland
 *                    All rights reserved
 *
 * As far as I am concerned, the code I have written for this software
 * can be used freely for any purpose.  Any derived versions of this
 * software must be clearly marked as such, and if the derived work is
 * incompatible with the protocol description in the RFC file, it must be
 * called by a name other than "ssh" or "Secure Shell".
 */
/*
 * Copyright (c) 2000 Markus Friedl.  All rights reserved.
 * Copyright (c) 2004-2023 Roumen Petrov.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "includes.h"

#include <sys/types.h>

#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#if defined(HAVE_STRNVIS) && defined(HAVE_VIS_H) && !defined(BROKEN_STRNVIS)
# include <vis.h>
#endif

#include "log.h"
#include "match.h"
#include "ssherr.h"

#define MSGBUFSIZ 1024

static LogLevel log_level = SYSLOG_LEVEL_INFO;
static int log_on_stderr = 1;
static int log_stderr_fd = STDERR_FILENO;
static int log_facility = LOG_AUTH;
static const char *argv0;
static log_handler_fn *log_handler;
static void *log_handler_ctx;
static char **log_verbose = NULL;
static size_t nlog_verbose = 0;

extern char *__progname;

#define LOG_SYSLOG_VIS	(VIS_CSTYLE|VIS_NL|VIS_TAB|VIS_OCTAL)
#define LOG_STDERR_VIS	(VIS_SAFE|VIS_OCTAL)

#ifdef __ANDROID__
#include <android/log.h>

static void
android_log(LogLevel level, const char *msg, void *ctx) {
	android_LogPriority a;

	UNUSED(ctx);

	switch (level) {
	case SYSLOG_LEVEL_QUIET		: a = ANDROID_LOG_SILENT	; break;
	case SYSLOG_LEVEL_FATAL		: a = ANDROID_LOG_FATAL		; break;
	case SYSLOG_LEVEL_ERROR		: a = ANDROID_LOG_ERROR		; break;
	case SYSLOG_LEVEL_INFO		: a = ANDROID_LOG_WARN		; break;
	case SYSLOG_LEVEL_VERBOSE	: a = ANDROID_LOG_INFO		; break;
	case SYSLOG_LEVEL_DEBUG1	: a = ANDROID_LOG_DEBUG		; break;
	case SYSLOG_LEVEL_DEBUG2	: a = ANDROID_LOG_DEBUG		; break;
	case SYSLOG_LEVEL_DEBUG3	: a = ANDROID_LOG_VERBOSE	; break;
	default				: a = ANDROID_LOG_UNKNOWN	; break;
	}

	if (a != ANDROID_LOG_UNKNOWN)
		__android_log_write(a, __progname, msg);
}
#endif /*def __ANDROID__*/

/* textual representation of log-facilities/levels */

static struct {
	const char *name;
	SyslogFacility val;
} log_facilities[] = {
	{ "DAEMON",	SYSLOG_FACILITY_DAEMON },
	{ "USER",	SYSLOG_FACILITY_USER },
	{ "AUTH",	SYSLOG_FACILITY_AUTH },
#ifdef LOG_AUTHPRIV
	{ "AUTHPRIV",	SYSLOG_FACILITY_AUTHPRIV },
#endif
	{ "LOCAL0",	SYSLOG_FACILITY_LOCAL0 },
	{ "LOCAL1",	SYSLOG_FACILITY_LOCAL1 },
	{ "LOCAL2",	SYSLOG_FACILITY_LOCAL2 },
	{ "LOCAL3",	SYSLOG_FACILITY_LOCAL3 },
	{ "LOCAL4",	SYSLOG_FACILITY_LOCAL4 },
	{ "LOCAL5",	SYSLOG_FACILITY_LOCAL5 },
	{ "LOCAL6",	SYSLOG_FACILITY_LOCAL6 },
	{ "LOCAL7",	SYSLOG_FACILITY_LOCAL7 },
	{ NULL,		SYSLOG_FACILITY_NOT_SET }
};

static struct {
	const char *name;
	LogLevel val;
} log_levels[] =
{
	{ "QUIET",	SYSLOG_LEVEL_QUIET },
	{ "FATAL",	SYSLOG_LEVEL_FATAL },
	{ "ERROR",	SYSLOG_LEVEL_ERROR },
	{ "INFO",	SYSLOG_LEVEL_INFO },
	{ "VERBOSE",	SYSLOG_LEVEL_VERBOSE },
	{ "DEBUG",	SYSLOG_LEVEL_DEBUG1 },
	{ "DEBUG1",	SYSLOG_LEVEL_DEBUG1 },
	{ "DEBUG2",	SYSLOG_LEVEL_DEBUG2 },
	{ "DEBUG3",	SYSLOG_LEVEL_DEBUG3 },
	{ NULL,		SYSLOG_LEVEL_NOT_SET }
};

SyslogFacility
log_facility_number(char *name)
{
	int i;

	if (name != NULL)
		for (i = 0; log_facilities[i].name; i++)
			if (strcasecmp(log_facilities[i].name, name) == 0)
				return log_facilities[i].val;
	return SYSLOG_FACILITY_NOT_SET;
}

const char *
log_facility_name(SyslogFacility facility)
{
	u_int i;

	for (i = 0;  log_facilities[i].name; i++)
		if (log_facilities[i].val == facility)
			return log_facilities[i].name;
	return NULL;
}

LogLevel
log_level_number(char *name)
{
	int i;

	if (name != NULL)
		for (i = 0; log_levels[i].name; i++)
			if (strcasecmp(log_levels[i].name, name) == 0)
				return log_levels[i].val;
	return SYSLOG_LEVEL_NOT_SET;
}

const char *
log_level_name(LogLevel level)
{
	u_int i;

	for (i = 0; log_levels[i].name != NULL; i++)
		if (log_levels[i].val == level)
			return log_levels[i].name;
	return NULL;
}

void
log_verbose_init(char **opts, size_t n) {
	size_t k;

	for (k = 0; k < nlog_verbose; k++)
		free(log_verbose[k]);
	free(log_verbose);

	nlog_verbose = 0;
	if (n == 0) {
		log_verbose = NULL;
		return;
	}
	log_verbose = calloc(n, sizeof(*log_verbose));

	for (k = 0; k < n; k++) {
		/* non-fatal if strdup fail*/
		log_verbose[nlog_verbose] = strdup(opts[k]);
		if (log_verbose[nlog_verbose] != NULL)
			nlog_verbose++;
	}
}

/*
 * Initialize the log.
 */

void
log_init(const char *av0, LogLevel level, SyslogFacility facility,
    int on_stderr)
{
	argv0 = av0;

	if (log_change_level(level) != 0) {
		fprintf(stderr, "Unrecognized internal syslog level code %d\n",
		    (int) level);
		exit(1);
	}

	log_handler = NULL;
	log_handler_ctx = NULL;

	log_on_stderr = on_stderr;
	if (on_stderr)
		return;

#ifdef __ANDROID__
	log_handler = android_log;
#endif
	switch (facility) {
	case SYSLOG_FACILITY_DAEMON:
		log_facility = LOG_DAEMON;
		break;
	case SYSLOG_FACILITY_USER:
		log_facility = LOG_USER;
		break;
	case SYSLOG_FACILITY_AUTH:
		log_facility = LOG_AUTH;
		break;
#ifdef LOG_AUTHPRIV
	case SYSLOG_FACILITY_AUTHPRIV:
		log_facility = LOG_AUTHPRIV;
		break;
#endif
	case SYSLOG_FACILITY_LOCAL0:
		log_facility = LOG_LOCAL0;
		break;
	case SYSLOG_FACILITY_LOCAL1:
		log_facility = LOG_LOCAL1;
		break;
	case SYSLOG_FACILITY_LOCAL2:
		log_facility = LOG_LOCAL2;
		break;
	case SYSLOG_FACILITY_LOCAL3:
		log_facility = LOG_LOCAL3;
		break;
	case SYSLOG_FACILITY_LOCAL4:
		log_facility = LOG_LOCAL4;
		break;
	case SYSLOG_FACILITY_LOCAL5:
		log_facility = LOG_LOCAL5;
		break;
	case SYSLOG_FACILITY_LOCAL6:
		log_facility = LOG_LOCAL6;
		break;
	case SYSLOG_FACILITY_LOCAL7:
		log_facility = LOG_LOCAL7;
		break;
	default:
		fprintf(stderr,
		    "Unrecognized internal syslog facility code %d\n",
		    (int) facility);
		exit(1);
	}

	/*
	 * If an external library (eg libwrap) attempts to use syslog
	 * immediately after reexec, syslog may be pointing to the wrong
	 * facility, so we force an open/close of syslog here.
	 */
{	const char *progname = (argv0 != NULL) ? argv0 : __progname;
#if defined(HAVE_OPENLOG_R) && defined(SYSLOG_DATA_INIT)
	struct syslog_data sdata = SYSLOG_DATA_INIT;

	openlog_r(progname, LOG_PID, log_facility, &sdata);
	closelog_r(&sdata);
#else
	openlog(progname, LOG_PID, log_facility);
	closelog();
#endif
}
}

int
log_change_level(LogLevel new_log_level)
{
	/* no-op if log_init has not been called */
	if (argv0 == NULL)
		return 0;

	switch (new_log_level) {
	case SYSLOG_LEVEL_QUIET:
	case SYSLOG_LEVEL_FATAL:
	case SYSLOG_LEVEL_ERROR:
	case SYSLOG_LEVEL_INFO:
	case SYSLOG_LEVEL_VERBOSE:
	case SYSLOG_LEVEL_DEBUG1:
	case SYSLOG_LEVEL_DEBUG2:
	case SYSLOG_LEVEL_DEBUG3:
		log_level = new_log_level;
		return 0;
	default:
		return -1;
	}
}

int
log_is_on_stderr(void)
{
	return log_on_stderr && log_stderr_fd == STDERR_FILENO;
}

/* redirect what would usually get written to stderr to specified file */
void
log_redirect_stderr_to(const char *logfile)
{
	int fd;

	if (logfile == NULL) {
		if (log_stderr_fd != STDERR_FILENO) {
			close(log_stderr_fd);
			log_stderr_fd = STDERR_FILENO;
		}
		return;
	}

	if ((fd = open(logfile, O_WRONLY|O_CREAT|O_APPEND, 0600)) == -1) {
		fprintf(stderr, "Couldn't open logfile %s: %s\n", logfile,
		    strerror(errno));
		exit(1);
	}
	log_stderr_fd = fd;
}

LogLevel
get_log_level(void) {
	return log_level;
}


void
set_log_handler(log_handler_fn *handler, void *ctx)
{
	log_handler = handler;
	log_handler_ctx = ctx;
}

static int/*boolean*/
forced_logging(const char *file, const char *func, int line)
{
	char tag[128];
	size_t k;

	if (nlog_verbose == 0) return 0;

	if (line <= 0) return 0 /* not applicable */;

{	const char *s = strrchr(file, '/');
	if (s != NULL ) file = s + 1;
	snprintf(tag, sizeof(tag), "%.48s:%.48s():%d", file, func, line);
}
	for (k = 0; k < nlog_verbose; k++) {
		if (match_pattern_list(tag, log_verbose[k], 0) == 1)
			return 1;
	}
	return 0;
}

void
sshlogv(const char *file, const char *func, int line,
    LogLevel level, const char *fmt, va_list args)
{
	char msgbuf[MSGBUFSIZ];
	char fmtbuf[MSGBUFSIZ];
	char *txt = NULL;
	int pri = LOG_INFO;
	int saved_errno = errno;
	const char *progname = (argv0 != NULL) ? argv0 : __progname;

	if (level > log_level) {
		if (!forced_logging(file, func, line))
			return;
	}

	switch (level) {
	case SYSLOG_LEVEL_FATAL:
		if (!log_on_stderr)
			txt = "fatal";
		pri = LOG_CRIT;
		break;
	case SYSLOG_LEVEL_ERROR:
		if (!log_on_stderr)
			txt = "error";
		pri = LOG_ERR;
		break;
	case SYSLOG_LEVEL_INFO:
		pri = LOG_INFO;
		break;
	case SYSLOG_LEVEL_VERBOSE:
		pri = LOG_INFO;
		break;
	case SYSLOG_LEVEL_DEBUG1:
		txt = "debug1";
		pri = LOG_DEBUG;
		break;
	case SYSLOG_LEVEL_DEBUG2:
		txt = "debug2";
		pri = LOG_DEBUG;
		break;
	case SYSLOG_LEVEL_DEBUG3:
		txt = "debug3";
		pri = LOG_DEBUG;
		break;
	default:
		txt = "internal error";
		pri = LOG_ERR;
		break;
	}
	if (txt != NULL && log_handler == NULL) {
		snprintf(fmtbuf, sizeof(fmtbuf), "%s: %s", txt, fmt);
		vsnprintf(msgbuf, sizeof(msgbuf), fmtbuf, args);
	} else {
		vsnprintf(msgbuf, sizeof(msgbuf), fmt, args);
	}
#if 0 /*TODO: vis result is completely broken on UTF-8 */
	strnvis(fmtbuf, msgbuf, sizeof(fmtbuf),
	    log_on_stderr ? LOG_STDERR_VIS : LOG_SYSLOG_VIS);
#else
	snprintf(fmtbuf, sizeof(fmtbuf), "%s", msgbuf);
#endif
	if (log_handler != NULL) {
		/* Avoid recursion */
		log_handler_fn *tmp_handler = log_handler;
		log_handler = NULL;
		tmp_handler(level, fmtbuf, log_handler_ctx);
		log_handler = tmp_handler;
	} else if (log_on_stderr) {
		snprintf(msgbuf, sizeof msgbuf, "%s%s%.*s",
		    (log_on_stderr > 1) ? progname : "",
		    (log_on_stderr > 1) ? ": " : "",
		    (int)sizeof msgbuf - 3, fmtbuf);
		(void)write(log_stderr_fd, msgbuf, strlen(msgbuf));
		(void)write(log_stderr_fd, "\r\n", 2);
	} else {
#if defined(HAVE_OPENLOG_R) && defined(SYSLOG_DATA_INIT)
		struct syslog_data sdata = SYSLOG_DATA_INIT;

		openlog_r(progname, LOG_PID, log_facility, &sdata);
		syslog_r(pri, &sdata, "%.1000s", fmtbuf);
		closelog_r(&sdata);
#else
		openlog(progname, LOG_PID, log_facility);
		syslog(pri, "%.1000s", fmtbuf);
		closelog();
#endif
	}
	errno = saved_errno;
}

void
sshlog(const char *file, const char *func, int line,
    LogLevel level, const char *fmt, ...)
{
	va_list args;

	va_start(args, fmt);
	sshlogv(file, func, line, level, fmt, args);
	va_end(args);
}

void
sshlogdie(const char *file, const char *func, int line,
    const char *fmt,...)
{
	va_list args;

	va_start(args, fmt);
	sshlogv(file, func, line, SYSLOG_LEVEL_INFO, fmt, args);
	va_end(args);
	cleanup_exit(255);
}

void
sshsigdie(const char *file, const char *func, int line,
    const char *fmt,...)
{
#if 0
/* NOTE 2024-07-01: Logging in alarm handler is still considered insecure on glibc.
 * Ref.: CVE-2024-6387, CVE-2008-4109, CVE-2006-5051
 * https://blog.qualys.com/vulnerabilities-threat-research/2024/07/01/regresshion-remote-unauthenticated-code-execution-vulnerability-in-openssh-server
 */
/* NOTE: "OpenSSH bug 3286". See grace_alarm_handler() in sshd.c.
 * Logging in signal handler cannot be considered as safe.
 * Let enable log as now daemon does not sent explicitly alarm
 * signal. This should avoid logging in child signal handler.
 */
# define DO_LOG_SAFE_IN_SIGHAND
#endif
#ifdef DO_LOG_SAFE_IN_SIGHAND
	va_list args;

	va_start(args, fmt);
	sshlogv(file, func, line, SYSLOG_LEVEL_FATAL, fmt, args);
	va_end(args);
#else
	UNUSED(file); UNUSED(func); UNUSED(line);
	UNUSED(fmt);
#endif
	_exit(1);
}

void
sshlogv_f(const char *file, const char *func, int line,
    LogLevel level, const char *fmt, va_list args)
{
	char msgbuf[MSGBUFSIZ];

	if (level > log_level) {
		if (nlog_verbose == 0)
			return;
		/*
		else
			pass to forced logging checks
		*/
	}

	vsnprintf(msgbuf, sizeof(msgbuf), fmt, args);
	sshlog(file, func, line, level, "%s: %s", func, msgbuf);
}

void
sshlog_f(const char *file, const char *func, int line,
    LogLevel level, const char *fmt, ...)
{
	va_list args;

	va_start(args, fmt);
	sshlogv_f(file, func, line, level, fmt, args);
	va_end(args);
}

void
sshlogv_r(const char *file, const char *func, int line,
    int errcode, LogLevel level, const char *fmt, va_list args)
{
	char msgbuf[MSGBUFSIZ];

	vsnprintf(msgbuf, sizeof(msgbuf), fmt, args);
	sshlog(file, func, line, level, "%s - %s", msgbuf, ssh_err(errcode));
}

void
sshlog_r(const char *file, const char *func, int line,
    int errcode, LogLevel level, const char *fmt, ...)
{
	va_list args;

	va_start(args, fmt);
	sshlogv_r(file, func, line, errcode, level, fmt, args);
	va_end(args);
}

void
sshlogv_fr(const char *file, const char *func, int line,
    int errcode, LogLevel level, const char *fmt, va_list args)
{
	char msgbuf[MSGBUFSIZ];

	vsnprintf(msgbuf, sizeof(msgbuf), fmt, args);
	sshlog(file, func, line, level, "%s: %s - %s", func, msgbuf, ssh_err(errcode));
}

void
sshlog_fr(const char *file, const char *func, int line,
    int errcode, LogLevel level, const char *fmt, ...)
{
	va_list args;

	va_start(args, fmt);
	sshlogv_fr(file, func, line, errcode, level, fmt, args);
	va_end(args);
}
