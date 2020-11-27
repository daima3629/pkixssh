/* $OpenBSD: log.h,v 1.29 2020/10/18 11:21:59 djm Exp $ */

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
 * Copyright (c) 2020 Roumen Petrov.  All rights reserved.
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

#ifndef SSH_LOG_H
#define SSH_LOG_H

/*  syslog.h include is required to get define for LOG_AUTHPRIV */
#include <syslog.h>
#include <stdarg.h> /* va_list */

/* Supported syslog facilities and levels. */
typedef enum {
	SYSLOG_FACILITY_DAEMON,
	SYSLOG_FACILITY_USER,
	SYSLOG_FACILITY_AUTH,
#ifdef LOG_AUTHPRIV
	SYSLOG_FACILITY_AUTHPRIV,
#endif
	SYSLOG_FACILITY_LOCAL0,
	SYSLOG_FACILITY_LOCAL1,
	SYSLOG_FACILITY_LOCAL2,
	SYSLOG_FACILITY_LOCAL3,
	SYSLOG_FACILITY_LOCAL4,
	SYSLOG_FACILITY_LOCAL5,
	SYSLOG_FACILITY_LOCAL6,
	SYSLOG_FACILITY_LOCAL7,
	SYSLOG_FACILITY_NOT_SET = -1
}       SyslogFacility;

typedef enum {
	SYSLOG_LEVEL_QUIET,
	SYSLOG_LEVEL_FATAL,
	SYSLOG_LEVEL_ERROR,
	SYSLOG_LEVEL_INFO,
	SYSLOG_LEVEL_VERBOSE,
	SYSLOG_LEVEL_DEBUG1,
	SYSLOG_LEVEL_DEBUG2,
	SYSLOG_LEVEL_DEBUG3,
	SYSLOG_LEVEL_NOT_SET = -1
}       LogLevel;

typedef void (log_handler_fn)(const char *file, const char *func, int line,
    LogLevel level, const char *msg, void *ctx);

void     log_init(char *, LogLevel, SyslogFacility, int);
int      log_change_level(LogLevel);
int      log_is_on_stderr(void);
void     log_redirect_stderr_to(const char *);
LogLevel get_log_level(void);

SyslogFacility	log_facility_number(char *);
const char *	log_facility_name(SyslogFacility);
LogLevel	log_level_number(char *);
const char *	log_level_name(LogLevel);

void	 set_log_handler(log_handler_fn *, void *);
void	 cleanup_exit(int) __attribute__((noreturn));

void	 sshlog(const char *file, const char *func, int line,
    LogLevel level, const char *fmt, ...)
    __attribute__((format(printf, 5, 6)));
void	 sshlogv(const char *file, const char *func, int line,
    LogLevel level, const char *fmt, va_list args);

#define do_log2(level, ...)	sshlog(__FILE__, __func__, __LINE__, level, __VA_ARGS__)

/* Error messages that should be logged. */
#define error(...)	sshlog(__FILE__, __func__, __LINE__, SYSLOG_LEVEL_ERROR, __VA_ARGS__)
/* Log this message (information that usually should go to the log). */
#define logit(...)	sshlog(__FILE__, __func__, __LINE__, SYSLOG_LEVEL_INFO, __VA_ARGS__)
/* More detailed messages (information that does not need to go to the log). */
#define verbose(...)	sshlog(__FILE__, __func__, __LINE__, SYSLOG_LEVEL_VERBOSE, __VA_ARGS__)
/* Debugging messages that should not be logged during normal operation. */
#define debug(...)	sshlog(__FILE__, __func__, __LINE__, SYSLOG_LEVEL_DEBUG1, __VA_ARGS__)
#define debug2(...)	sshlog(__FILE__, __func__, __LINE__, SYSLOG_LEVEL_DEBUG2, __VA_ARGS__)
#define debug3(...)	sshlog(__FILE__, __func__, __LINE__, SYSLOG_LEVEL_DEBUG3, __VA_ARGS__)

void     sshfatal(const char *file, const char *func, int line,
    const char *fmt, ...) __attribute__((noreturn))
    __attribute__((format(printf, 4, 5)));
void     sshsigdie(const char *file, const char *func, int line,
    const char *fmt, ...) __attribute__((noreturn))
    __attribute__((format(printf, 4, 5)));
void     sshlogdie(const char *file, const char *func, int line,
    const char *fmt, ...) __attribute__((noreturn))
    __attribute__((format(printf, 4, 5)));

#define fatal(...)	sshfatal(__FILE__, __func__, __LINE__, __VA_ARGS__)
#define logdie(...)	sshlogdie(__FILE__, __func__, __LINE__, __VA_ARGS__)
#define sigdie(...)	sshsigdie(__FILE__, __func__, __LINE__, __VA_ARGS__)


/* Error messages from cryptographic library that should be logged. */
void sshlog_cryptoerr(const char *file, const char *func, int line,
    LogLevel level, const char *openssl_method, const char *fmt, ...)
    __attribute__((format(printf, 6, 7)));
void  sshlog_cryptoerr_all(const char *file, const char *func, int line,
    LogLevel level);

#define error_crypto(openssl_method, ...)	\
    sshlog_cryptoerr(__FILE__, __func__, __LINE__, SYSLOG_LEVEL_ERROR, openssl_method, __VA_ARGS__)
#define debug3_crypto(openssl_method, ...)	\
    sshlog_cryptoerr(__FILE__, __func__, __LINE__, SYSLOG_LEVEL_DEBUG3, openssl_method, __VA_ARGS__)
 
#define do_log_crypto_errors(level)	\
    sshlog_cryptoerr_all(__FILE__, __func__, __LINE__, level)
#endif
