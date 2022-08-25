/*
 * Copyright (c) 2004-2022 Roumen Petrov.  All rights reserved.
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

#include "log.h"
#include <openssl/err.h>

#define MSGBUFSIZ 4096


static inline unsigned long
ssh_ERR_get_error_all(const char **data, int *flags) {
#ifdef HAVE_ERR_GET_ERROR_ALL   /* OpenSSL >= 3.0 */
	return ERR_get_error_all(NULL, NULL, NULL, data, flags);
#else
	return ERR_get_error_line_data(NULL, NULL, data, flags);
#endif
}


static char*
get_one_crypto_error(char *buf, size_t len) {
	unsigned long err_code;
	const char *err_data;
	int err_flags;

	err_code = ssh_ERR_get_error_all(&err_data, &err_flags);
	if (err_code == 0) return NULL;

	if (!(err_flags & ERR_TXT_STRING))
		err_data = NULL;

{	char ebuf[MSGBUFSIZ];
	ERR_error_string_n(err_code, ebuf, sizeof(ebuf));
	snprintf(buf, len, "%s%s%s", ebuf
	    , err_data ? ":" : ""
	    , err_data ? err_data : ""
	);
}

	return buf;
}


void
sshlog_cryptoerr_all(const char *file, const char *func, int line,
    LogLevel level
) {
	char ebuf[MSGBUFSIZ];
	const char *emsg;
	for (
	    emsg = get_one_crypto_error(ebuf, sizeof(ebuf));
	    emsg != NULL;
	    emsg = get_one_crypto_error(ebuf, sizeof(ebuf))
	)
		sshlog(file, func, line, level,
		    "%s: crypto message: '%s'", func, emsg);
}


static char*
crypto_errormsg(char *buf, size_t len) {
	unsigned long err_code;
	const char *err_data;
	int err_flags;

	if (buf == NULL) goto out;

	err_code = ssh_ERR_get_error_all(&err_data, &err_flags);
	if (err_code == 0) {
		if (len > 0) *buf = '\0';
		goto out;
	}
	if (!(err_flags & ERR_TXT_STRING))
		err_data = NULL;

{	char ebuf[MSGBUFSIZ];
	ERR_error_string_n(err_code, ebuf, sizeof(ebuf));
	snprintf(buf, len, "%s%s%s", ebuf
	    , err_data ? ":" : ""
	    , err_data ? err_data : ""
	);
}

out:
	/* clear rest of errors in OpenSSL "error buffer" */
	ERR_clear_error();
	return buf;
}


void
sshlog_cryptoerr_fmt(const char *file, const char *func, int line,
    LogLevel level, const char *openssl_method, const char *fmt, ...)
{
	char *sep, mbuf[MSGBUFSIZ], ebuf[MSGBUFSIZ];
	va_list args;

	va_start(args, fmt);
	vsnprintf(mbuf, sizeof(mbuf), fmt, args);
	va_end(args);

	sep = mbuf[0] != '\0' ? "/" : "",

	crypto_errormsg(ebuf, sizeof(ebuf));

	sshlog(file, func, line, level,
	    "%s->%s%s%s%s last error: '%s'", func, openssl_method,
	    sep, mbuf, sep, ebuf);
}


void
sshlog_cryptoerr(const char *file, const char *func, int line,
    LogLevel level, const char *openssl_method)
{
	char ebuf[MSGBUFSIZ];

	crypto_errormsg(ebuf, sizeof(ebuf));

	sshlog(file, func, line, level,
	    "%s->%s last error: '%s'", func, openssl_method, ebuf);
}
