/*
 * Copyright (c) 2004-2019 Roumen Petrov.  All rights reserved.
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

#include "ssh_ldap.h"

#include <openssl/err.h>


#ifdef TRACE_BY_LDAP_ENABLED
void
TRACE_BY_LDAP(const char *f, const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    fputs("TRACE_BY_LDAP ", stderr);
    fputs(f, stderr);
    fputs(":  ", stderr);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    fputs("\n", stderr);
}
#endif /*def TRACE_BY_LDAP_ENABLED*/


/* ================================================================== */
/* wrappers for some LDAP-functions */

int
ssh_ldap_bind_s(LDAP *ld) {
	int result;

	/* anonymous bind - data must be retrieved by anybody */
#ifdef HAVE_LDAP_SASL_BIND_S
{
	static struct berval	cred = { 0, (char*)"" };

	result = ldap_sasl_bind_s(
		ld, NULL/*dn*/, LDAP_SASL_SIMPLE, &cred,
		NULL, NULL, NULL);
}
#else
	result = ldap_simple_bind_s(ld, NULL/*binddn*/, NULL/*bindpw*/);
#endif

TRACE_BY_LDAP(__func__, "ldap_XXX_bind_s return 0x%x(%s)"
, result, ldap_err2string(result));
	return result;
}


int
ssh_ldap_unbind_s(LDAP *ld) {
	int result;
#ifdef HAVE_LDAP_UNBIND_EXT_S
	result = ldap_unbind_ext_s(ld, NULL, NULL);
#else
	result = ldap_unbind_s(ld);
#endif

TRACE_BY_LDAP(__func__, "ldap_XXX_unbind_s return 0x%x(%s)"
, result, ldap_err2string(result));
	return result;
}


int
ssh_ldap_search_s(
	LDAP *ld,
	LDAP_CONST char *base,
	int scope,
	LDAP_CONST char *filter,
	char **attrs,
	int attrsonly,
	LDAPMessage **res
) {
	int result;
#ifdef HAVE_LDAP_SEARCH_EXT_S
	result = ldap_search_ext_s(ld, base,
		scope, filter, attrs, attrsonly,
		NULL, NULL, NULL, 0, res);
#else
	result = ldap_search_s(ld, base, scope, filter, attrs, attrsonly, res);
#endif

TRACE_BY_LDAP(__func__, "..."
"\n  base: '%s'\n  filter: '%s'\n  ldap_search_{XXX}s return 0x%x(%s)"
, base, filter, result, ldap_err2string(result));
	return result;
}


void
ssh_ldap_parse_result (
	LDAP *ld,
	LDAPMessage *res
) {
	static const int freeit = 0;
	int result;
#ifdef HAVE_LDAP_PARSE_RESULT
	int ret;
	char *matcheddn;
	char *errmsg;

	ret = ldap_parse_result(ld, res, &result, &matcheddn, &errmsg, NULL, NULL, freeit);
	if (ret == LDAP_SUCCESS) {
		if (errmsg) ERR_add_error_data(1, errmsg);
	}
	if (matcheddn) ldap_memfree(matcheddn);
	if (errmsg)    ldap_memfree(errmsg);
#else
	result = ldap_result2error(ld, res, freeit);
	crypto_add_ldap_error(result);
#endif
}


/* ================================================================== */
static char*
ldap_errormsg(char *buf, size_t len, int err) {
	snprintf(buf, len, "ldaperror=0x%x(%.256s)", err, ldap_err2string(err));
	return buf;
}


void
crypto_add_ldap_error(int err) {
	char	buf[512];
	ERR_add_error_data(1, ldap_errormsg(buf, sizeof(buf), err));
}
