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
/* Crypto library error management */
extern void ERR_load_SSHLDAP_strings(void);
extern void ERR_load_X509byLDAP_strings(void);

#ifndef OPENSSL_NO_ERR

/* Function codes. */
#define SSHLDAP_F_LDAPHOST_NEW				101

/* Reason codes. */
#define SSHLDAP_R_NOT_LDAP_URL				101
#define SSHLDAP_R_INVALID_URL				102
#define SSHLDAP_R_INITIALIZATION_ERROR			103
#define SSHLDAP_R_UNABLE_TO_GET_PROTOCOL_VERSION	104


static ERR_STRING_DATA SSHLDAP_str_functs[] = {
	{ ERR_PACK(0, SSHLDAP_F_LDAPHOST_NEW, 0)	, "LDAPHOST_NEW" },
	{ 0, NULL }
};

static ERR_STRING_DATA SSHLDAP_str_reasons[] = {
	{ ERR_PACK(0, 0, SSHLDAP_R_NOT_LDAP_URL)			, "not ldap url" },
	{ ERR_PACK(0, 0, SSHLDAP_R_INVALID_URL)				, "invalid ldap url" },
	{ ERR_PACK(0, 0, SSHLDAP_R_INITIALIZATION_ERROR)		, "ldap initialization error" },
	{ ERR_PACK(0, 0, SSHLDAP_R_UNABLE_TO_GET_PROTOCOL_VERSION)	, "unable to get ldap protocol version" },
	{ 0, NULL }
};

static ERR_STRING_DATA SSHLDAP_lib_name[] = {
	{ 0, "SSHLDAP" },
	{ 0, NULL }
};


static int ERR_LIB_SSHLDAP = 0;
static inline void
SSHLDAP_PUT_error(int function, int reason, const char *file, int line) {
	if (ERR_LIB_SSHLDAP == 0)
		ERR_LIB_SSHLDAP = ERR_get_next_error_library();

	ERR_PUT_error(ERR_LIB_SSHLDAP, function, reason, file, line);
}

#define SSHLDAPerr(f,r) SSHLDAP_PUT_error((f),(r),__FILE__,__LINE__)

#else

#define SSHLDAPerr(f,r)

#endif /*ndef OPENSSL_NO_ERR*/


void
ERR_load_SSHLDAP_strings(void) {
#ifndef OPENSSL_NO_ERR
{	static int loaded = 0;
	if (loaded) return;
	loaded = 1;
}
	ERR_LIB_SSHLDAP = ERR_get_next_error_library();

	ERR_load_strings(ERR_LIB_SSHLDAP, SSHLDAP_str_functs);
	ERR_load_strings(ERR_LIB_SSHLDAP, SSHLDAP_str_reasons);

	SSHLDAP_lib_name[0].error = ERR_PACK(ERR_LIB_SSHLDAP, 0, 0);
	ERR_load_strings(0, SSHLDAP_lib_name);
#endif
	ERR_load_X509byLDAP_strings();
}


/* ================================================================== */
/* LDAP connection details */

ldaphost*
ldaphost_new(const char *url) {
	ldaphost *p;
	int ret;

TRACE_BY_LDAP(__func__, "url: '%s')", url);
	p = OPENSSL_malloc(sizeof(ldaphost));
	if (p == NULL) return NULL;

	memset(p, 0, sizeof(ldaphost));

	p->url = OPENSSL_malloc(strlen(url) + 1);
	if (p->url == NULL) goto error;
	strcpy(p->url, url);

	/*ldap://hostport/dn[?attrs[?scope[?filter[?exts]]]] */
	ret = ldap_is_ldap_url(url);
	if (ret < 0) {
		SSHLDAPerr(SSHLDAP_F_LDAPHOST_NEW, SSHLDAP_R_NOT_LDAP_URL);
		goto error;
	}

	ret = ldap_url_parse(p->url, &p->ldapurl);
	if (ret != 0) {
		SSHLDAPerr(SSHLDAP_F_LDAPHOST_NEW, SSHLDAP_R_INVALID_URL);
		crypto_add_ldap_error(ret);
		goto error;
	}
#ifdef TRACE_BY_LDAP_ENABLED
{
char *uri = ldap_url_desc2str(p->ldapurl);
TRACE_BY_LDAP(__func__, "ldap_url_desc2str: '%s'", uri);
ldap_memfree(uri);
}
#endif /*def TRACE_BY_LDAP_ENABLED*/
TRACE_BY_LDAP(__func__, "ldapurl: '%s://%s:%d'", p->ldapurl->lud_scheme, p->ldapurl->lud_host, p->ldapurl->lud_port);

	/* allocate connection without to open */
#ifdef HAVE_LDAP_INITIALIZE
	ret = ldap_initialize(&p->ld, p->url);
	if (ret != LDAP_SUCCESS) {
		SSHLDAPerr(SSHLDAP_F_LDAPHOST_NEW, SSHLDAP_R_INITIALIZATION_ERROR);
		crypto_add_ldap_error(ret);
		goto error;
	}
#else /*ndef HAVE_LDAP_INITIALIZE*/
	p->ld = ldap_init(p->ldapurl->lud_host, p->ldapurl->lud_port);
	if(p->ld == NULL) {
		SSHLDAPerr(SSHLDAP_F_LDAPHOST_NEW, SSHLDAP_R_INITIALIZATION_ERROR);
		goto error;
	}
#endif /*ndef HAVE_LDAP_INITIALIZE*/

{	int version = -1;

	ret = ldap_get_option(p->ld, LDAP_OPT_PROTOCOL_VERSION, &version);
	if (ret != LDAP_OPT_SUCCESS) {
		SSHLDAPerr(SSHLDAP_F_LDAPHOST_NEW, SSHLDAP_R_UNABLE_TO_GET_PROTOCOL_VERSION );
		goto error;
	}
TRACE_BY_LDAP(__func__, "using protocol v%d (default)", version);
}

	return p;
error:
	ldaphost_free(p);
	return NULL;
}


void
ldaphost_free(ldaphost *p) {
TRACE_BY_LDAP(__func__, "...");
	if (p == NULL) return;
	if (p->url    != NULL) OPENSSL_free(p->url);
	if (p->binddn != NULL) OPENSSL_free(p->binddn);
	if (p->bindpw != NULL) OPENSSL_free(p->bindpw);
	if (p->ldapurl != NULL) {
		ldap_free_urldesc(p->ldapurl);
		p->ldapurl = NULL;
	}
	if (p->ld != NULL) {
		(void)ssh_ldap_unbind_s(p->ld);
		p->ld = NULL;
	}
	OPENSSL_free(p);
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
