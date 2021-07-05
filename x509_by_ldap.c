/*
 * Copyright (c) 2004-2021 Roumen Petrov.  All rights reserved.
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

#include "x509_by_ldap.h"
#include "ssh_ldap.h"

#ifndef USE_OPENSSL_STORE2
/* custom X.509 look-up */

#include "x509store.h"
#include <openssl/err.h>

#include <string.h>


/* ================================================================== */
/* backport OpenSSL 1.1 functions */
#ifndef HAVE_X509_STORE_GET0_OBJECTS
static inline STACK_OF(X509_OBJECT)*
X509_STORE_get0_objects(X509_STORE *store) {
	return store->objs;
}
#endif /*ndef HAVE_X509_STORE_GET0_OBJECTS*/


#ifndef HAVE_X509_STORE_LOCK
static inline int
X509_STORE_lock(X509_STORE *s) {
	UNUSED(s);
#ifdef CRYPTO_LOCK_X509_STORE
	CRYPTO_w_lock(CRYPTO_LOCK_X509_STORE);
#endif
	return 1;
}

static inline int
X509_STORE_unlock(X509_STORE *s) {
	UNUSED(s);
#ifdef CRYPTO_LOCK_X509_STORE
	CRYPTO_w_unlock(CRYPTO_LOCK_X509_STORE);
#endif
	return 1;
}
#endif /*def HAVE_X509_STORE_LOCK*/


/* ================================================================== */
/* ERRORS */

/* Function codes. */
#define X509byLDAP_F_LOOKUPCRTL			100
#define X509byLDAP_F_GET_BY_SUBJECT		104

/* Reason codes. */
#define X509byLDAP_R_INVALID_CRTLCMD			100
#define X509byLDAP_R_WRONG_LOOKUP_TYPE			107
#define X509byLDAP_R_UNABLE_TO_GET_FILTER		108
#define X509byLDAP_R_UNABLE_TO_BIND			109
#define X509byLDAP_R_SEARCH_FAIL			110

#ifndef OPENSSL_NO_ERR

static ERR_STRING_DATA X509byLDAP_str_functs[] = {
	{ ERR_PACK(0, X509byLDAP_F_LOOKUPCRTL, 0)	, "LOOKUPCRTL" },
	{ ERR_PACK(0, X509byLDAP_F_GET_BY_SUBJECT, 0)	, "GET_BY_SUBJECT" },
	{ 0, NULL }
};


static ERR_STRING_DATA X509byLDAP_str_reasons[] = {
	{ ERR_PACK(0, 0, X509byLDAP_R_INVALID_CRTLCMD)			, "invalid control command" },
	{ ERR_PACK(0, 0, X509byLDAP_R_WRONG_LOOKUP_TYPE)		, "wrong lookup type" },
	{ ERR_PACK(0, 0, X509byLDAP_R_UNABLE_TO_GET_FILTER)		, "unable to get ldap filter" },
	{ ERR_PACK(0, 0, X509byLDAP_R_UNABLE_TO_BIND)			, "unable to bind to ldap server" },
	{ ERR_PACK(0, 0, X509byLDAP_R_SEARCH_FAIL)			, "search failure" },
	{ 0, NULL }
};

static ERR_STRING_DATA X509byLDAP_lib_name[] = {
	{ 0, "X509byLDAP" },
	{ 0, NULL }
};

#endif /*ndef OPENSSL_NO_ERR*/


static int ERR_LIB_X509byLDAP = 0;

static inline void
X509byLDAP_PUT_error(int function, int reason, const char *file, int line, const char *funcname) {
	if (ERR_LIB_X509byLDAP == 0)
		ERR_LIB_X509byLDAP = ERR_get_next_error_library();

#ifdef OPENSSL_NO_FILENAMES /* OpenSSL 1.1+ */
	file = NULL;
	line = 0;
#endif
#ifdef ERR_raise_data
	UNUSED(function);
	ERR_new();
	ERR_set_debug(file, line, funcname);
	ERR_set_error(ERR_LIB_X509byLDAP, reason, NULL);
#else
# ifdef OPENSSL_NO_ERR
	/* If ERR_PUT_error macro ignores file and line */
	UNUSED(file);
	UNUSED(line);
# endif
	UNUSED(funcname);
	ERR_PUT_error(ERR_LIB_X509byLDAP, function, reason, file, line);
#endif /*ndef ERR_raise_data*/
}

#define X509byLDAPerr(f,r) X509byLDAP_PUT_error((f),(r),__FILE__,__LINE__, __func__)


extern void ERR_load_X509byLDAP_strings(void);
void
ERR_load_X509byLDAP_strings(void) {
#ifndef OPENSSL_NO_ERR
{	static int loaded = 0;
	if (loaded) return;
	loaded = 1;
}
	if (ERR_LIB_X509byLDAP == 0)
		ERR_LIB_X509byLDAP = ERR_get_next_error_library();

	ERR_load_strings(ERR_LIB_X509byLDAP, X509byLDAP_str_functs);
	ERR_load_strings(ERR_LIB_X509byLDAP, X509byLDAP_str_reasons);

	X509byLDAP_lib_name[0].error = ERR_PACK(ERR_LIB_X509byLDAP, 0, 0);
	ERR_load_strings(0, X509byLDAP_lib_name);
#endif /*ndef OPENSSL_NO_ERR*/
}


/* ================================================================== */
/* LOOKUP by LDAP */

static int  ldaplookup_ctrl(X509_LOOKUP *ctx, int cmd, const char *argp, long argl, char **ret);
static int  ldaplookup_new(X509_LOOKUP *ctx);
static void ldaplookup_free(X509_LOOKUP *ctx);
static int  ldaplookup_init(X509_LOOKUP *ctx);
static int  ldaplookup_shutdown(X509_LOOKUP *ctx);
static int  ldaplookup_by_subject(X509_LOOKUP *ctx, int type, X509_NAME *name, X509_OBJECT *ret);


typedef struct lookup_item_s lookup_item;

struct lookup_item_s {
	ldaphost *lh;
	lookup_item *next;
};

static inline void
lookup_item_free(lookup_item *p) {
	if (p == NULL) return;

	ldaphost_free(p->lh);
	OPENSSL_free(p);
}

static inline lookup_item*
lookup_item_new(const char *url) {
	lookup_item *ret;

	ret = OPENSSL_malloc(sizeof(lookup_item));
	if (ret == NULL) return NULL;

	ret->lh = ldaphost_new(url);
	if (ret->lh == NULL) {
		OPENSSL_free(ret);
		return NULL;
	}

	ret->next = NULL;
	return ret;
}


X509_LOOKUP_METHOD x509_ldap_lookup = {
	"Load certs and crls from LDAP server",
	ldaplookup_new,		/* new */
	ldaplookup_free,	/* free */
	ldaplookup_init,	/* init */
	ldaplookup_shutdown,	/* shutdown */
	ldaplookup_ctrl,	/* ctrl */
	ldaplookup_by_subject,	/* get_by_subject */
	NULL,			/* get_by_issuer_serial */
	NULL,			/* get_by_fingerprint */
	NULL,			/* get_by_alias */
};


X509_LOOKUP_METHOD*
X509_LOOKUP_ldap(void) {
	return &x509_ldap_lookup;
}


static int
ldaplookup_new(X509_LOOKUP *ctx) {
TRACE_BY_LDAP(__func__, "ctx=%p", ctx);
	if (ctx == NULL) return 0;

	ctx->method_data = NULL;
	return 1;
}


static void
ldaplookup_free(X509_LOOKUP *ctx) {
	lookup_item *p;
TRACE_BY_LDAP(__func__, "ctx=%p", ctx);

	if (ctx == NULL) return;

	p = (lookup_item*)(void*) ctx->method_data;
	while (p != NULL) {
		lookup_item *q = p;
		p = p->next;
		lookup_item_free(q);
	}
}


static int
ldaplookup_init(X509_LOOKUP *ctx) {
TRACE_BY_LDAP(__func__, "ctx=%p", ctx);
	UNUSED(ctx);
	return 1;
}


static int
ldaplookup_shutdown(X509_LOOKUP *ctx) {
TRACE_BY_LDAP(__func__, "ctx=%p", ctx);
	UNUSED(ctx);
	return 1;
}


static int/*bool*/
ldaplookup_add_search(X509_LOOKUP *ctx, const char *url) {
	lookup_item *p, *q;

	if (ctx == NULL) return 0;
	if (url == NULL) return 0;

	q = lookup_item_new(url);
	if (q == NULL) return 0;

	p = (lookup_item*)(void*) ctx->method_data;
	if (p == NULL) {
		ctx->method_data = (void*) q;
		return 1;
	}

	for(; p->next != NULL; p = p->next) {
		/*find list end*/
	}
	p->next = q;

	return 1;
}


static int
ldaplookup_ctrl(X509_LOOKUP *ctx, int cmd, const char *argc, long argl, char **retp) {
	int ret = 0;

	UNUSED(argl);
	UNUSED(retp);
TRACE_BY_LDAP(__func__, "ctx=%p, cmd: %d, argc: '%s'", ctx, cmd, argc);
	switch (cmd) {
	case X509_L_LDAP_HOST:
		ret = ldaplookup_add_search(ctx, argc);
		break;
	default:
		X509byLDAPerr(X509byLDAP_F_LOOKUPCRTL, X509byLDAP_R_INVALID_CRTLCMD);
		break;
	}
	return ret;
}


/*
 * We will put into store X509 object from passed data in buffer only
 * when object name match passed. To compare both names we use our
 * method "ssh_X509_NAME_cmp"(it is more general).
 */
static int/*bool*/
ldaplookup_data2store(
	int         type,
	X509_NAME*  name,
	void*       buf,
	int         len,
	X509_STORE* store
) {
	int ok = 0;
	BIO *mbio;

	if (name == NULL) return 0;
	if (buf == NULL) return 0;
	if (len <= 0) return 0;
	if (store == NULL) return 0;

	mbio = BIO_new_mem_buf(buf, len);
	if (mbio == NULL) return 0;

	switch (type) {
	case X509_LU_X509: {
		X509 *x509 = d2i_X509_bio(mbio, NULL);
		if(x509 == NULL) goto exit;

		/*This is correct since lookup method is by subject*/
		if (ssh_X509_NAME_cmp(name, X509_get_subject_name(x509)) != 0) goto exit;

		ok = X509_STORE_add_cert(store, x509);
		/* X509_STORE_add...() increase "object" reference,
		 * so here object must be released unconditionally.
		 */
		X509_free(x509);
		} break;
	case X509_LU_CRL: {
		X509_CRL *crl = d2i_X509_CRL_bio(mbio, NULL);
		if(crl == NULL) goto exit;

		if (ssh_X509_NAME_cmp(name, X509_CRL_get_issuer(crl)) != 0) goto exit;

		ok = X509_STORE_add_crl(store, crl);
		X509_CRL_free(crl);
		} break;
	}

exit:
	BIO_free_all(mbio);
TRACE_BY_LDAP(__func__, "ok: %d", ok);
	return ok;
}


/*
 * Clasic(direct) search "by subject"
 */
static int
ldaplookup_by_subject(
	X509_LOOKUP *ctx,
	int          type,
	X509_NAME   *name,
	X509_OBJECT *ret
) {
	int count = 0;
	lookup_item *p;
	const char *attrs[2];
	static const char *ATTR_CACERT = "cACertificate";
	static const char *ATTR_CACRL = "certificateRevocationList";
	char *filter = NULL;

TRACE_BY_LDAP(__func__, "ctx=%p, type: %d", ctx, type);
	if (ctx == NULL) return 0;
	if (name == NULL) return 0;

	p = (lookup_item*)(void*) ctx->method_data;
	if (p == NULL) return 0;

	switch(type) {
	case X509_LU_X509: {
		attrs[0] = ATTR_CACERT;
		} break;
	case X509_LU_CRL: {
		attrs[0] = ATTR_CACRL;
		} break;
	default: {
		X509byLDAPerr(X509byLDAP_F_GET_BY_SUBJECT, X509byLDAP_R_WRONG_LOOKUP_TYPE);
		goto done;
		}
	}
	attrs[1] = NULL;

	filter = X509_NAME_ldapfilter(name, attrs[0]);
	if (filter == NULL) {
		X509byLDAPerr(X509byLDAP_F_GET_BY_SUBJECT, X509byLDAP_R_UNABLE_TO_GET_FILTER);
		goto done;
	}
TRACE_BY_LDAP(__func__, "filter: '%s'", filter);

	for (; p != NULL; p = p->next) {
		ldaphost *lh = p->lh;
		LDAPMessage *res = NULL;
		int result;

#ifdef TRACE_BY_LDAP_ENABLED
{
int version = -1;

ldap_get_option(lh->ld, LDAP_OPT_PROTOCOL_VERSION, &version);
TRACE_BY_LDAP(__func__, "bind to '%s://%s:%d' using protocol v%d"
, lh->ldapurl->lud_scheme, lh->ldapurl->lud_host, lh->ldapurl->lud_port
, version
);
}
#endif /*def TRACE_BY_LDAP_ENABLED*/

		result = ssh_ldap_bind_s(lh->ld);
		if (result != LDAP_SUCCESS) {
			X509byLDAPerr(X509byLDAP_F_GET_BY_SUBJECT, X509byLDAP_R_UNABLE_TO_BIND);
			{
				char	buf[1024];
				snprintf(buf, sizeof(buf),
					" url=\"%s://%s:%d\""
					" ldaperror=0x%x(%.256s)"
					, lh->ldapurl->lud_scheme, lh->ldapurl->lud_host, lh->ldapurl->lud_port
					, result, ldap_err2string(result)
				);
				ERR_add_error_data(1, buf);
			}
			continue;
		}

		result = ssh_ldap_search_s(lh->ld, lh->ldapurl->lud_dn,
				LDAP_SCOPE_SUBTREE, filter, (char**)attrs, 0, &res);
		if (result != LDAP_SUCCESS) {
			X509byLDAPerr(X509byLDAP_F_GET_BY_SUBJECT, X509byLDAP_R_SEARCH_FAIL);
			ldap_msgfree(res);
			continue;
		}
	{	X509_STORE *store = ctx->store_ctx;
		ldapsearch_result *it = ldapsearch_iterator(lh->ld, res);

		while (ldapsearch_advance(it)) {
		{	const char *q;

			switch (type) {
			case X509_LU_X509: q = ATTR_CACERT; break;
			case X509_LU_CRL : q = ATTR_CACRL ; break;
			default: /* warnings */
				continue;
			}
			if (strncmp(it->attr, q, strlen(q)) != 0)
				continue;
		}

		{	struct berval *q = *it->p;
			count += ldaplookup_data2store(type, name,
			    q->bv_val, q->bv_len, store)
			    ? 1 : 0;
		}
		}

		OPENSSL_free(it);
	}

		ldap_msgfree(res);

		/* NOTE: do not call ldap_unbind... here!
		 * Function ldaphost_free() unbind LDAP structure.
		 */
	}

TRACE_BY_LDAP(__func__, "count: %d", count);
	if (count > 0) {
		X509_STORE *store = ctx->store_ctx;
		X509_OBJECT *tmp;

		X509_STORE_lock(store);
		{	STACK_OF(X509_OBJECT) *objs;
			objs = X509_STORE_get0_objects(store);
			tmp = X509_OBJECT_retrieve_by_subject(objs, type, name);
		}
		X509_STORE_unlock(store);
TRACE_BY_LDAP(__func__, "tmp=%p", (void*)tmp);

		if (tmp == NULL) {
			count = 0;
			goto done;
		}

		ret->type = tmp->type;
		memcpy(&ret->data, &tmp->data, sizeof(ret->data));
	}

done:
	OPENSSL_free(filter);
	return count > 0;
}
#else /*ndef USE_OPENSSL_STORE2*/

/* use OpenSSL 3.0+ X.509 look-up "by_store" */
typedef int x509_by_ldap_empty_translation_unit;

#endif
