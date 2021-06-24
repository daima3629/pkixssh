/*
 * Copyright (c) 2004-2020 Roumen Petrov.  All rights reserved.
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

#ifndef USE_X509_LOOKUP_STORE
/* custom X.509 look-up */

#ifdef USE_LDAP_STORE
#  include <openssl/store.h>
#endif
#include <openssl/err.h>

/* prefer X509_NAME_cmp method from ssh-x509.c */
extern int     ssh_X509_NAME_cmp(X509_NAME *a, X509_NAME *b);

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


#ifndef HAVE_STRUCT_X509_LOOKUP_METHOD_ST
/* temporary for some OpenSSL 1.1 "alpha" versions */
struct x509_lookup_method_st {
	const char *name;
	int (*new_item) (X509_LOOKUP *ctx);
	void (*free) (X509_LOOKUP *ctx);
	int (*init) (X509_LOOKUP *ctx);
	int (*shutdown) (X509_LOOKUP *ctx);
	int (*ctrl) (X509_LOOKUP *ctx, int cmd, const char *argc, long argl, char **ret);
	int (*get_by_subject) (X509_LOOKUP *ctx, int type, X509_NAME *name, X509_OBJECT *ret);
	int (*get_by_issuer_serial) (X509_LOOKUP *ctx, int type, X509_NAME *name, ASN1_INTEGER *serial, X509_OBJECT *ret);
	int (*get_by_fingerprint) (X509_LOOKUP *ctx, int type, unsigned char *bytes, int len, X509_OBJECT *ret);
	int (*get_by_alias) (X509_LOOKUP *ctx, int type, char *str, int len, X509_OBJECT *ret);
};

struct x509_lookup_st {
	int init;                   /* have we been started */
	int skip;                   /* don't use us. */
	X509_LOOKUP_METHOD *method; /* the functions */
	char *method_data;          /* method data */
	X509_STORE *store_ctx;      /* who owns us */
};

struct x509_object_st {
	X509_LOOKUP_TYPE type;
	union {
		char *ptr;
		X509 *x509;
		X509_CRL *crl;
		EVP_PKEY *pkey;
	} data;
};
#endif /*ndef HAVE_STRUCT_X509_LOOKUP_METHOD_ST*/


/* ================================================================== */
/* ERRORS */

/* Function codes. */
#define X509byLDAP_F_LOOKUPCRTL			100
#define X509byLDAP_F_SET_PROTOCOL		102
#define X509byLDAP_F_GET_BY_SUBJECT		104

/* Reason codes. */
#define X509byLDAP_R_INVALID_CRTLCMD			100
#define X509byLDAP_R_UNABLE_TO_SET_PROTOCOL_VERSION	105
#define X509byLDAP_R_WRONG_LOOKUP_TYPE			107
#define X509byLDAP_R_UNABLE_TO_GET_FILTER		108
#define X509byLDAP_R_UNABLE_TO_BIND			109
#define X509byLDAP_R_SEARCH_FAIL			110

#ifndef OPENSSL_NO_ERR

static ERR_STRING_DATA X509byLDAP_str_functs[] = {
	{ ERR_PACK(0, X509byLDAP_F_LOOKUPCRTL, 0)	, "LOOKUPCRTL" },
	{ ERR_PACK(0, X509byLDAP_F_SET_PROTOCOL, 0)	, "SET_PROTOCOL" },
	{ ERR_PACK(0, X509byLDAP_F_GET_BY_SUBJECT, 0)	, "GET_BY_SUBJECT" },
	{ 0, NULL }
};


static ERR_STRING_DATA X509byLDAP_str_reasons[] = {
	{ ERR_PACK(0, 0, X509byLDAP_R_INVALID_CRTLCMD)			, "invalid control command" },
	{ ERR_PACK(0, 0, X509byLDAP_R_UNABLE_TO_SET_PROTOCOL_VERSION)	, "unable to set ldap protocol version" },
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
#ifdef USE_LDAP_STORE
typedef struct ldapstore_s ldapstore;
struct ldapstore_s {
	char *url;
	OSSL_STORE_CTX *ctx;
};


static ldapstore* ldapstore_new(const char *url);
static void ldapstore_free(ldapstore *p);


static ldapstore*
ldapstore_new(const char *url) {
	ldapstore *p;

	p = OPENSSL_malloc(sizeof(ldapstore));
	if (p == NULL) return NULL;

	p->url = OPENSSL_malloc(strlen(url) + 1);
	if (p->url == NULL) goto error;
	strcpy(p->url, url);

	p->ctx = NULL;

	return p;

error:
	ldapstore_free(p);
	return NULL;
}


static void
ldapstore_free(ldapstore *p) {
	if (p == NULL) return;

	OPENSSL_free(p->url);
	if (p->ctx != NULL) {
		OSSL_STORE_close(p->ctx);
		p->ctx = NULL;
	}
	OPENSSL_free(p);
}
#endif /*def USE_LDAP_STORE*/


/* ================================================================== */
/* LOOKUP by LDAP */

static int  ldaplookup_ctrl(X509_LOOKUP *ctx, int cmd, const char *argp, long argl, char **ret);
static int  ldaplookup_new(X509_LOOKUP *ctx);
static void ldaplookup_free(X509_LOOKUP *ctx);
static int  ldaplookup_init(X509_LOOKUP *ctx);
static int  ldaplookup_shutdown(X509_LOOKUP *ctx);
static int  ldaplookup_by_subject(X509_LOOKUP *ctx, int type, X509_NAME *name, X509_OBJECT *ret);

static int  ldaplookup_add_search(X509_LOOKUP *ctx, const char *url);


typedef struct lookup_item_s lookup_item;
struct lookup_item_s {
#ifndef USE_LDAP_STORE
	ldaphost *lh;
#else
	ldapstore *ls;
#endif
	lookup_item *next;
};

static inline void
lookup_item_free(lookup_item *p) {
	if (p == NULL) return;

#ifndef USE_LDAP_STORE
	ldaphost_free(p->lh);
#else
	ldapstore_free(p->ls);
#endif
	OPENSSL_free(p);
}

static inline lookup_item*
lookup_item_new(const char *url) {
	lookup_item *ret;

	ret = OPENSSL_malloc(sizeof(lookup_item));
	if (ret == NULL) return NULL;

#ifndef USE_LDAP_STORE
	ret->lh = ldaphost_new(url);
	if (ret->lh == NULL) {
#else
	ret->ls = ldapstore_new(url);
	if (ret->ls == NULL) {
#endif
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


#ifdef USE_LDAP_STORE
#include "x509_by_ldap1.c"
#else
#include "x509_by_ldap0.c"
#endif


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
#else /*def USE_X509_LOOKUP_STORE*/

/* use OpenSSL 3.0+ X.509 look-up "by_store" */
typedef int x509_by_ldap_empty_translation_unit;

#endif
