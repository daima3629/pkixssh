/*
 * Copyright (c) 2004-2018 Roumen Petrov.  All rights reserved.
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

/* prefer X509_NAME_cmp method from ssh-x509.c */
extern int     ssh_X509_NAME_cmp(X509_NAME *a, X509_NAME *b);

#include <string.h>
#ifndef LDAP_DEPRECATED
   /* to suppress warnings in some 2.3x versions */
#  define LDAP_DEPRECATED 0
#endif
#include <ldap.h>

#undef TRACE_BY_LDAP_ENABLED
#ifdef TRACE_BY_LDAP
#undef TRACE_BY_LDAP
#define TRACE_BY_LDAP_ENABLED 1
static void
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
#else
static inline void
TRACE_BY_LDAP(const char *f, const char *fmt, ...) {
    UNUSED(f);
    UNUSED(fmt);
}
#endif


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
#ifndef OPENSSL_NO_ERR
static ERR_STRING_DATA X509byLDAP_str_functs[] = {
	{ ERR_PACK(0, X509byLDAP_F_LOOKUPCRTL, 0)	, "LOOKUPCRTL" },
	{ ERR_PACK(0, X509byLDAP_F_LDAPHOST_NEW, 0)	, "LDAPHOST_NEW" },
	{ ERR_PACK(0, X509byLDAP_F_SET_PROTOCOL, 0)	, "SET_PROTOCOL" },
	{ ERR_PACK(0, X509byLDAP_F_RESULT2STORE, 0)	, "RESULT2STORE" },
	{ ERR_PACK(0, X509byLDAP_F_GET_BY_SUBJECT, 0)	, "GET_BY_SUBJECT" },
	{ 0, NULL }
};


static ERR_STRING_DATA X509byLDAP_str_reasons[] = {
	{ ERR_PACK(0, 0, X509byLDAP_R_INVALID_CRTLCMD)			, "invalid control command" },
	{ ERR_PACK(0, 0, X509byLDAP_R_NOT_LDAP_URL)			, "not ldap url" },
	{ ERR_PACK(0, 0, X509byLDAP_R_INVALID_URL)			, "invalid ldap url" },
	{ ERR_PACK(0, 0, X509byLDAP_R_INITIALIZATION_ERROR)		, "ldap initialization error" },
	{ ERR_PACK(0, 0, X509byLDAP_R_UNABLE_TO_GET_PROTOCOL_VERSION)	, "unable to get ldap protocol version" },
	{ ERR_PACK(0, 0, X509byLDAP_R_UNABLE_TO_SET_PROTOCOL_VERSION)	, "unable to set ldap protocol version" },
	{ ERR_PACK(0, 0, X509byLDAP_R_UNABLE_TO_COUNT_ENTRIES)		, "unable to count ldap entries" },
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
X509byLDAP_PUT_error(int function, int reason, const char *file, int line) {
	if (ERR_LIB_X509byLDAP == 0)
		ERR_LIB_X509byLDAP = ERR_get_next_error_library();

	ERR_PUT_error(ERR_LIB_X509byLDAP, function, reason, file, line);
}
#define X509byLDAPerr(f,r) X509byLDAP_PUT_error((f),(r),__FILE__,__LINE__)


void
ERR_load_X509byLDAP_strings(void) {
#ifndef OPENSSL_NO_ERR
{	static int loaded = 0;
	if (loaded) return;
	loaded = 1;
}
	ERR_LIB_X509byLDAP = ERR_get_next_error_library();

	ERR_load_strings(ERR_LIB_X509byLDAP, X509byLDAP_str_functs);
	ERR_load_strings(ERR_LIB_X509byLDAP, X509byLDAP_str_reasons);

	X509byLDAP_lib_name[0].error = ERR_PACK(ERR_LIB_X509byLDAP, 0, 0);
	ERR_load_strings(0, X509byLDAP_lib_name);
#endif
}


static char*
ldap_errormsg(char *buf, size_t len, int err) {
	snprintf(buf, len, "ldaperror=0x%x(%.256s)", err, ldap_err2string(err));
	return buf;
}


static void
openssl_add_ldap_error(int err) {
	char	buf[512];
	ERR_add_error_data(1, ldap_errormsg(buf, sizeof(buf), err));
}


/* ================================================================== */
/* wrappers for some deprecated functions */

static void
ldaplookup_parse_result (
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
	openssl_add_ldap_error(result);
#endif
}


static int
ldaplookup_bind_s(LDAP *ld) {
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


static int
ldaplookup_search_s(
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


/* ================================================================== */
/* LDAP connection details */

typedef struct ldaphost_s ldaphost;
struct ldaphost_s {
	char        *url;
	char        *binddn;
	char        *bindpw;
	LDAPURLDesc *ldapurl;
	LDAP        *ld;
	ldaphost    *next;
};


static ldaphost* ldaphost_new(const char *url);
static void ldaphost_free(ldaphost *p);


static ldaphost*
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
		X509byLDAPerr(X509byLDAP_F_LDAPHOST_NEW, X509byLDAP_R_NOT_LDAP_URL);
		goto error;
	}

	ret = ldap_url_parse(p->url, &p->ldapurl);
	if (ret != 0) {
		X509byLDAPerr(X509byLDAP_F_LDAPHOST_NEW, X509byLDAP_R_INVALID_URL);
		openssl_add_ldap_error(ret);
		goto error;
	}
TRACE_BY_LDAP(__func__, "ldap_url_desc2str: '%s'", ldap_url_desc2str(p->ldapurl));
TRACE_BY_LDAP(__func__, "ldapurl: '%s://%s:%d'", p->ldapurl->lud_scheme, p->ldapurl->lud_host, p->ldapurl->lud_port);

	/* allocate connection without to open */
#ifdef HAVE_LDAP_INITIALIZE
	ret = ldap_initialize(&p->ld, p->url);
	if (ret != LDAP_SUCCESS) {
		X509byLDAPerr(X509byLDAP_F_LDAPHOST_NEW, X509byLDAP_R_INITIALIZATION_ERROR);
		openssl_add_ldap_error(ret);
		goto error;
	}
#else /*ndef HAVE_LDAP_INITIALIZE*/
	p->ld = ldap_init(p->ldapurl->lud_host, p->ldapurl->lud_port);
	if(p->ld == NULL) {
		X509byLDAPerr(X509byLDAP_F_LDAPHOST_NEW, X509byLDAP_R_INITIALIZATION_ERROR);
		goto error;
	}
#endif /*ndef HAVE_LDAP_INITIALIZE*/

{	int version = -1;

	ret = ldap_get_option(p->ld, LDAP_OPT_PROTOCOL_VERSION, &version);
	if (ret != LDAP_OPT_SUCCESS) {
		X509byLDAPerr(X509byLDAP_F_LDAPHOST_NEW, X509byLDAP_R_UNABLE_TO_GET_PROTOCOL_VERSION );
		goto error;
	}
TRACE_BY_LDAP(__func__, "using protocol v%d (default)", version);
}

	return p;
error:
	ldaphost_free(p);
	return NULL;
}


static void
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
		/* how to free ld ???*/
		p->ld = NULL;
	}
	OPENSSL_free(p);
}


/* ================================================================== */
/* LDAP result iterator */

typedef struct ldapsearch_result_st ldapsearch_result;
struct ldapsearch_result_st {
	LDAP *ld;
	LDAPMessage *entry;
	/* loop on attribute */
	char *attr;
	BerElement *attr_ber;
	/* loop on attribute values */
	struct berval **vals;
	struct berval **p;
	int eom;
};


static ldapsearch_result*
ldapsearch_iterator(LDAP *ld, LDAPMessage *res) {
{	int k = ldap_count_entries(ld, res);
TRACE_BY_LDAP(__func__, "ldap_count_entries: %d", k);
	if (k < 0) {
		X509byLDAPerr(X509byLDAP_F_RESULT2STORE, X509byLDAP_R_UNABLE_TO_COUNT_ENTRIES);
		ldaplookup_parse_result (ld, res);
		return NULL;
	}
}
{
	ldapsearch_result *ret = OPENSSL_malloc(sizeof(ldapsearch_result));
	if (ret == NULL) return NULL;

	memset(ret, 0, sizeof(ldapsearch_result));

	ret->ld = ld;
	ret->entry = ldap_first_entry(ld, res);
	return ret;
}
}


static int
ldapsearch_advance(ldapsearch_result* r) {
	while(r->entry != NULL) {
#ifdef TRACE_BY_LDAP_ENABLED
{
char *dn = ldap_get_dn(r->ld, r->entry);
TRACE_BY_LDAP(__func__, "ldap_get_dn: '%s'", dn);
ldap_memfree(dn);
}
#endif
		if (r->attr == NULL)
			r->attr = ldap_first_attribute(r->ld, r->entry, &r->attr_ber);

		while(r->attr != NULL) {
TRACE_BY_LDAP(__func__, "attr: '%s'", r->attr);

			if (r->p == NULL) {
				r->vals = ldap_get_values_len(r->ld, r->entry, r->attr);
				r->p = r->vals;
TRACE_BY_LDAP(__func__, "r->p[0]=%p'", *r->p);
				return 1;
			}

			r->p++;
TRACE_BY_LDAP(__func__, "r->p[x]=%p'", *r->p);
			if (*r->p != NULL)
				return 1;

			ldap_value_free_len(r->vals);

			r->attr = ldap_next_attribute(r->ld, r->entry, r->attr_ber);
		}

		ber_free(r->attr_ber, 0);

		r->entry = ldap_next_entry(r->ld, r->entry);
	}
TRACE_BY_LDAP(__func__, "end");
	return 0;
}


/* ================================================================== */
/* LOOKUP by LDAP */

static const char ATTR_CACERT[] = "cACertificate";
static const char ATTR_CACRL[] = "certificateRevocationList";

static int  ldaplookup_ctrl(X509_LOOKUP *ctx, int cmd, const char *argp, long argl, char **ret);
static int  ldaplookup_new(X509_LOOKUP *ctx);
static void ldaplookup_free(X509_LOOKUP *ctx);
static int  ldaplookup_init(X509_LOOKUP *ctx);
static int  ldaplookup_shutdown(X509_LOOKUP *ctx);
static int  ldaplookup_by_subject(X509_LOOKUP *ctx, int type, X509_NAME *name, X509_OBJECT *ret);

static int  ldaplookup_add_search(X509_LOOKUP *ctx, const char *url);
static int  ldaplookup_set_protocol(X509_LOOKUP *ctx, const char *ver);


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
ldaplookup_ctrl(X509_LOOKUP *ctx, int cmd, const char *argc, long argl, char **retp) {
	int ret = 0;

	UNUSED(argl);
	UNUSED(retp);
TRACE_BY_LDAP(__func__, "cmd: %d, argc: '%s'", cmd, argc);
	switch (cmd) {
	case X509_L_LDAP_HOST:
		ret = ldaplookup_add_search(ctx, argc);
		break;
	case X509_L_LDAP_VERSION:
		ret = ldaplookup_set_protocol(ctx, argc);
		break;
	default:
		X509byLDAPerr(X509byLDAP_F_LOOKUPCRTL, X509byLDAP_R_INVALID_CRTLCMD);
		break;
	}
	return ret;
}


static int
ldaplookup_new(X509_LOOKUP *ctx) {
TRACE_BY_LDAP(__func__, "...");
	if (ctx == NULL) return 0;

	ctx->method_data = NULL;
	return 1;
}


static void
ldaplookup_free(X509_LOOKUP *ctx) {
	ldaphost *p;
TRACE_BY_LDAP(__func__, "...");

	if (ctx == NULL) return;

	p = (ldaphost*) ctx->method_data;
	while (p != NULL) {
		ldaphost *q = p;
		p = p->next;
		ldaphost_free(q);
	}
}


static int
ldaplookup_init(X509_LOOKUP *ctx) {
TRACE_BY_LDAP(__func__, "...");
	UNUSED(ctx);
	return 1;
}


static int
ldaplookup_shutdown(X509_LOOKUP *ctx) {
TRACE_BY_LDAP(__func__, "...");
	UNUSED(ctx);
	return 1;
}


static int/*bool*/
ldaplookup_add_search(X509_LOOKUP *ctx, const char *url) {
	ldaphost *p, *q;

	if (ctx == NULL) return 0;
	if (url == NULL) return 0;

	q = ldaphost_new(url);
	if (q == NULL) return 0;

	p = (ldaphost*) ctx->method_data;
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


static int/*bool*/
ldaplookup_set_protocol(X509_LOOKUP *ctx, const char *ver) {
	ldaphost *p;
	char *q = NULL;
	int n;

TRACE_BY_LDAP(__func__, "ver: '%s'  ...", ver);
	if (ctx == NULL) return 0;
	if (ver == NULL) return 0;

	p = (ldaphost*) ctx->method_data;
TRACE_BY_LDAP(__func__, "p=%p", (void*)p);
	if (p == NULL) return 0;

	n = (int) strtol(ver, &q, 10);
	if (*q != '\0') return 0;
	if ((n < LDAP_VERSION_MIN) || (n > LDAP_VERSION_MAX)) return 0;

	for(; p->next != NULL; p = p->next) {
		/*find list end*/
	}
TRACE_BY_LDAP(__func__, "ver: %d", n);
	{
		int ret;
		const int version = n;

		ret = ldap_set_option(p->ld, LDAP_OPT_PROTOCOL_VERSION, &version);
		if (ret != LDAP_OPT_SUCCESS) {
			X509byLDAPerr(X509byLDAP_F_SET_PROTOCOL, X509byLDAP_R_UNABLE_TO_SET_PROTOCOL_VERSION);
			openssl_add_ldap_error(ret);
			return 0;
		}
	}

	return 1;
}


static char*
ldaplookup_attr(ASN1_STRING *nv) {
	char *p = NULL;
	int k;
	BIO *mbio;

	mbio = BIO_new(BIO_s_mem());
	if (mbio == NULL) return NULL;

	k = ASN1_STRING_print_ex(mbio, nv, XN_FLAG_RFC2253);
	p = OPENSSL_malloc(k + 1);
	if (p == NULL) goto done;

	k = BIO_read(mbio, p, k);
	p[k] = '\0';

done:
	BIO_free_all(mbio);
	return p;
}


static char*
ldaplookup_filter(X509_NAME *name, const char *attribute) {
	char *p = NULL;
	int k;
	BIO *mbio;

	mbio = BIO_new(BIO_s_mem());
	if (mbio == NULL) return NULL;

	BIO_puts(mbio, "(&");

	k = X509_NAME_entry_count(name);
	for (--k; k >= 0; k--) {
		X509_NAME_ENTRY *ne;
		ASN1_STRING     *nv;
		int nid;

		ne = X509_NAME_get_entry(name, k);
		nid = OBJ_obj2nid(X509_NAME_ENTRY_get_object(ne));

		if (
			(nid != NID_organizationName) &&
			(nid != NID_organizationalUnitName) &&
			(nid != NID_commonName)
		) continue;

		BIO_puts(mbio, "(");
		BIO_puts(mbio, OBJ_nid2sn(nid));
		BIO_puts(mbio, "=");
		nv = X509_NAME_ENTRY_get_data(ne);
		{
			char *q, *s;

			q = ldaplookup_attr(nv);
TRACE_BY_LDAP(__func__, "ldaplookup_attr(nv) return '%s'", (q ? q : "<?>"));
			if (q == NULL) goto done;
			/* escape some charecters according to RFC2254 */
			for (s=q; *s; s++) {
				if ((*s == '*') ||
				    (*s == '(') ||
				    (*s == ')')
				    /* character '\' should be already escaped ! */
				) {
					/* RFC2254 recommendation */
					BIO_printf(mbio, "\\%02X", (int)*s);
					continue;
				}
				BIO_write(mbio, s, 1);
			}

			OPENSSL_free(q);
		}
		BIO_puts(mbio, ")");
	}

	BIO_puts(mbio, "(");
	BIO_puts(mbio, attribute);
	BIO_puts(mbio, "=*)");

	BIO_puts(mbio, ")");
	(void)BIO_flush(mbio);

	k = BIO_pending(mbio);
	p = OPENSSL_malloc(k + 1);
	if (p == NULL) goto done;

	k = BIO_read(mbio, p, k);
	p[k] = '\0';
TRACE_BY_LDAP(__func__, "result: '%.1024s'%s", p, (k > 1024 ? "...": ""));

done:
	BIO_free_all(mbio);
	return p;
}


static int/*bool*/
ldaplookup_check_attr(
	int type,
	const char *attr
) {
	if (type == X509_LU_X509)
		return strncmp(attr, ATTR_CACERT, sizeof(ATTR_CACERT)) != 0;

	if (type == X509_LU_CRL)
		return strncmp(attr, ATTR_CACRL, sizeof(ATTR_CACRL)) != 0;

	return 0;
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
		} break;
	case X509_LU_CRL: {
		X509_CRL *crl = d2i_X509_CRL_bio(mbio, NULL);
		if(crl == NULL) goto exit;

		if (ssh_X509_NAME_cmp(name, X509_CRL_get_issuer(crl)) != 0) goto exit;

		ok = X509_STORE_add_crl(store, crl);
		} break;
	}

exit:
	BIO_free_all(mbio);
TRACE_BY_LDAP(__func__, "ok: %d", ok);
	return ok;
}


static int
ldaplookup_by_subject(
	X509_LOOKUP *ctx,
	int          type,
	X509_NAME   *name,
	X509_OBJECT *ret
) {
	int count = 0;
	ldaphost *lh;
	const char *attrs[2];
	char *filter = NULL;

TRACE_BY_LDAP(__func__, "type: %d", type);
	if (ctx == NULL) return 0;
	if (name == NULL) return 0;

	lh = (ldaphost*) ctx->method_data;
	if (lh == NULL) return 0;

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

	filter = ldaplookup_filter(name, attrs[0]);
	if (filter == NULL) {
		X509byLDAPerr(X509byLDAP_F_GET_BY_SUBJECT, X509byLDAP_R_UNABLE_TO_GET_FILTER);
		goto done;
	}
TRACE_BY_LDAP(__func__, "filter: '%s'", filter);

	for (; lh != NULL; lh = lh->next) {
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

		result = ldaplookup_bind_s(lh->ld);
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

		result = ldaplookup_search_s(lh->ld, lh->ldapurl->lud_dn,
				LDAP_SCOPE_SUBTREE, filter, (char**)attrs, 0, &res);
		if (result != LDAP_SUCCESS) {
			X509byLDAPerr(X509byLDAP_F_GET_BY_SUBJECT, X509byLDAP_R_SEARCH_FAIL);
			ldap_msgfree(res);
			continue;
		}

	{	X509_STORE *store = ctx->store_ctx;
		ldapsearch_result *it = ldapsearch_iterator(lh->ld, res);

		while (ldapsearch_advance(it)) {
			struct berval *q;
			if (!ldaplookup_check_attr(type, it->attr))
				continue;

			q = *it->p;
			count += ldaplookup_data2store(type, name,
			    q->bv_val, q->bv_len, store)
			    ? 1 : 0;
		}

		OPENSSL_free(it);
	}

		ldap_msgfree(res);

		/*do not call ldap_unbind_s*/
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
	if (filter != NULL) OPENSSL_free(filter);
	return count > 0;
}
