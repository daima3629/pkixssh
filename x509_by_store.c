/*
 * Copyright (c) 2016-2021 Roumen Petrov.  All rights reserved.
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

#include "x509store.h"

#ifdef USE_X509_LOOKUP_MYSTORE

#include <openssl/store.h>
#include <string.h>


typedef struct mystore_s mystore;
struct mystore_s {
	char *url;
	OSSL_STORE_CTX *ctx;
};

static void
mystore_free(mystore *p) {
	if (p == NULL) return;

	OPENSSL_free(p->url);
	if (p->ctx != NULL) {
		OSSL_STORE_close(p->ctx);
		p->ctx = NULL;
	}
	OPENSSL_free(p);
}

static mystore*
mystore_new(const char *url) {
	mystore *p;

	p = OPENSSL_malloc(sizeof(mystore));
	if (p == NULL) return NULL;

	p->url = OPENSSL_malloc(strlen(url) + 1);
	if (p->url == NULL) goto error;
	strcpy(p->url, url);

	p->ctx = NULL;

	return p;

error:
	mystore_free(p);
	return NULL;
}


typedef struct lookup_item_s lookup_item;
struct lookup_item_s {
	mystore *db;
	lookup_item *next;
};

static lookup_item*
lookup_item_new(const char *url) {
	lookup_item *ret;

	ret = OPENSSL_malloc(sizeof(lookup_item));
	if (ret == NULL) return NULL;

	ret->db = mystore_new(url);
	if (ret->db == NULL) {
		OPENSSL_free(ret);
		return NULL;
	}

	ret->next = NULL;
	return ret;
}

static void
lookup_item_free(lookup_item *p) {
	if (p == NULL) return;

	mystore_free(p->db);
	OPENSSL_free(p);
}


static int  mystorelookup_new(X509_LOOKUP *ctx);
static void mystorelookup_free(X509_LOOKUP *ctx);
static int  mystorelookup_init(X509_LOOKUP *ctx);
static int  mystorelookup_shutdown(X509_LOOKUP *ctx);
static int  mystorelookup_ctrl(X509_LOOKUP *ctx, int cmd, const char *argp, long argl, char **ret);
static int  mystorelookup_by_subject(X509_LOOKUP *ctx, int type, X509_NAME *name, X509_OBJECT *ret);

X509_LOOKUP_METHOD*
X509_LOOKUP_mystore(void) {
static X509_LOOKUP_METHOD
	x509_mystore_lookup = {
		"Load certs and crls from Store",
		mystorelookup_new,
		mystorelookup_free,
		mystorelookup_init,
		mystorelookup_shutdown,
		mystorelookup_ctrl,
		mystorelookup_by_subject,
		NULL/*get_by_issuer_serial*/,
		NULL/*get_by_fingerprint*/,
		NULL/*get_by_alias */
	};
	return &x509_mystore_lookup;
}


static int
mystorelookup_new(X509_LOOKUP *ctx) {
	if (ctx == NULL) return 0;

	ctx->method_data = NULL;
	return 1;
}


static void
mystorelookup_free(X509_LOOKUP *ctx) {
	lookup_item *p;

	if (ctx == NULL) return;

	p = (lookup_item*)(void*) ctx->method_data;
	while (p != NULL) {
		lookup_item *q = p;
		p = p->next;
		lookup_item_free(q);
	}
}


static int
mystorelookup_init(X509_LOOKUP *ctx) {
	UNUSED(ctx);
	return 1;
}


static int
mystorelookup_shutdown(X509_LOOKUP *ctx) {
	UNUSED(ctx);
	return 1;
}


static int/*bool*/
mystorelookup_add_search(X509_LOOKUP *ctx, const char *uri) {
	lookup_item *p, *q;

	if (ctx == NULL) return 0;
	if (uri == NULL) return 0;

	q = lookup_item_new(uri);
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
mystorelookup_ctrl(X509_LOOKUP *ctx, int cmd, const char *argc, long argl, char **retp) {
	int ret = 0;

	UNUSED(argl);
	UNUSED(retp);
	switch (cmd) {
	case X509_L_MYSTORE_URI:
		ret = mystorelookup_add_search(ctx, argc);
		break;
	default:
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
mystorelookup_data2store(
	int type, X509_NAME *name,
	OSSL_STORE_INFO *info,
	X509_STORE *store
) {
	int ok = 0;

	if (name == NULL) return 0;
	if (info == NULL) return 0;
	if (store == NULL) return 0;

	switch (type) {
	case X509_LU_X509: {
		X509 *x509 = OSSL_STORE_INFO_get0_CERT(info);
		if(x509 == NULL) goto exit;

		/*This is correct since lookup method is by subject*/
		if (ssh_X509_NAME_cmp(name, X509_get_subject_name(x509)) != 0) goto exit;

		ok = X509_STORE_add_cert(store, x509);
		} break;
	case X509_LU_CRL: {
		X509_CRL *crl = OSSL_STORE_INFO_get0_CRL(info);
		if(crl == NULL) goto exit;

		if (ssh_X509_NAME_cmp(name, X509_CRL_get_issuer(crl)) != 0) goto exit;

		ok = X509_STORE_add_crl(store, crl);
		} break;
	default:
		return 0;
	}
exit:
	return ok;
}


/*
 * Search "by subject" based on "Store2 API"
 */
static int
mystorelookup_by_subject(
	X509_LOOKUP *ctx,
	int          type,
	X509_NAME   *name,
	X509_OBJECT *ret
) {
	int count = 0;
	lookup_item *p;

	if (ctx == NULL) return 0;
	if (name == NULL) return 0;

	p = (lookup_item*)(void*) ctx->method_data;
	if (p == NULL) return 0;

	for (; p != NULL; p = p->next) {
		mystore *ls = p->db;
		X509_STORE *store = ctx->store_ctx;
		OSSL_STORE_SEARCH *search;

		if (ls->ctx == NULL)
			ls->ctx = OSSL_STORE_open(ls->url, NULL, NULL, NULL, NULL);
		if (ls->ctx == NULL) continue;

	{	int expected;
		switch(type) {
		case X509_LU_X509: expected = OSSL_STORE_INFO_CERT; break;
		case X509_LU_CRL: expected = OSSL_STORE_INFO_CRL; break;
		default: expected = -1; /*suppress warning*/
		}
		(void)OSSL_STORE_expect(ls->ctx, expected);
	}

		search = OSSL_STORE_SEARCH_by_name(name);
		OSSL_STORE_find(ls->ctx, search);

		while (!OSSL_STORE_eof(ls->ctx)) {
			OSSL_STORE_INFO *store_info;

			store_info = OSSL_STORE_load(ls->ctx);
			if (store_info == NULL) break;

			count += mystorelookup_data2store(type, name,
			    store_info, store)
			    ? 1 : 0;

			OSSL_STORE_INFO_free(store_info);
		}

		OSSL_STORE_SEARCH_free(search);
		OSSL_STORE_close(ls->ctx);
		ls->ctx = NULL;
	}

	if (count > 0) {
		X509_STORE *store = ctx->store_ctx;
		X509_OBJECT *tmp;

		X509_STORE_lock(store);
		{	STACK_OF(X509_OBJECT) *objs;
			objs = X509_STORE_get0_objects(store);
			tmp = X509_OBJECT_retrieve_by_subject(objs, type, name);
		}
		X509_STORE_unlock(store);

		if (tmp == NULL) {
			count = 0;
			goto done;
		}

		ret->type = tmp->type;
		memcpy(&ret->data, &tmp->data, sizeof(ret->data));
	}

done:
	return count > 0;
}
#else /*def USE_X509_LOOKUP_MYSTORE */

typedef int x509_by_sock_empty_translation_unit;

#endif
