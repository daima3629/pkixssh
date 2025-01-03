/*
 * Copyright (c) 2011-2025 Roumen Petrov.  All rights reserved.
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

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#ifdef USE_OPENSSL_STORE2
#define SSHKEY_INTERNAL
#include "includes.h"

#include <stdlib.h>

# include <openssl/store.h>

#include "key-eng.h"
#include "ssh-x509.h"
#include "log.h"
#include "ssherr.h"
#include "xmalloc.h"

extern UI_METHOD *ssh_ui_method;
extern char* ignore_suffixes(const char *filename);


struct STORE_KEY_DATA_st {
	EVP_PKEY *pk;
	STACK_OF(X509) *chain;
};
typedef struct STORE_KEY_DATA_st STORE_KEY_DATA;

static STORE_KEY_DATA*
STORE_KEY_DATA_new(void) {
	STORE_KEY_DATA* p;

	p = malloc(sizeof(STORE_KEY_DATA));
	if (p == NULL) return NULL;

	p->chain = sk_X509_new_null();
	if (p->chain == NULL) {
		free(p);
		return NULL;
	}

	p->pk = NULL;
	return p;
}

static void
STORE_KEY_DATA_free(STORE_KEY_DATA* p) {
	if (p == NULL) return;

	sk_X509_pop_free(p->chain, X509_free);
	EVP_PKEY_free(p->pk);
	free(p);
}


static STORE_KEY_DATA*
store_load_key(const char *url) {
	STORE_KEY_DATA *ret;
	OSSL_STORE_CTX *store_ctx;

	ret = STORE_KEY_DATA_new();
	if (ret == NULL) return NULL;

	store_ctx = OSSL_STORE_open(url, ssh_ui_method, NULL, NULL, NULL);
	debug3_f("ctx: %p", (void*)store_ctx);
	do_log_crypto_errors(SYSLOG_LEVEL_DEBUG3);
	if (store_ctx == NULL) goto done;

	while (!OSSL_STORE_eof(store_ctx) ) {
		OSSL_STORE_INFO *store_info;
		int info_type;

		store_info = OSSL_STORE_load(store_ctx);
		if (store_info == NULL) break;

		info_type = OSSL_STORE_INFO_get_type(store_info);
		debug3_f("type: %d", info_type);
		switch (info_type) {
		case OSSL_STORE_INFO_PKEY: {
			ret->pk = OSSL_STORE_INFO_get0_PKEY(store_info);
			EVP_PKEY_up_ref(ret->pk);
			} break;
		case OSSL_STORE_INFO_CERT: {
			X509 *x = OSSL_STORE_INFO_get0_CERT(store_info);
			X509_up_ref(x);
			sk_X509_insert(ret->chain, x, -1 /*last*/);
			} break;
		}
		OSSL_STORE_INFO_free(store_info);
	}
	do_log_crypto_errors(SYSLOG_LEVEL_DEBUG3);
	OSSL_STORE_close(store_ctx);

done:
	if (ret->pk == NULL) {
		STORE_KEY_DATA_free(ret);
		return NULL;
	}
	return ret;
}


static void
store_set_key_certs(STORE_KEY_DATA *kd, struct sshkey *key) {
	int n, len;
	X509 *x = NULL;

	len = sk_X509_num(kd->chain);
	if (len <= 0) return;

	for (n = 0; n < sk_X509_num(kd->chain); n++) {
		x = sk_X509_value(kd->chain, n);

		if (ssh_EVP_PKEY_eq(kd->pk, X509_get0_pubkey(x)) == 1)
			break;
	}
	if (n >= len) {
		debug3_f("no certificate that match private key");
		return;
	}

	x = sk_X509_delete(kd->chain, n);
	(void)ssh_x509_set_cert(key, x, kd->chain);
}


int
store_load_private(const char *name, const char *passphrase,
	struct sshkey **keyp, char **commentp
) {
	int ret;
	STORE_KEY_DATA *kd = NULL;
	struct sshkey *prv = NULL;

	UNUSED(passphrase);
	debug3_f("name=%s", name);

	if (keyp != NULL) *keyp = NULL;
	if (commentp != NULL) *commentp = NULL;

	kd = store_load_key(name);
	if (kd == NULL) {
		ret = SSH_ERR_KEY_NOT_FOUND;
		goto done;
	}

	ret = sshkey_from_pkey(kd->pk, &prv);
	if (ret != SSH_ERR_SUCCESS) goto done;

	store_set_key_certs(kd, prv);
	debug3("STORE private key type: %s", sshkey_type(prv));

	kd->pk = NULL; /* transferred */

	if (commentp != NULL)
		xasprintf(commentp, "store:%s", name);

	if (keyp != NULL) {
		*keyp = prv;
		prv = NULL;
	}

done:
	sshkey_free(prv);
	STORE_KEY_DATA_free(kd);
	return ret;
}


int
store_try_load_public(const char *name, struct sshkey **keyp, char **commentp) {
	int ret;
	const char *url = NULL;
	STORE_KEY_DATA *kd = NULL;
	struct sshkey *k = NULL;

	debug3_f("name=%s", name);
	if (keyp != NULL) *keyp = NULL;
	if (commentp != NULL) *commentp = NULL;

	url = ignore_suffixes(name);
/* NOTE: For external keys simulate "missing" file.
 * This suppress extra messages due to faulty load control in ssh.c
 */
	if (url == NULL) {
		errno = ENOENT;
		return SSH_ERR_SYSTEM_ERROR;
	}

	debug3_f("url=%s", url);

	kd = store_load_key(url);
	if (kd == NULL) {
		ret = SSH_ERR_KEY_NOT_FOUND;
		goto done;
	}

	ret = sshkey_from_pkey(kd->pk, &k);
	if (ret != SSH_ERR_SUCCESS) goto done;

	store_set_key_certs(kd, k);
	debug3("STORE public key type: %s", sshkey_type(k));

	kd->pk = NULL; /* transferred */

	if (commentp != NULL)
		xasprintf(commentp, "store:%s", url);

	if (keyp != NULL) {
		*keyp = k;
		k = NULL;
	}

done:
	sshkey_free(k);
	STORE_KEY_DATA_free(kd);
	free((void*)url);
	return ret;
}

#else /*ndef USE_OPENSSL_STORE2*/

typedef int key_store_empty_translation_unit;

#endif /*ndef USE_OPENSSL_STORE2*/
