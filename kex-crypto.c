/*
 * Copyright (c) 2021-2025 Roumen Petrov.  All rights reserved.
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

#ifndef USE_OPENSSL_PROVIDER
/* TODO: implement OpenSSL 4.0 API, as OpenSSL 3.* is quite nonfunctional */
# define OPENSSL_SUPPRESS_DEPRECATED
#endif

#define SSHKEY_INTERNAL
#include "includes.h"

#ifdef WITH_OPENSSL
#include "evp-compat.h"

#include "kex.h"
#include "ssherr.h"
#include "misc.h"
#include "log.h"


extern void/*internal*/
kex_reset_crypto_keys(struct kex *kex);

void
kex_reset_crypto_keys(struct kex *kex) {
	EVP_PKEY_free(kex->pk);
	kex->pk = NULL;
}


#ifdef USE_EVP_PKEY_KEYGEN
int
kex_pkey_derive_shared_secret_raw(struct kex *kex, EVP_PKEY *peerkey,
    u_char **kbufp, size_t *klenp
) {
	EVP_PKEY_CTX *ctx;
	u_char *kbuf = NULL;
	size_t klen = 0;
	int r = SSH_ERR_LIBCRYPTO_ERROR;

	ctx = EVP_PKEY_CTX_new(kex->pk, NULL);
	if (ctx == NULL) return SSH_ERR_INTERNAL_ERROR;

	if (EVP_PKEY_derive_init(ctx) != 1)
		goto out;

	if (EVP_PKEY_derive_set_peer(ctx, peerkey) != 1)
		goto out;

	if (EVP_PKEY_derive(ctx, NULL, &klen) != 1)
		goto out;
	kbuf = OPENSSL_malloc(klen);
	if (kbuf == NULL) {
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	if (EVP_PKEY_derive(ctx, kbuf, &klen) != 1) {
		OPENSSL_free(kbuf);
		goto out;
	}
#if defined(DEBUG_KEX) || defined(DEBUG_KEXDH) || defined(DEBUG_KEXECDH) || \
    defined(DEBUG_KEXECX) || defined(DEBUG_KEXKEM)
	dump_digest("shared secret", kbuf, klen);
#endif

	*klenp = klen;
	*kbufp = kbuf;
	r = 0;

 out:
	EVP_PKEY_CTX_free(ctx);
	return r;
}
#endif /*def USE_EVP_PKEY_KEYGEN*/


#ifdef USE_EVP_PKEY_KEYGEN
int
kex_pkey_derive_shared_secret(struct kex *kex, EVP_PKEY *peerkey,
    int raw, struct sshbuf **bufp
) {
	u_char *kbuf = NULL;
	size_t klen = 0;
	int r = SSH_ERR_LIBCRYPTO_ERROR;

	r =  kex_pkey_derive_shared_secret_raw(kex, peerkey,
	    &kbuf, &klen);
	if (r != 0) goto out;

	r = kex_shared_secret_to_sshbuf(kbuf, klen, raw, bufp);

 out:
	OPENSSL_clear_free(kbuf, klen);
	return r;
}
#endif /*def USE_EVP_PKEY_KEYGEN*/
#else

typedef int kex_crypto_empty_translation_unit;

#endif /* WITH_OPENSSL */
