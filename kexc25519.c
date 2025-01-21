/* $OpenBSD: kexc25519.c,v 1.18 2024/09/02 12:13:56 djm Exp $ */
/*
 * Copyright (c) 2019 Markus Friedl.  All rights reserved.
 * Copyright (c) 2010 Damien Miller.  All rights reserved.
 * Copyright (c) 2013 Aris Adamantiadis.  All rights reserved.
 * Copyright (c) 2024 Roumen Petrov.  All rights reserved.
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

#include <sys/types.h>

#include <stdio.h>
#include <string.h>

#include "kex.h"
#include "digest.h"
#ifdef ENABLE_ECDH_C25519
#include "sshkey.h"
#include "sshbuf.h"
#include "ssherr.h"
#include "ssh2.h"

#ifndef USE_ECDH_X25519
extern int crypto_scalarmult_curve25519(u_char a[CURVE25519_SIZE],
    const u_char b[CURVE25519_SIZE], const u_char c[CURVE25519_SIZE])
	__attribute__((__bounded__(__minbytes__, 1, CURVE25519_SIZE)))
	__attribute__((__bounded__(__minbytes__, 2, CURVE25519_SIZE)))
	__attribute__((__bounded__(__minbytes__, 3, CURVE25519_SIZE)));
#endif

#ifdef USE_ECDH_X25519
static int
kexc25519_keygen_crypto(struct kex *kex, u_char pub[CURVE25519_SIZE]) {
	EVP_PKEY *pk = NULL;
	size_t len;
	int r;

	r = ssh_pkey_keygen_simple(EVP_PKEY_X25519, &pk);
	if (r != 0) return r;

	/* compatibility: fill data used by build-in implementation */
	len = CURVE25519_SIZE;
	if (EVP_PKEY_get_raw_public_key(pk, pub, &len) != 1 &&
	    len != CURVE25519_SIZE) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		goto err;
	}

	kex->pk = pk;
	pk = NULL;
err:
	EVP_PKEY_free(pk);
	return r;
}
#endif /*def USE_ECDH_X25519*/

#ifndef USE_ECDH_X25519
static int
kexc25519_keygen_buildin(struct kex *kex, u_char pub[CURVE25519_SIZE]
) {
	static const u_char basepoint[CURVE25519_SIZE] = {9};

	arc4random_buf(kex->c25519_key, CURVE25519_SIZE);
	crypto_scalarmult_curve25519(pub, kex->c25519_key, basepoint);
	return 0;
}
#endif /*ndef USE_ECDH_X25519*/

int
kex_c25519_keygen_to_sshbuf(struct kex *kex, struct sshbuf **bufp) {
	struct sshbuf *buf = NULL;
	u_char pub[CURVE25519_SIZE];
	int r;

	if (*bufp == NULL) {
		buf = sshbuf_new();
		if (buf == NULL) return SSH_ERR_ALLOC_FAIL;
	} else
		buf = *bufp;

#ifdef USE_ECDH_X25519
	/*TODO: FIPS mode?*/
	r = kexc25519_keygen_crypto(kex, pub);
#else
	r = kexc25519_keygen_buildin(kex, pub);
#endif
	if (r != 0) goto out;

#ifdef DEBUG_KEXECDH
	if (kex->server)
		dump_digest("server public key 25519:", pub, CURVE25519_SIZE);
	else
		dump_digest("client public key 25519:", pub, CURVE25519_SIZE);
#endif
	r = sshbuf_put(buf, pub, CURVE25519_SIZE);
	if (r != 0)
		kex_reset_keys(kex);

out:
	if (*bufp == NULL) {
		if (r == 0)
			*bufp = buf;
		else
			sshbuf_free(buf);
	}
	return r;
}

#ifdef USE_ECDH_X25519
static int
kex_c25519_derive_shared_secret(struct kex *kex,
    const u_char pub[CURVE25519_SIZE], int raw, struct sshbuf **bufp
) {
	EVP_PKEY *peerkey = NULL;
	int r;

	peerkey = EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, NULL,
	    pub, CURVE25519_SIZE);
	if (peerkey == NULL)
		return SSH_ERR_INVALID_FORMAT;

	r = kex_pkey_derive_shared_secret(kex, peerkey, raw, bufp);

	EVP_PKEY_free(peerkey);
	return r;
}
#endif /*def USE_ECDH_X25519*/

#ifndef USE_ECDH_X25519
static int
kex_c25519_shared_key_ext(struct kex *kex,
    const u_char pub[CURVE25519_SIZE], struct sshbuf *out, int raw)
{
	const u_char *key = kex->c25519_key;
	u_char shared_key[CURVE25519_SIZE];
	u_char zero[CURVE25519_SIZE];
	int r;

	crypto_scalarmult_curve25519(shared_key, key, pub);

	/* Check for all-zero shared secret */
	explicit_bzero(zero, CURVE25519_SIZE);
	if (timingsafe_bcmp(zero, shared_key, CURVE25519_SIZE) == 0)
		return SSH_ERR_KEY_INVALID_EC_VALUE;

#ifdef DEBUG_KEXECDH
	dump_digest("shared secret", shared_key, CURVE25519_SIZE);
#endif

	r = kex_shared_secret_to_sshbuf(shared_key, CURVE25519_SIZE, raw, &out);

	explicit_bzero(shared_key, CURVE25519_SIZE);
	return r;
}
#endif /*ndef USE_ECDH_X25519*/

int
kex_c25519_shared_secret_to_sshbuf(struct kex *kex, const u_char pub[CURVE25519_SIZE],
    int raw, struct sshbuf **bufp) {
	struct sshbuf *buf;
	int r;

	if (*bufp == NULL) {
		buf = sshbuf_new();
		if (buf == NULL) return SSH_ERR_ALLOC_FAIL;
	} else
		buf = *bufp;

#ifdef USE_ECDH_X25519
	r = kex_c25519_derive_shared_secret(kex, pub, raw, &buf);
#else
	r = kex_c25519_shared_key_ext(kex, pub, buf, raw);
#endif

	if (*bufp == NULL) {
		if (r == 0)
			*bufp = buf;
		else
			sshbuf_free(buf);
	}
	return r;
}

#ifndef USE_ECDH_X25519
static inline int
kex_c25519_mpint_shared_secret_to_sshbuf(struct kex *kex,
    const struct sshbuf *blob, struct sshbuf **bufp
) {
	const u_char *pub = sshbuf_ptr(blob);
	return kex_c25519_shared_secret_to_sshbuf(kex, pub, 0, bufp);
}
#endif /*ndef USE_ECDH_X25519*/

#ifndef USE_ECDH_X25519	/*use build-in*/
/* curve25519 key exchange implementation */

static int
kex_c25519_keypair(struct kex *kex)
{
	return kex_c25519_keygen_to_sshbuf(kex, &kex->client_pub);
}

static int
kex_c25519_enc(struct kex *kex, const struct sshbuf *client_blob,
   struct sshbuf **server_blobp, struct sshbuf **shared_secretp)
{
	int r;

	*server_blobp = NULL;
	*shared_secretp = NULL;

	if (sshbuf_len(client_blob) != CURVE25519_SIZE) {
		r = SSH_ERR_SIGNATURE_INVALID;
		goto out;
	}
#ifdef DEBUG_KEXECDH
	dump_digestb("client public key c25519:", client_blob);
#endif

	r = kex_c25519_keygen_to_sshbuf(kex, server_blobp);
	if (r != 0) goto out;

	r = kex_c25519_mpint_shared_secret_to_sshbuf(kex, client_blob, shared_secretp);
	if (r != 0) goto out;
#ifdef DEBUG_KEXECDH
	dump_digestb("encoded shared secret:", *shared_secretp);
#endif

 out:
	kex_reset_keys(kex);
	if (r != 0) {
		sshbuf_free(*server_blobp);
		*server_blobp = NULL;
	}
	return r;
}

static int
kex_c25519_dec(struct kex *kex, const struct sshbuf *server_blob,
    struct sshbuf **shared_secretp)
{
	int r;

	*shared_secretp = NULL;

	if (sshbuf_len(server_blob) != CURVE25519_SIZE) {
		r = SSH_ERR_SIGNATURE_INVALID;
		goto out;
	}
#ifdef DEBUG_KEXECDH
	dump_digestb("server public key c25519:", server_blob);
#endif
	r = kex_c25519_mpint_shared_secret_to_sshbuf(kex, server_blob, shared_secretp);
	if (r != 0) goto out;
#ifdef DEBUG_KEXECDH
	dump_digestb("encoded shared secret:", *shared_secretp);
#endif

 out:
	kex_reset_keys(kex);
	return r;
}

static int kex_c25519_enabled(void) { return 1; }

static const struct kex_impl_funcs kex_c25519_funcs = {
	kex_init_gen,
	kex_c25519_keypair,
	kex_c25519_enc,
	kex_c25519_dec
};

const struct kex_impl kex_c25519_sha256_impl = {
	"curve25519-sha256",
	SSH_DIGEST_SHA256,
	kex_c25519_enabled,
	&kex_c25519_funcs,
	NULL
};

const struct kex_impl kex_c25519_sha256_impl_ext = {
	"curve25519-sha256@libssh.org",
	SSH_DIGEST_SHA256,
	kex_c25519_enabled,
	&kex_c25519_funcs,
	NULL
};
#endif /*ndef USE_ECDH_X25519*/
#else /*ndef ENABLE_ECDH_C25519*/

static int kex_c25519_enabled(void) { return 0; }
const struct kex_impl kex_c25519_sha256_impl = {
	"curve25519-sha256", SSH_DIGEST_SHA256,
	kex_c25519_enabled, NULL, NULL
};
const struct kex_impl kex_c25519_sha256_impl_ext = {
	"curve25519-sha256@libssh.org", SSH_DIGEST_SHA256,
	kex_c25519_enabled, NULL, NULL
};

#endif /*ndef ENABLE_ECDH_C25519*/
