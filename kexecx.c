/*
 * Copyright (c) 2024-2025 Roumen Petrov.  All rights reserved.
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

#undef USE_KEX_ECX
#if defined(USE_ECDH_X448) || defined(USE_ECDH_X25519)
# define USE_KEX_ECX
#endif

#include <sys/types.h>

#include <stdlib.h>

#include "kex.h"
#include "digest.h"
#ifdef USE_KEX_ECX
#include "sshbuf.h"
#include "ssherr.h"

struct kex_ecx_spec {
	int key_id;
	size_t pub_len;
};

/* generate key and store public part to buffer */
int
kex_ecx_keygen_to_sshbuf(struct kex *kex, int key_id, size_t pub_len,
    struct sshbuf **bufp
) {
	EVP_PKEY *pk = NULL;
	u_char *pub = NULL;
	struct sshbuf *buf;
	int r;

	if (*bufp == NULL) {
		buf = sshbuf_new();
		if (buf == NULL) return SSH_ERR_ALLOC_FAIL;
	} else
		buf = *bufp;

	/*TODO: FIPS mode?*/
	r = ssh_pkey_keygen_simple(key_id, &pk);
	if (r != 0) goto err;

	pub = malloc(pub_len);
	if (pub == NULL) {
		r = SSH_ERR_ALLOC_FAIL;
		goto err;
	}

	/* extra control */
{	size_t len = pub_len;
	if (EVP_PKEY_get_raw_public_key(pk, pub, &len) != 1 &&
	    len != pub_len) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		goto err;
	}
}
#ifdef DEBUG_KEXECX
	if (kex->server)
		dump_digest("server ecx public key:", pub, pub_len);
	else
		dump_digest("client ecx public key:", pub, pub_len);
#endif

	r = sshbuf_put(buf, pub, pub_len);
	if (r != 0) goto err;

	kex->pk = pk;
	pk = NULL;

err:
	free(pub);
	EVP_PKEY_free(pk);
	if (*bufp == NULL) {
		if (r == 0)
			*bufp = buf;
		else
			sshbuf_free(buf);
	}
	return r;
}

int
kex_ecx_shared_secret_to_sshbuf(struct kex *kex, int key_id,
    const u_char *kbuf, size_t klen, int raw, struct sshbuf **bufp
) {
	EVP_PKEY *peerkey = NULL;
	int r;

	peerkey = EVP_PKEY_new_raw_public_key(key_id, NULL, kbuf, klen);
	if (peerkey == NULL)
		return SSH_ERR_INVALID_FORMAT;

	r = kex_pkey_derive_shared_secret(kex, peerkey, raw, bufp);

	EVP_PKEY_free(peerkey);
	return r;
}

/* ECDH X... key exchange implementation */

static int
kex_ecx_keypair(struct kex *kex)
{
	struct kex_ecx_spec *spec = kex->impl->spec;
	return kex_ecx_keygen_to_sshbuf(kex, spec->key_id, spec->pub_len,
	    &kex->client_pub);
}

static int
kex_ecx_enc(struct kex *kex, const struct sshbuf *client_blob,
   struct sshbuf **server_blobp, struct sshbuf **shared_secretp)
{
	struct kex_ecx_spec *spec = kex->impl->spec;
	int r;

	*server_blobp = NULL;
	*shared_secretp = NULL;

	if (sshbuf_len(client_blob) != spec->pub_len) {
		r = SSH_ERR_SIGNATURE_INVALID;
		goto out;
	}
#ifdef DEBUG_KEXECX
	dump_digestb("client ecx public key:", client_blob);
#endif

	r = kex_ecx_keygen_to_sshbuf(kex, spec->key_id, spec->pub_len,
	    server_blobp);
	if (r != 0) goto out;

	r = kex_ecx_shared_secret_to_sshbuf(kex, spec->key_id,
	    sshbuf_ptr(client_blob), sshbuf_len(client_blob), 0, shared_secretp);
	if (r != 0) goto out;
#ifdef DEBUG_KEXECX
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
kex_ecx_dec(struct kex *kex, const struct sshbuf *server_blob,
    struct sshbuf **shared_secretp)
{
	struct kex_ecx_spec *spec = kex->impl->spec;
	int r;

	*shared_secretp = NULL;

	if (sshbuf_len(server_blob) != spec->pub_len) {
		r = SSH_ERR_SIGNATURE_INVALID;
		goto out;
	}
#ifdef DEBUG_KEXECX
	dump_digestb("server ecx public key:", server_blob);
#endif

	r = kex_ecx_shared_secret_to_sshbuf(kex, spec->key_id,
	    sshbuf_ptr(server_blob), sshbuf_len(server_blob), 0, shared_secretp);
	if (r != 0) goto out;
#ifdef DEBUG_KEXECX
	dump_digestb("encoded shared secret:", *shared_secretp);
#endif

 out:
	kex_reset_keys(kex);
	return r;
}


static const struct kex_impl_funcs kex_ecx_funcs = {
	kex_init_gen,
	kex_ecx_keypair,
	kex_ecx_enc,
	kex_ecx_dec
};
#endif /*ndef USE_KEX_ECX*/

#ifdef USE_ECDH_X25519
/* kexc25519.c, failback */
static int kex_c25519_enabled(void) {
	return ssh_pkey_allowed(EVP_PKEY_X25519);
}

static struct kex_ecx_spec kex_c25519_spec = {
	EVP_PKEY_X25519, 32
};
const struct kex_impl kex_c25519_sha256_impl = {
	"curve25519-sha256",
	SSH_DIGEST_SHA256,
	kex_c25519_enabled,
	&kex_ecx_funcs,
	&kex_c25519_spec
};
const struct kex_impl kex_c25519_sha256_impl_ext = {
	"curve25519-sha256@libssh.org",
	SSH_DIGEST_SHA256,
	kex_c25519_enabled,
	&kex_ecx_funcs,
	&kex_c25519_spec
};
#endif /*def USE_ECDH_X25519*/

#ifdef USE_ECDH_X448
static int kex_c448_enabled(void) {
	return ssh_pkey_allowed(EVP_PKEY_X448);
}

static struct kex_ecx_spec kex_c448_spec = {
	EVP_PKEY_X448, 56
};
const struct kex_impl kex_c448_sha512_impl = {
	"curve448-sha512",
	SSH_DIGEST_SHA512,
	kex_c448_enabled,
	&kex_ecx_funcs,
	&kex_c448_spec
};
#else /*ndef USE_ECDH_X448*/
static int kex_c448_enabled(void) { return 0; }
const struct kex_impl kex_c448_sha512_impl = {
	"curve448-sha512", SSH_DIGEST_SHA512,
	kex_c448_enabled, NULL, NULL
};
#endif /*ndef USE_ECDH_X448*/
