/* $OpenBSD: kexecdh.c,v 1.10 2019/01/21 10:40:11 djm Exp $ */
/*
 * Copyright (c) 2010 Damien Miller.  All rights reserved.
 * Copyright (c) 2019 Markus Friedl.  All rights reserved.
 * Copyright (c) 2021-2024 Roumen Petrov.  All rights reserved.
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

#if defined(WITH_OPENSSL) && defined(OPENSSL_HAS_ECC)

#include <sys/types.h>

#include <stdio.h>
#include <string.h>
#include <signal.h>

#include <openssl/ecdh.h>

#include "sshkey.h"
#include "kex.h"
#include "sshbuf.h"
#include "digest.h"
#include "ssherr.h"

struct kex_ecdh_spec {
	int	ec_nid;
};

#ifdef USE_EVP_PKEY_KEYGEN
extern int /* see ssh-ecdsa.c */
ssh_pkey_keygen_ec(int nid, EVP_PKEY **ret);

static inline int
kex_ecdh_pkey_keygen(struct kex *kex) {
	struct kex_ecdh_spec *spec = kex->impl->spec;
	return ssh_pkey_keygen_ec(spec->ec_nid, &kex->pk);
}
#else /*ndef USE_EVP_PKEY_KEYGEN*/
static int
kex_ecdh_key_init(struct kex *kex) {
	struct kex_ecdh_spec *spec = kex->impl->spec;
	EC_KEY *ec = NULL;

	ec = EC_KEY_new_by_curve_name(spec->ec_nid);
	if (ec == NULL) return SSH_ERR_ALLOC_FAIL;

#if defined(OPENSSL_VERSION_NUMBER) && (OPENSSL_VERSION_NUMBER < 0x10100000L) || \
    defined(LIBRESSL_VERSION_NUMBER)
	/* see ssh-ecdsa.c */
	EC_KEY_set_asn1_flag(ec, OPENSSL_EC_NAMED_CURVE);
#endif

{	EVP_PKEY *pk = EVP_PKEY_new();
	if (pk == NULL) {
		EC_KEY_free(ec);
		return SSH_ERR_ALLOC_FAIL;
	}
	if (!EVP_PKEY_set1_EC_KEY(pk, ec)) {
		EC_KEY_free(ec);
		EVP_PKEY_free(pk);
		return SSH_ERR_LIBCRYPTO_ERROR;
	}
	EC_KEY_free(ec);
	kex->pk = pk;
}

	return 0;
}

static int
kex_ecdh_key_gen(struct kex *kex) {
	int r;
	EC_KEY *ec;

	if (kex->pk == NULL)
		return SSH_ERR_INVALID_ARGUMENT;

	ec = EVP_PKEY_get1_EC_KEY(kex->pk);
	if (ec == NULL)
		return SSH_ERR_INVALID_ARGUMENT;

	if (EC_KEY_generate_key(ec) == 0) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		goto done;
	}

	/* success */
	r = 0;

done:
	EC_KEY_free(ec);
	return r;
}

static inline int
kex_ecdh_pkey_keygen(struct kex *kex) {
	int r = kex_ecdh_key_init(kex);
	if (r != 0) return r;
	return kex_ecdh_key_gen(kex);
}
#endif /*ndef USE_EVP_PKEY_KEYGEN*/


#ifdef USE_EVP_PKEY_KEYGEN
static int
create_peer_pkey(struct kex *kex, const EC_POINT *dh_pub, EVP_PKEY **peerkeyp) {
	struct kex_ecdh_spec *spec = kex->impl->spec;
	EVP_PKEY *peerkey = NULL;
	EC_KEY *ec;
	int r = SSH_ERR_LIBCRYPTO_ERROR;

	ec = EC_KEY_new_by_curve_name(spec->ec_nid);
	if (ec == NULL) return SSH_ERR_ALLOC_FAIL;
	/* NOTE: named curve flag is not required */

	peerkey = EVP_PKEY_new();
	if (peerkey == NULL) {
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}

	if (EC_KEY_set_public_key(ec, dh_pub) != 1)
		goto out;

	if (!EVP_PKEY_set1_EC_KEY(peerkey, ec))
		goto out;

	*peerkeyp = peerkey;
	peerkey = NULL;
	r = 0;

 out:
	EC_KEY_free(ec);
	EVP_PKEY_free(peerkey);
	return r;
}
#endif /*def USE_EVP_PKEY_KEYGEN*/

static int
kex_ecdh_derive_shared_secret(struct kex *kex, const EC_POINT *dh_pub, struct sshbuf **bufp) {
#ifdef USE_EVP_PKEY_KEYGEN
	EVP_PKEY *peerkey = NULL;
	int r;

	r = create_peer_pkey(kex, dh_pub, &peerkey);
	if (r != 0) return r;

	r = kex_pkey_derive_shared_secret(kex, peerkey, 0, bufp);

	EVP_PKEY_free(peerkey);
#else /*ndef USE_EVP_PKEY_KEYGEN*/
	EC_KEY *key;
	const EC_GROUP *group;
	u_char *kbuf = NULL;
	size_t klen = 0;
	int r;

	if ((key = EVP_PKEY_get1_EC_KEY(kex->pk)) == NULL)
		return SSH_ERR_INVALID_ARGUMENT;

	if ((group = EC_KEY_get0_group(key)) == NULL) {
		r = SSH_ERR_INTERNAL_ERROR;
		goto out;
	}

	klen = (EC_GROUP_get_degree(group) + 7) / 8;
	if ((kbuf = malloc(klen)) == NULL) {
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}

	if (ECDH_compute_key(kbuf, klen, dh_pub, key, NULL) != (int)klen) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		goto out;
	}
#ifdef DEBUG_KEXECDH
	dump_digest("shared secret", kbuf, klen);
#endif

	r = kex_shared_secret_to_sshbuf(kbuf, klen, 0, bufp);

 out:
	EC_KEY_free(key);
	freezero(kbuf, klen);
#endif /*ndef USE_EVP_PKEY_KEYGEN*/
	return r;
}

static int
kex_ecdh_compute_key(struct kex *kex, const struct sshbuf *ec_blob,
    struct sshbuf **shared_secretp)
{
	EC_POINT *dh_pub = NULL;
	int r;

	r = sshbuf_to_ecpub(ec_blob, kex->pk, &dh_pub);
	if (r != 0) return r;

	/* ignore exact result from validation */
	if (ssh_EVP_PKEY_validate_public_ec(kex->pk, dh_pub) != 0) {
		r = SSH_ERR_MESSAGE_INCOMPLETE;
		goto out;
	}

	r = kex_ecdh_derive_shared_secret(kex, dh_pub, shared_secretp);

 out:
	EC_POINT_clear_free(dh_pub);
	return r;
}

static int
kex_ecdh_to_sshbuf(struct kex *kex, struct sshbuf **bufp) {
	EC_KEY *key;
	struct sshbuf *buf;
	int r;

	*bufp = NULL;

	if ((key = EVP_PKEY_get1_EC_KEY(kex->pk)) == NULL)
		return SSH_ERR_INVALID_ARGUMENT;
#ifdef DEBUG_KEXECDH
	fputs("ecdh private key:\n", stderr);
	EC_KEY_print_fp(stderr, key, 0);
#endif
	if ((buf = sshbuf_new()) == NULL)
		return SSH_ERR_ALLOC_FAIL;

	if ((r = sshbuf_put_eckey(buf, key)) != 0 ||
	    (r = sshbuf_get_u32(buf, NULL)) != 0)
		goto out;

	*bufp = buf;
	buf = NULL;

 out:
	EC_KEY_free(key);
	sshbuf_free(buf);
	return r;
}


/* elliptic-curve diffie-hellman key exchange implementation */

static int
kex_ecdh_keypair(struct kex *kex)
{
	int r;

	if ((r = kex_ecdh_pkey_keygen(kex)) != 0)
		goto out;

	r = kex_ecdh_to_sshbuf(kex, &kex->client_pub);
#ifdef DEBUG_KEXECDH
	dump_digestb("client public keypair ecdh:", kex->client_pub);
#endif

 out:
	if (r != 0)
		kex_reset_keys(kex);
	return r;
}

static int
kex_ecdh_enc(struct kex *kex, const struct sshbuf *client_blob,
    struct sshbuf **server_blobp, struct sshbuf **shared_secretp)
{
	int r;

	*server_blobp = NULL;
	*shared_secretp = NULL;

#ifdef DEBUG_KEXECDH
	dump_digestb("client public key ecdh:", client_blob);
#endif
	if ((r = kex_ecdh_pkey_keygen(kex)) != 0 ||
	    (r = kex_ecdh_to_sshbuf(kex, server_blobp)) != 0)
		goto out;

	r = kex_ecdh_compute_key(kex, client_blob, shared_secretp);

 out:
	kex_reset_keys(kex);
	if (r != 0) {
		sshbuf_free(*server_blobp);
		*server_blobp = NULL;
	}
	return r;
}

static int
kex_ecdh_dec(struct kex *kex, const struct sshbuf *server_blob,
    struct sshbuf **shared_secretp)
{
	int r;

	*shared_secretp = NULL;
#ifdef DEBUG_KEXECDH
	dump_digestb("server public key ecdh:", server_blob);
#endif

	r = kex_ecdh_compute_key(kex, server_blob, shared_secretp);
#ifdef DEBUG_KEXECDH
	if (r == 0)
		dump_digestb("encoded shared secret:", *shared_secretp);
#endif

	kex_reset_keys(kex);
	return r;
}

static int kex_ecdh_enabled(void) { return 1; }

static const struct kex_impl_funcs kex_ecdh_funcs = {
	kex_init_gen,
	kex_ecdh_keypair,
	kex_ecdh_enc,
	kex_ecdh_dec
};

static struct kex_ecdh_spec kex_ecdh_p256_spec = {
	NID_X9_62_prime256v1
};
const struct kex_impl kex_ecdh_p256_sha256_impl = {
	"ecdh-sha2-nistp256",
	SSH_DIGEST_SHA256,
	kex_ecdh_enabled,
	&kex_ecdh_funcs,
	&kex_ecdh_p256_spec
};

static struct kex_ecdh_spec kex_ecdh_p384_spec = {
	NID_secp384r1
};
const struct kex_impl kex_ecdh_p384_sha384_impl = {
	"ecdh-sha2-nistp384",
	SSH_DIGEST_SHA384,
	kex_ecdh_enabled,
	&kex_ecdh_funcs,
	&kex_ecdh_p384_spec
};

# ifdef OPENSSL_HAS_NISTP521
static int kex_ecdh_p521_enabled(void) { return 1; }

static struct kex_ecdh_spec kex_ecdh_p521_spec = {
	NID_secp521r1
};
const struct kex_impl kex_ecdh_p521_sha512_impl = {
	"ecdh-sha2-nistp521",
	SSH_DIGEST_SHA512,
	kex_ecdh_p521_enabled,
	&kex_ecdh_funcs,
	&kex_ecdh_p521_spec
};
# endif /* OPENSSL_HAS_NISTP521 */

#endif /* defined(WITH_OPENSSL) && defined(OPENSSL_HAS_ECC) */
