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

static int
kex_key_init_ecdh(struct kex *kex) {
	EC_KEY *ec = NULL;

	ec = EC_KEY_new_by_curve_name(kex->ec_nid);
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
kex_key_gen_ecdh(struct kex *kex) {
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

static int
derive_ecdh_shared_secret(const EC_POINT *dh_pub, const EC_KEY *key, struct sshbuf *buf) {
	const EC_GROUP *group;
	BIGNUM *shared_secret = NULL;
	u_char *kbuf = NULL;
	size_t klen = 0;
	int r;

	if ((group = EC_KEY_get0_group(key)) == NULL)
		return SSH_ERR_INTERNAL_ERROR;

	klen = (EC_GROUP_get_degree(group) + 7) / 8;
	if ((kbuf = malloc(klen)) == NULL ||
	    (shared_secret = BN_new()) == NULL) {
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}

	if (ECDH_compute_key(kbuf, klen, dh_pub, key, NULL) != (int)klen ||
	    BN_bin2bn(kbuf, klen, shared_secret) == NULL) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		goto out;
	}
#ifdef DEBUG_KEXECDH
	dump_digest("shared secret", kbuf, klen);
#endif

	r = sshbuf_put_bignum2(buf, shared_secret);

 out:
	BN_clear_free(shared_secret);
	freezero(kbuf, klen);
	return r;
}

static int
kex_ecdh_compute_key(struct kex *kex, const struct sshbuf *ec_blob,
    struct sshbuf **shared_secretp)
{
	EC_KEY *key;
	struct sshbuf *buf = NULL;
	EC_POINT *dh_pub = NULL;
	int r;

	*shared_secretp = NULL;

	if ((key = EVP_PKEY_get1_EC_KEY(kex->pk)) == NULL)
		return SSH_ERR_INVALID_ARGUMENT;
	if ((buf = sshbuf_new()) == NULL)
		return SSH_ERR_ALLOC_FAIL;

	r = sshbuf_put_stringb(buf, ec_blob);
	if (r != 0) goto out;

	r = sshbuf_get_ecpub(buf, key, &dh_pub);
	if (r != 0) goto out;

	sshbuf_reset(buf);

	/* ignore exact result from validation */
	if (ssh_EVP_PKEY_validate_public_ec(kex->pk, dh_pub) != 0) {
		r = SSH_ERR_MESSAGE_INCOMPLETE;
		goto out;
	}

	r = derive_ecdh_shared_secret(dh_pub, key, buf);
	if (r != 0) goto out;

	*shared_secretp = buf;
	buf = NULL;
 out:
	EC_KEY_free(key);
	EC_POINT_clear_free(dh_pub);
	sshbuf_free(buf);
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


int
kex_ecdh_keypair(struct kex *kex)
{
	int r;

	if ((r = kex_key_init_ecdh(kex)) != 0 ||
	    (r = kex_key_gen_ecdh(kex)) != 0)
		goto out;

	r = kex_ecdh_to_sshbuf(kex, &kex->client_pub);

 out:
	if (r != 0)
		kex_reset_crypto_keys(kex);
	return r;
}

int
kex_ecdh_enc(struct kex *kex, const struct sshbuf *client_blob,
    struct sshbuf **server_blobp, struct sshbuf **shared_secretp)
{
	int r;

	*server_blobp = NULL;
	*shared_secretp = NULL;

	if ((r = kex_key_init_ecdh(kex)) != 0 ||
	    (r = kex_key_gen_ecdh(kex)) != 0 ||
	    (r = kex_ecdh_to_sshbuf(kex, server_blobp)) != 0)
		goto out;

	r = kex_ecdh_compute_key(kex, client_blob, shared_secretp);

 out:
	if (r != 0) {
		sshbuf_free(*server_blobp);
		*server_blobp = NULL;
	}
	kex_reset_crypto_keys(kex);
	return r;
}

int
kex_ecdh_dec(struct kex *kex, const struct sshbuf *server_blob,
    struct sshbuf **shared_secretp)
{
	int r;

	r = kex_ecdh_compute_key(kex, server_blob, shared_secretp);

	kex_reset_crypto_keys(kex);
	return r;
}
#endif /* defined(WITH_OPENSSL) && defined(OPENSSL_HAS_ECC) */
