/* $OpenBSD: ssh-ed25519.c,v 1.19 2022/10/28 00:44:44 djm Exp $ */
/*
 * Copyright (c) 2013 Markus Friedl <markus@openbsd.org>
 * Copyright (c) 2022 Roumen Petrov.  All rights reserved.
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include "includes.h"

#include <sys/types.h>
#include <limits.h>

#include "crypto_api.h"

#include <string.h>
#include <stdarg.h>

#include "evp-compat.h"

#include "log.h"
#include "sshbuf.h"
#define SSHKEY_INTERNAL
#include "sshkey.h"
#include "ssherr.h"
#include "ssh.h"

static int
sshbuf_read_pub_ed25519(struct sshbuf *buf, struct sshkey *key) {
	int r;
	u_char *ed25519_pk = NULL;
	size_t pklen = 0;

	r = sshbuf_get_string(buf, &ed25519_pk, &pklen);
	if (r != 0) goto err;

	if (pklen != ED25519_PK_SZ) {
		r = SSH_ERR_INVALID_FORMAT;
		goto err;
	}

#ifdef OPENSSL_HAS_ED25519
{	EVP_PKEY *pk = EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, NULL, ed25519_pk, pklen);
	if (pk == NULL) {
		r = SSH_ERR_INVALID_FORMAT;
		goto err;
	}
	key->pk = pk;
}
#endif
	key->ed25519_pk = ed25519_pk;
	ed25519_pk = NULL; /* transferred */

err:
	freezero(ed25519_pk, pklen);
	return r;
}

static inline int
sshbuf_write_pub_ed25519(struct sshbuf *buf, const struct sshkey *key) {
	return sshbuf_put_string(buf, key->ed25519_pk, ED25519_PK_SZ);
}


static int
sshbuf_read_priv_ed25519(struct sshbuf *buf, struct sshkey *key) {
	int r;
	u_char *ed25519_sk = NULL;
	size_t sklen = 0;

	r = sshbuf_get_string(buf, &ed25519_sk, &sklen);
	if (r != 0) goto err;

	if (sklen != ED25519_SK_SZ) {
		r = SSH_ERR_INVALID_FORMAT;
		goto err;
	}

#ifdef OPENSSL_HAS_ED25519
{	EVP_PKEY *pk = EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, NULL,
	    ed25519_sk, sklen - ED25519_PK_SZ);
	if (pk == NULL) {
		r = SSH_ERR_INVALID_FORMAT;
		goto err;
	}
	if (key->pk != NULL) {
		/* TODO match public vs private ? */
		if (ssh_EVP_PKEY_eq(key->pk, pk) != 1) {
			EVP_PKEY_free(pk);
			r = SSH_ERR_INVALID_ARGUMENT;
			goto err;
		}
		EVP_PKEY_free(key->pk);
	}
	key->pk = pk;
}
#endif
	key->ed25519_sk = ed25519_sk;
	ed25519_sk = NULL; /* transferred */

err:
	freezero(ed25519_sk, sklen);
	return r;
}

static inline int
sshbuf_write_priv_ed25519(struct sshbuf *buf, const struct sshkey *key) {
	return sshbuf_put_string(buf, key->ed25519_sk, ED25519_SK_SZ);
}


/* key implementation */

static u_int
ssh_ed25519_size(const struct sshkey *key)
{
#ifdef WITH_OPENSSL
	if (key->pk != NULL) {
		/* work-around, see OpenSSL issue #19070:
		 * 253 in OpenSSL 1.1.1
		 * 253 in OpenSSL 3.0 for non provider keys
		return EVP_PKEY_bits(key->pk);
		 */
		return 256;
	}
#endif
	return 256;
}

static void
ssh_ed25519_cleanup(struct sshkey *k)
{
#ifdef OPENSSL_HAS_ED25519
	sshkey_clear_pkey(k);
#endif
	freezero(k->ed25519_pk, ED25519_PK_SZ);
	k->ed25519_pk = NULL;
	freezero(k->ed25519_sk, ED25519_SK_SZ);
	k->ed25519_sk = NULL;
}

static int
ssh_ed25519_equal(const struct sshkey *a, const struct sshkey *b)
{
	if (a->ed25519_pk == NULL || b->ed25519_pk == NULL)
		return 0;
	if (memcmp(a->ed25519_pk, b->ed25519_pk, ED25519_PK_SZ) != 0)
		return 0;
	return 1;
}

static int
ssh_ed25519_serialize_public(const struct sshkey *key, struct sshbuf *buf,
    enum sshkey_serialize_rep opts)
{
	UNUSED(opts);
	if (key->ed25519_pk == NULL)
		return SSH_ERR_INVALID_ARGUMENT;

	return sshbuf_write_pub_ed25519(buf, key);
}

static int
ssh_ed25519_serialize_private(const struct sshkey *key, struct sshbuf *buf,
    enum sshkey_serialize_rep opts)
{
	int r;

	UNUSED(opts);
	/* NOTE !cert */
	if ((r = sshbuf_write_pub_ed25519(buf, key)) != 0)
		return r;
	return sshbuf_write_priv_ed25519(buf, key);
}

#ifdef USE_EVP_PKEY_KEYGEN
static int
ssh_pkey_keygen_ed25519(EVP_PKEY **ret) {
	EVP_PKEY *pk = NULL;
	EVP_PKEY_CTX *ctx = NULL;
	int r;

	ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_ED25519, NULL);
	if (ctx == NULL) return SSH_ERR_ALLOC_FAIL;

	if (EVP_PKEY_keygen_init(ctx) <= 0) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		goto err;
	}

	if (EVP_PKEY_keygen(ctx, &pk) <= 0) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		goto err;
	}

	/* success */
	*ret = pk;
	r = 0;

err:
	EVP_PKEY_CTX_free(ctx);
	return r;
}
#endif

static int
ssh_ed25519_generate(struct sshkey *key, int bits) {
	UNUSED(bits);

#ifdef USE_EVP_PKEY_KEYGEN
{	EVP_PKEY *pk = NULL;
	size_t len;
	size_t slen;
	int r = 0;

	r = ssh_pkey_keygen_ed25519(&pk);
	if (r != 0) return r;

	if ((key->ed25519_pk = malloc(ED25519_PK_SZ)) == NULL ||
	    (key->ed25519_sk = malloc(ED25519_SK_SZ)) == NULL) {
		r = SSH_ERR_ALLOC_FAIL;
		goto err;
	}

	len = ED25519_PK_SZ;
	if (EVP_PKEY_get_raw_public_key(pk, key->ed25519_pk, &len) != 1 &&
	   len != ED25519_PK_SZ) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		goto err;
	}
	len = slen = ED25519_SK_SZ - ED25519_PK_SZ;
	if (EVP_PKEY_get_raw_private_key(pk, key->ed25519_sk, &len) != 1 &&
	   len != slen) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		goto err;
	}
	memcpy(key->ed25519_sk + slen, key->ed25519_pk, ED25519_PK_SZ);

	key->pk = pk;
	pk = NULL;
err:
	EVP_PKEY_free(pk);
}
#else /* ndef USE_EVP_PKEY_KEYGEN */
	if ((key->ed25519_pk = malloc(ED25519_PK_SZ)) == NULL ||
	    (key->ed25519_sk = malloc(ED25519_SK_SZ)) == NULL)
		return SSH_ERR_ALLOC_FAIL;
	crypto_sign_ed25519_keypair(key->ed25519_pk, key->ed25519_sk);
#ifdef OPENSSL_HAS_ED25519
	key->pk = EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, NULL,
	    key->ed25519_sk, ED25519_SK_SZ - ED25519_PK_SZ);
	if (key->pk == NULL)
		return SSH_ERR_LIBCRYPTO_ERROR;
#endif
#endif /* ndef USE_EVP_PKEY_KEYGEN */
	return 0;
}

static void
ssh_ed25519_move_public(struct sshkey *from, struct sshkey *to) {
#ifdef OPENSSL_HAS_ED25519
	sshkey_move_pk(from, to);
#endif
	freezero(to->ed25519_pk, ED25519_PK_SZ);
	to->ed25519_pk = from->ed25519_pk;
	from->ed25519_pk = NULL;
}

static int
ssh_ed25519_copy_public(const struct sshkey *from, struct sshkey *to)
{
	if (from->ed25519_pk == NULL)
		return 0; /* XXX SSH_ERR_INTERNAL_ERROR ? */
	if ((to->ed25519_pk = malloc(ED25519_PK_SZ)) == NULL)
		return SSH_ERR_ALLOC_FAIL;
	memcpy(to->ed25519_pk, from->ed25519_pk, ED25519_PK_SZ);
#ifdef OPENSSL_HAS_ED25519
	to->pk = EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, NULL,
	    to->ed25519_pk, ED25519_PK_SZ);
	if (to->pk == NULL)
		return SSH_ERR_LIBCRYPTO_ERROR;
#endif
	return 0;
}

static int
ssh_ed25519_deserialize_public(const char *pkalg, struct sshbuf *buf,
    struct sshkey *key)
{
	UNUSED(pkalg);
	return sshbuf_read_pub_ed25519(buf, key);
}

static int
ssh_ed25519_deserialize_private(const char *pkalg, struct sshbuf *buf,
    struct sshkey *key)
{
	int r;

	UNUSED(pkalg);
	/* NOTE !cert */
	if ((r = sshbuf_read_pub_ed25519(buf, key)) != 0)
		return r;
	return sshbuf_read_priv_ed25519(buf, key);
}

static int
ssh_ed25519_sign(const ssh_sign_ctx *ctx, u_char **sigp, size_t *lenp,
    const u_char *data, size_t datalen)
{
	const struct sshkey *key = ctx->key;
	u_char *sig = NULL;
	size_t slen = 0;
	unsigned long long smlen;
	int r;

	if (lenp != NULL)
		*lenp = 0;
	if (sigp != NULL)
		*sigp = NULL;

	if (key == NULL ||
	    sshkey_type_plain(key->type) != KEY_ED25519 ||
	    key->ed25519_sk == NULL ||
	    datalen >= INT_MAX - crypto_sign_ed25519_BYTES)
		return SSH_ERR_INVALID_ARGUMENT;
	smlen = slen = datalen + crypto_sign_ed25519_BYTES;
	if ((sig = malloc(slen)) == NULL)
		return SSH_ERR_ALLOC_FAIL;

	if (crypto_sign_ed25519(sig, &smlen, data, datalen,
	    key->ed25519_sk) != 0 || smlen <= datalen) {
		r = SSH_ERR_INVALID_ARGUMENT; /* XXX better error? */
		goto out;
	}

	r = ssh_encode_signature(sigp, lenp,
	    "ssh-ed25519", sig, smlen - datalen);

 out:
	if (sig != NULL)
		freezero(sig, slen);

	return r;
}

static int
ssh_ed25519_verify(const ssh_verify_ctx *ctx,
    const u_char *sig, size_t siglen,
    const u_char *data, size_t dlen)
{
	const struct sshkey *key = ctx->key;
	struct sshbuf *b = NULL;
	char *ktype = NULL;
	const u_char *sigblob;
	u_char *sm = NULL, *m = NULL;
	size_t len;
	unsigned long long smlen = 0, mlen = 0;
	int r, ret;

	if (key == NULL ||
	    sshkey_type_plain(key->type) != KEY_ED25519 ||
	    key->ed25519_pk == NULL ||
	    dlen >= INT_MAX - crypto_sign_ed25519_BYTES ||
	    sig == NULL || siglen == 0)
		return SSH_ERR_INVALID_ARGUMENT;

	if ((b = sshbuf_from(sig, siglen)) == NULL)
		return SSH_ERR_ALLOC_FAIL;
	if ((r = sshbuf_get_cstring(b, &ktype, NULL)) != 0 ||
	    (r = sshbuf_get_string_direct(b, &sigblob, &len)) != 0)
		goto out;
	if (strcmp("ssh-ed25519", ktype) != 0) {
		r = SSH_ERR_KEY_TYPE_MISMATCH;
		goto out;
	}
	if (sshbuf_len(b) != 0) {
		r = SSH_ERR_UNEXPECTED_TRAILING_DATA;
		goto out;
	}
	if (len > crypto_sign_ed25519_BYTES) {
		r = SSH_ERR_INVALID_FORMAT;
		goto out;
	}
	if (dlen >= SIZE_MAX - len) {
		r = SSH_ERR_INVALID_ARGUMENT;
		goto out;
	}
	smlen = len + dlen;
	mlen = smlen;
	if ((sm = malloc(smlen)) == NULL || (m = malloc(mlen)) == NULL) {
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	memcpy(sm, sigblob, len);
	memcpy(sm+len, data, dlen);
	if ((ret = crypto_sign_ed25519_open(m, &mlen, sm, smlen,
	    key->ed25519_pk)) != 0) {
		debug2_f("crypto_sign_ed25519_open failed: %d", ret);
	}
	if (ret != 0 || mlen != dlen) {
		r = SSH_ERR_SIGNATURE_INVALID;
		goto out;
	}
	/* XXX compare 'm' and 'data' ? */
	/* success */
	r = 0;
 out:
	if (sm != NULL)
		freezero(sm, smlen);
	if (m != NULL)
		freezero(m, smlen); /* NB mlen may be invalid if r != 0 */
	sshbuf_free(b);
	free(ktype);
	return r;
}

static const struct sshkey_impl_funcs sshkey_ed25519_funcs = {
	/* .size = */		ssh_ed25519_size,
	/* .alloc =		NULL, */
	/* .cleanup = */	ssh_ed25519_cleanup,
	/* .equal = */		ssh_ed25519_equal,
	/* .serialize_public = */	ssh_ed25519_serialize_public,
	/* .deserialize_public = */	ssh_ed25519_deserialize_public,
	/* .serialize_private = */	ssh_ed25519_serialize_private,
	/* .deserialize_private = */	ssh_ed25519_deserialize_private,
	/* .generate = */	ssh_ed25519_generate,
	/* .move_public = */	ssh_ed25519_move_public,
	/* .copy_public = */	ssh_ed25519_copy_public,
	/* .sign = */		ssh_ed25519_sign,
	/* .verify = */		ssh_ed25519_verify
};

const struct sshkey_impl sshkey_ed25519_impl = {
	/* .name = */		"ssh-ed25519",
	/* .shortname = */	"ED25519",
	/* .sigalg = */		NULL,
	/* .type = */		KEY_ED25519,
	/* .nid = */		0,
	/* .cert = */		0,
	/* .sigonly = */	0,
	/* .keybits = */	256,
	/* .funcs = */		&sshkey_ed25519_funcs
};

const struct sshkey_impl sshkey_ed25519_cert_impl = {
	/* .name = */		"ssh-ed25519-cert-v01@openssh.com",
	/* .shortname = */	"ED25519-CERT",
	/* .sigalg = */		NULL,
	/* .type = */		KEY_ED25519_CERT,
	/* .nid = */		0,
	/* .cert = */		1,
	/* .sigonly = */	0,
	/* .keybits = */	256,
	/* .funcs = */		&sshkey_ed25519_funcs
};
