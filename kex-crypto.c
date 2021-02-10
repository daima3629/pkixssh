/*
 * Copyright (c) 2021 Roumen Petrov.  All rights reserved.
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

#define SSHKEY_INTERNAL
#include "includes.h"

#ifdef WITH_OPENSSL
#include "evp-compat.h"

#include "kex.h"
#include "dh.h"
#include "ssherr.h"
#include "misc.h"

#ifndef HAVE_DH_GET0_KEY	/* OpenSSL < 1.1 */
/* Partial backport of opaque DH from OpenSSL >= 1.1, commits
 * "Make DH opaque", "RSA, DSA, DH: Allow some given input to be NULL
 * on already initialised keys" and etc.
 */
static inline void
DH_get0_key(const DH *dh, const BIGNUM **pub_key, const BIGNUM **priv_key) {
	if (pub_key  != NULL) *pub_key  = dh->pub_key;
	if (priv_key != NULL) *priv_key = dh->priv_key;
}

static inline int
DH_set_length(DH *dh, long length) {
	dh->length = length;
	return 1;
}

static inline void
DH_get0_pqg(const DH *dh, const BIGNUM **p, const BIGNUM **q, const BIGNUM **g) {
	if (p != NULL) *p = dh->p;
	if (q != NULL) *q = dh->q;
	if (g != NULL) *g = dh->g;
}

static inline int
DH_set0_pqg(DH *dh, BIGNUM *p, BIGNUM *q, BIGNUM *g) {
/* If the fields p and g in d are NULL, the corresponding input
 * parameters MUST be non-NULL.  q may remain NULL.
 *
 * It is an error to give the results from get0 on d as input
 * parameters.
 */
	if (p == dh->p || (dh->q != NULL && q == dh->q) || g == dh->g)
		return 0;

	if (p != NULL) { BN_free(dh->p); dh->p = p; }
	if (q != NULL) { BN_free(dh->q); dh->q = q; }
	if (g != NULL) { BN_free(dh->g); dh->g = g; }

	if (q != NULL)
	        (void)DH_set_length(dh, BN_num_bits(q));

	return 1;
}
#endif /*ndef HAVE_DH_GET0_KEY*/

extern DH* _dh_new_group_num(int);
extern int _dh_gen_key(DH *dh, int need);


int
_dh_gen_key(DH *dh, int need)
{
	int pbits;
	const BIGNUM *dh_p, *pub_key;

	DH_get0_pqg(dh, &dh_p, NULL, NULL);

	if (need < 0 || dh_p == NULL ||
	    (pbits = BN_num_bits(dh_p)) <= 0 ||
	    need > INT_MAX / 2 ||
	    2 * need > pbits)
		return SSH_ERR_INVALID_ARGUMENT;

	if (need < 256) need = 256;
	/*
	 * Pollard Rho, Big step/Little Step attacks are O(sqrt(n)),
	 * so double requested need here.
	 */
	if (!DH_set_length(dh, MINIMUM(need * 2, pbits - 1)))
		return SSH_ERR_LIBCRYPTO_ERROR;

	if (DH_generate_key(dh) == 0)
		return SSH_ERR_LIBCRYPTO_ERROR;

	DH_get0_key(dh, &pub_key, NULL);
	if (!dh_pub_is_valid(dh, pub_key))
		return SSH_ERR_INVALID_FORMAT;

	return 0;
}


int
kex_key_init_dh(struct kex *kex) {
	DH *dh;

	switch (kex->kex_type) {
	case KEX_DH_GRP1_SHA1:
		dh = _dh_new_group_num(1);
		break;
	case KEX_DH_GRP14_SHA1:
	case KEX_DH_GRP14_SHA256:
		dh = _dh_new_group_num(14);
		break;
	case KEX_DH_GRP16_SHA512:
		dh = _dh_new_group_num(16);
		break;
	case KEX_DH_GRP18_SHA512:
		dh = _dh_new_group_num(18);
		break;
	default:
		return SSH_ERR_INVALID_ARGUMENT;
	}
	if (dh == NULL) return SSH_ERR_ALLOC_FAIL;

{	EVP_PKEY *pk = EVP_PKEY_new();
	if (pk == NULL) {
		DH_free(dh);
		return SSH_ERR_ALLOC_FAIL;
	}
	if (!EVP_PKEY_set1_DH(pk, dh)) {
		DH_free(dh);
		EVP_PKEY_free(pk);
		return SSH_ERR_ALLOC_FAIL;
	}
	kex->pk = pk;
}
	kex->dh = dh; /* TODO */

	return 0;
}


void
kex_reset_crypto_keys(struct kex *kex) {
	EVP_PKEY_free(kex->pk);
	kex->pk = NULL;

	DH_free(kex->dh);
	kex->dh = NULL;

#ifdef OPENSSL_HAS_ECC
	EC_KEY_free(kex->ec_client_key);
	kex->ec_client_key = NULL;
#endif /* OPENSSL_HAS_ECC */
}


/* TODO: internal */
extern DH* _choose_dh(int, int, int);

EVP_PKEY*
kex_new_dh_group_bits(int min, int wantbits, int max) {
	EVP_PKEY *pk;
	DH *dh = NULL;

	dh = _choose_dh(min, wantbits, max);
	if (dh == NULL) return NULL;

	pk = EVP_PKEY_new();
	if (pk == NULL) goto done;

	if (!EVP_PKEY_set1_DH(pk, dh)) {
		EVP_PKEY_free(pk);
		pk = NULL;
	}

done:
	DH_free(dh);
	return pk;
}

EVP_PKEY*
kex_new_dh_group(BIGNUM *modulus, BIGNUM *gen) {
	EVP_PKEY *pk = NULL;
	DH *dh = NULL;

	dh = DH_new();
	if (dh == NULL) return NULL;

	pk = EVP_PKEY_new();
	if (pk == NULL)
		goto done;

	if (!EVP_PKEY_set1_DH(pk, dh))
		goto err;

	if (DH_set0_pqg(dh, modulus, NULL, gen))
		goto done;

err:
	EVP_PKEY_free(pk);
	pk = NULL;

done:
	DH_free(dh);
	return pk;
}


int
sshbuf_kex_write_dh_group(struct sshbuf *buf, EVP_PKEY *pk) {
	int r;
	DH *dh;

	dh = EVP_PKEY_get1_DH(pk);
	if (dh == NULL)
		return SSH_ERR_INVALID_ARGUMENT;

{	const BIGNUM *p = NULL, *g = NULL;
	DH_get0_pqg(dh, &p, NULL, &g);

	if ((r = sshbuf_put_bignum2(buf, p)) != 0)
		goto done;
	r = sshbuf_put_bignum2(buf, g);
}

done:
	DH_free(dh);
	return r;
}

int
sshbuf_kex_write_dh_pub(struct sshbuf *buf, EVP_PKEY *pk) {
	int r;
	DH *dh;

	dh = EVP_PKEY_get1_DH(pk);
	if (dh == NULL)
		return SSH_ERR_INVALID_ARGUMENT;

{	const BIGNUM *pub_key;
	DH_get0_key(dh, &pub_key, NULL);
#ifdef DEBUG_KEXDH
	fprintf(stderr, "dh pub: ");
	BN_print_fp(stderr, pub_key);
	fprintf(stderr, "\n");
	DHparams_print_fp(stderr, dh);
#endif

	r = sshbuf_put_bignum2(buf, pub_key);
}
	DH_free(dh);
	return r;
}


int
kexgex_hash_client(const struct kex *kex,
    const struct sshbuf *key_blob, const BIGNUM *peer_pub,
    const struct sshbuf *shared_secret,
    u_char *hash, size_t *hashlen
) {
	const BIGNUM *my_pub, *dh_p, *dh_g;

	DH_get0_key(kex->dh, &my_pub, NULL);
	DH_get0_pqg(kex->dh, &dh_p, NULL, &dh_g);

	return kexgex_hash(kex->hash_alg,
	    kex->client_version, kex->server_version,
	    kex->my, kex->peer, key_blob,
	    kex->min, kex->nbits, kex->max,
	    dh_p, dh_g, my_pub, peer_pub,
	    sshbuf_ptr(shared_secret), sshbuf_len(shared_secret),
	    hash, hashlen);
}

int
kexgex_hash_server(const struct kex *kex,
    const struct sshbuf *key_blob, const BIGNUM *peer_pub,
    const struct sshbuf *shared_secret,
    u_char *hash, size_t *hashlen
) {
	const BIGNUM *my_pub, *dh_p, *dh_g;

	DH_get0_key(kex->dh, &my_pub, NULL);
	DH_get0_pqg(kex->dh, &dh_p, NULL, &dh_g);

	return kexgex_hash( kex->hash_alg,
	    kex->client_version, kex->server_version,
	    kex->peer, kex->my, key_blob,
	    kex->min, kex->nbits, kex->max,
	    dh_p, dh_g, peer_pub, my_pub,
	    sshbuf_ptr(shared_secret), sshbuf_len(shared_secret),
	    hash, hashlen);
}
#else

typedef int kex_crypto_empty_translation_unit;

#endif /* WITH_OPENSSL */
