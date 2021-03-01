/*
 * Copyright (c) 2020-2021 Roumen Petrov.  All rights reserved.
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
#include <openssl/pem.h>

#include "ssh-x509.h"
#include "ssherr.h"
#include "crypto_api.h" /*for some Ed25519 defines */
#include "log.h"

#ifndef HAVE_RSA_GET0_KEY
/* opaque RSA key structure */
static inline void
RSA_get0_key(const RSA *rsa, const BIGNUM **n, const BIGNUM **e, const BIGNUM **d) {
	if (n != NULL) *n = rsa->n;
	if (e != NULL) *e = rsa->e;
	if (d != NULL) *d = rsa->d;
}

static inline int
RSA_set0_key(RSA *rsa, BIGNUM *n, BIGNUM *e, BIGNUM *d) {
/* If the fields in r are NULL, the corresponding input parameters MUST
 * be non-NULL for n and e.  d may be left NULL (in case only the
 * public key is used).
 *
 * It is an error to give the results from get0 on r as input
 * parameters.
 */
	if (n == rsa->n || e == rsa->e
	|| (rsa->d != NULL && d == rsa->d))
		return 0;

	if (n != NULL) { BN_free(rsa->n); rsa->n = n; }
	if (e != NULL) { BN_free(rsa->e); rsa->e = e; }
	if (d != NULL) { BN_free(rsa->d); rsa->d = d; }

	return 1;
}


static inline void
RSA_get0_crt_params(const RSA *rsa, const BIGNUM **dmp1, const BIGNUM **dmq1, const BIGNUM **iqmp) {
	if (dmp1 != NULL) *dmp1 = rsa->dmp1;
	if (dmq1 != NULL) *dmq1 = rsa->dmq1;
	if (iqmp != NULL) *iqmp = rsa->iqmp;
}

static inline int
RSA_set0_crt_params(RSA *rsa, BIGNUM *dmp1, BIGNUM *dmq1, BIGNUM *iqmp) {
/* If the fields in r are NULL, the corresponding input parameters MUST
 * be non-NULL.
 *
 * It is an error to give the results from get0 on r as input
 * parameters.
 */
	if (dmp1 == rsa->dmp1 || dmq1 == rsa->dmq1 || iqmp == rsa->iqmp)
		return 0;

	if (dmp1 != NULL) { BN_free(rsa->dmp1); rsa->dmp1 = dmp1; }
	if (dmq1 != NULL) { BN_free(rsa->dmq1); rsa->dmq1 = dmq1; }
	if (iqmp != NULL) { BN_free(rsa->iqmp); rsa->iqmp = iqmp; }

	return 1;
}


static inline void
RSA_get0_factors(const RSA *rsa, const BIGNUM **p, const BIGNUM **q) {
	if (p != NULL) *p = rsa->p;
	if (q != NULL) *q = rsa->q;
}


static inline int
RSA_set0_factors(RSA *rsa, BIGNUM *p, BIGNUM *q) {
/* If the fields in r are NULL, the corresponding input parameters MUST
 * be non-NULL.
 *
 * It is an error to give the results from get0 on r as input
 * parameters.
 */
	if (p == rsa->p || q == rsa->q)
		return 0;

	if (p != NULL) { BN_free(rsa->p); rsa->p = p; }
	if (q != NULL) { BN_free(rsa->q); rsa->q = q; }

	return 1;
}
#endif /*ndef HAVE_RSA_GET0_KEY*/

#ifndef HAVE_DSA_GET0_KEY
/* opaque DSA key structure */
static inline void
DSA_get0_key(const DSA *dsa, const BIGNUM **pub_key, const BIGNUM **priv_key) {
	if (pub_key  != NULL) *pub_key  = dsa->pub_key;
	if (priv_key != NULL) *priv_key = dsa->priv_key;
}

static inline int
DSA_set0_key(DSA *dsa, BIGNUM *pub_key, BIGNUM *priv_key) {
/* If the pub_key in d is NULL, the corresponding input parameters MUST
 * be non-NULL.  The priv_key field may be left NULL.
 *
 * It is an error to give the results from get0 on d as input
 * parameters.
 */
	if (pub_key == dsa->pub_key
	|| (dsa->priv_key != NULL && priv_key == dsa->priv_key)
	)
		return 0;

	if (pub_key  != NULL) { BN_free(dsa->pub_key ); dsa->pub_key  = pub_key ; }
	if (priv_key != NULL) { BN_free(dsa->priv_key); dsa->priv_key = priv_key; }

	return 1;
}


static inline void
DSA_get0_pqg(const DSA *dsa, const BIGNUM **p, const BIGNUM **q, const BIGNUM **g) {
	if (p != NULL) *p = dsa->p;
	if (q != NULL) *q = dsa->q;
	if (g != NULL) *g = dsa->g;
}

static /*inline*/ int
DSA_set0_pqg(DSA *dsa, BIGNUM *p, BIGNUM *q, BIGNUM *g) {
	/* If the fields in d are NULL, the corresponding input
	 * parameters MUST be non-NULL.
	 *
	 * It is an error to give the results from get0 on d
	 * as input parameters.
	 */
	if (p == dsa->p || q == dsa->q || g == dsa->g)
		return 0;

	if (p != NULL) { BN_free(dsa->p); dsa->p = p; }
	if (q != NULL) { BN_free(dsa->q); dsa->q = q; }
	if (g != NULL) { BN_free(dsa->g); dsa->g = g; }

	return 1;
}
#endif /*ndef HAVE_DSA_GET0_KEY*/


#ifdef DEBUG_PK
static void
ssh_EVP_PKEY_print_fp(FILE *fp, const EVP_PKEY *pkey) {
#ifdef HAVE_EVP_PKEY_PRINT_PARAMS /* OpenSSL 1.0.0+ */
{	/* OpenSSL lacks print to file stream */
	BIO *bio = BIO_new_fp(fp, BIO_NOCLOSE);
#ifdef VMS
	{	BIO *tmpbio = BIO_new(BIO_f_linebuffer());
		bio = BIO_push(tmpbio, bio);
	}
#endif

	EVP_PKEY_print_private(bio, pkey, 0, NULL);
	BIO_free_all(bio);
}
#else
{
	int evp_id = EVP_PKEY_base_id(pkey);

	switch (evp_id) {
	case EVP_PKEY_RSA: {
		RSA *rsa = EVP_PKEY_get1_RSA(pkey);
		RSA_print_fp(fp, rsa, 0);
		RSA_free(rsa);
		} break;
#ifdef OPENSSL_HAS_ECC
	case EVP_PKEY_EC: {
		EC_KEY *ec = EVP_PKEY_get1_EC_KEY(pkey);
		EC_KEY_print_fp(fp, ec, 0);
		EC_KEY_free(ec);
		} break;
#endif /* OPENSSL_HAS_ECC */
	case EVP_PKEY_DSA: {
		DSA *dsa = EVP_PKEY_get1_DSA(pkey);
		DSA_print_fp(fp, dsa, 0);
		DSA_free(dsa);
		} break;
	}
}
#endif /*ndef HAVE_EVP_PKEY_PRINT_PARAMS*/
}

static void
sshkey_dump(const char *func, const struct sshkey *key) {
	fprintf(stderr, "dump key %s():\n", func);
	ssh_EVP_PKEY_print_fp(stderr, key->pk);
}
#else
static inline void
sshkey_dump(const char *func, const struct sshkey *key) {
	UNUSED(func);
	UNUSED(key);
}
#endif /* DEBUG_PK */

#define SSHKEY_DUMP(...)	sshkey_dump(__func__, __VA_ARGS__)


/* TODO: validation of deprecated in OpenSSL 3.0 elementary keys */
static int
sshkey_validate_rsa_pub(const RSA *rsa) {
	int r;
	const BIGNUM *n = NULL;

	RSA_get0_key(rsa, &n, NULL, NULL);

	r = sshrsa_verify_length(BN_num_bits(n));
	if (r != 0) return r;

	/* other checks ? */
	return 0;
}

static int
sshkey_validate_dsa_pub(const DSA *dsa) {
	int r;
	const BIGNUM *p = NULL;

	DSA_get0_pqg(dsa, &p, NULL, NULL);

	r = sshdsa_verify_length(BN_num_bits(p));
	if (r != 0) return r;

	/* other checks ? */
	return 0;
}

#ifdef OPENSSL_HAS_ECC
static int
sshkey_validate_ec_pub(const EC_KEY *ec) {
	int r;

	r = sshkey_ec_validate_public(EC_KEY_get0_group(ec),
	    EC_KEY_get0_public_key(ec));
	if (r != 0) return r;

	/* other checks ? */
	return 0;
}

static int
sshkey_validate_ec_priv(const EC_KEY *ec) {
	int r;
	const BIGNUM *exponent;
	BIGNUM *order = NULL, *tmp = NULL;

	exponent = EC_KEY_get0_private_key(ec);
	if (exponent == NULL) {
		r = SSH_ERR_INVALID_ARGUMENT;
		goto err;
	}

	order = BN_new();
	if (order == NULL)  {
		r = SSH_ERR_ALLOC_FAIL;
		goto err;
	}

	if (EC_GROUP_get_order(EC_KEY_get0_group(ec), order, NULL) != 1) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		goto err;
	}

	/* log2(private) > log2(order)/2 */
	if (BN_num_bits(exponent) <= BN_num_bits(order) / 2) {
		r = SSH_ERR_KEY_INVALID_EC_VALUE;
		goto err;
	}

	tmp = BN_new();
	if (tmp == NULL) {
		r = SSH_ERR_ALLOC_FAIL;
		goto err;
	}

	/* private < order - 1 */
	if (!BN_sub(tmp, order, BN_value_one())) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		goto err;
	}
	if (BN_cmp(exponent, tmp) >= 0) {
		r = SSH_ERR_KEY_INVALID_EC_VALUE;
		goto err;
	}

	/* other checks ? */

	r = 0;

err:
	BN_clear_free(order);
	BN_clear_free(tmp);
	return r;
}
#endif


#ifndef BN_FLG_CONSTTIME
#  define BN_FLG_CONSTTIME 0x0 /* OpenSSL < 0.9.8 */
#endif
/* TODO: new method compatible with OpenSSL 3.0 API */
static int
sshrsa_complete_crt_parameters(RSA *rsa, const BIGNUM *rsa_iqmp)
{
	BN_CTX *ctx;
	BIGNUM *aux = NULL, *d = NULL;
	BIGNUM *dmq1 = NULL, *dmp1 = NULL, *iqmp = NULL;
	int r;

	ctx = BN_CTX_new();
	if (ctx == NULL)
		return SSH_ERR_ALLOC_FAIL;
	if ((aux = BN_new()) == NULL ||
	    (iqmp = BN_dup(rsa_iqmp)) == NULL ||
	    (dmq1 = BN_new()) == NULL ||
	    (dmp1 = BN_new()) == NULL) {
		r = SSH_ERR_ALLOC_FAIL;
		goto err;
	}
	BN_set_flags(aux, BN_FLG_CONSTTIME);

{	const BIGNUM *p, *q;
	RSA_get0_factors(rsa, &p, &q);
	{	const BIGNUM *key_d;
		RSA_get0_key(rsa, NULL, NULL, &key_d);
		if ((d = BN_dup(key_d)) == NULL) {
			r = SSH_ERR_ALLOC_FAIL;
			goto err;
		}
		BN_set_flags(d, BN_FLG_CONSTTIME);
	}

	if ((BN_sub(aux, q, BN_value_one()) == 0) ||
	    (BN_mod(dmq1, d, aux, ctx) == 0) ||
	    (BN_sub(aux, p, BN_value_one()) == 0) ||
	    (BN_mod(dmp1, d, aux, ctx) == 0)) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		goto err;
	}
}
	if (!RSA_set0_crt_params(rsa, dmp1, dmq1, iqmp)) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		goto err;
	}
	dmp1 = dmq1 = iqmp = NULL; /* transferred */

	/* success */
	r = 0;

err:
	BN_clear_free(aux);
	BN_clear_free(d);
	BN_clear_free(dmp1);
	BN_clear_free(dmq1);
	BN_clear_free(iqmp);
	BN_CTX_free(ctx);
	return r;
}


static int
sshkey_init_rsa_key(struct sshkey *key, BIGNUM *n, BIGNUM *e, BIGNUM *d) {
	int r;
	EVP_PKEY *pk = NULL;
	RSA *rsa = NULL;

	pk = EVP_PKEY_new();
	if (pk == NULL) {
		r = SSH_ERR_ALLOC_FAIL;
		goto err;
	}
	rsa = RSA_new();
	if (rsa == NULL) {
		r = SSH_ERR_ALLOC_FAIL;
		goto err;
	}

	if (!EVP_PKEY_set1_RSA(pk, rsa)) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		goto err;
	}

	/* transfer to key must be last operation -
	   if fail then caller could free arguments */
	if (!RSA_set0_key(rsa, n, e, d)) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		goto err;
	}

	/* success */
	key->pk = pk;
	pk = NULL;
	r = 0;

err:
	RSA_free(rsa);
	EVP_PKEY_free(pk);
	return r;
}

static int
ssh_EVP_PKEY_complete_pub_rsa(EVP_PKEY *pk) {
	int r;
	RSA *rsa;

	rsa = EVP_PKEY_get1_RSA(pk);
	if (rsa == NULL)
		return SSH_ERR_INVALID_ARGUMENT;

	r = sshkey_validate_rsa_pub(rsa);
	if (r != 0) goto err;

	if (RSA_blinding_on(rsa, NULL) != 1) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		goto err;
	}

	/* success */
	r = 0;
err:
	RSA_free(rsa);
	return r;
}


static int
sshkey_init_dsa_params(struct sshkey *key, BIGNUM *p, BIGNUM *q, BIGNUM *g) {
	int r;
	EVP_PKEY *pk = NULL;
	DSA *dsa = NULL;

	pk = EVP_PKEY_new();
	if (pk == NULL)
		return SSH_ERR_ALLOC_FAIL;

	dsa = DSA_new();
	if (dsa == NULL) {
		r = SSH_ERR_ALLOC_FAIL;
		goto err;
	}

	if (!EVP_PKEY_set1_DSA(pk, dsa)) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		goto err;
	}

	/* transfer to key must be last operation -
	   if fail then caller could free arguments */
	if (!DSA_set0_pqg(dsa, p, q, g)) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		goto err;
	}

	/* success */
	key->pk = pk;
	pk = NULL;
	r =  0;

err:
	DSA_free(dsa);
	EVP_PKEY_free(pk);
	return r;
}

static int
ssh_EVP_PKEY_complete_pub_dsa(EVP_PKEY *pk) {
	int r;
	DSA *dsa;

	dsa = EVP_PKEY_get1_DSA(pk);
	if (dsa == NULL)
		return SSH_ERR_INVALID_ARGUMENT;

	r = sshkey_validate_dsa_pub(dsa);

	DSA_free(dsa);
	return r;
}

static int
sshkey_set_dsa_key(struct sshkey *key, BIGNUM *pub_key, BIGNUM *priv_key) {
	int r;
	DSA *dsa;

	dsa = EVP_PKEY_get1_DSA(key->pk);
	if (dsa == NULL)
		return SSH_ERR_INVALID_ARGUMENT;

	if (!DSA_set0_key(dsa, pub_key, priv_key)) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		goto err;
	}

	/* success */
	r = 0;
err:
	DSA_free(dsa);
	return r;
}


#ifdef OPENSSL_HAS_ECC
static inline EC_KEY*
ssh_EC_KEY_new_by_curve_name(int nid) {
	EC_KEY *ec;

	ec = EC_KEY_new_by_curve_name(nid);
	if (ec == NULL) return NULL;

#if defined(OPENSSL_VERSION_NUMBER) && (OPENSSL_VERSION_NUMBER < 0x10100000L) || \
    defined(LIBRESSL_VERSION_NUMBER)
	/* Note since 1.1.0 OpenSSL uses named curve parameter encoding by default.
	 * It seems to me default is changed in upcomming 3.0 but key is marked
	 * properly when created by nid.
	 */
	EC_KEY_set_asn1_flag(ec, OPENSSL_EC_NAMED_CURVE);
#endif
	return ec;
}

static int
sshkey_init_ecdsa_curve(struct sshkey *key, int nid) {
	int r;
	EVP_PKEY *pk;
	EC_KEY *ec;

	pk = EVP_PKEY_new();
	if (pk == NULL)
		return SSH_ERR_ALLOC_FAIL;

	ec = ssh_EC_KEY_new_by_curve_name(nid);
	if (ec == NULL) {
		r = SSH_ERR_ALLOC_FAIL;
		goto err;
	}

	if (!EVP_PKEY_set1_EC_KEY(pk, ec)) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		goto err;
	}

	/* success */
	key->pk = pk;
	pk = NULL;
	key->ecdsa_nid = nid;
	r = 0;

err:
	EC_KEY_free(ec);
	EVP_PKEY_free(pk);
	return r;
}

static int
ssh_EVP_PKEY_complete_pub_ecdsa(EVP_PKEY *pk) {
	int r, nid;
	EC_KEY *ec;

	ec = EVP_PKEY_get1_EC_KEY(pk);
	if (ec == NULL)
		return SSH_ERR_INVALID_ARGUMENT;

	nid = sshkey_ecdsa_key_to_nid(ec);
	if (nid < 0) {
		error_f("unsupported elliptic curve");
		r = SSH_ERR_EC_CURVE_INVALID;
		goto err;
	}

	r = sshkey_validate_ec_pub(ec);

err:
	EC_KEY_free(ec);
	return r;
}
#endif /*def OPENSSL_HAS_ECC*/


static int
sshkey_from_pkey_rsa(EVP_PKEY *pk, struct sshkey **keyp) {
	int r;
	struct sshkey* key;

	r = ssh_EVP_PKEY_complete_pub_rsa(pk);
	if (r != 0) return r;

	key = sshkey_new(KEY_UNSPEC);
	if (key == NULL)
		return SSH_ERR_ALLOC_FAIL;

	key->type = KEY_RSA;
	key->pk = pk;

	/* success */
	SSHKEY_DUMP(key);
	*keyp = key;
	return 0;
}

static int
sshkey_from_pkey_dsa(EVP_PKEY *pk, struct sshkey **keyp) {
	int r;
	struct sshkey* key;

	r = ssh_EVP_PKEY_complete_pub_dsa(pk);
	if (r != 0) return r;

	key = sshkey_new(KEY_UNSPEC);
	if (key == NULL)
		return SSH_ERR_ALLOC_FAIL;

	/* success */
	key->type = KEY_DSA;
	key->pk = pk;

	SSHKEY_DUMP(key);
	*keyp = key;
	return 0;
}

#ifdef OPENSSL_HAS_ECC
static int
sshkey_from_pkey_ecdsa(EVP_PKEY *pk, struct sshkey **keyp) {
	int r;
	struct sshkey* key;
	EC_KEY *ec;

	r = ssh_EVP_PKEY_complete_pub_ecdsa(pk);
	if (r != 0) return r;

	key = sshkey_new(KEY_UNSPEC);
	if (key == NULL)
		return SSH_ERR_ALLOC_FAIL;

	key->type = KEY_ECDSA;
	key->pk = pk;

	ec = EVP_PKEY_get1_EC_KEY(key->pk);
	if (ec == NULL) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		goto err;
	}

{	/* indirectly set in sshkey_ecdsa_key_to_nid(if needed)
	   when pkey is completed */
	const EC_GROUP *g = EC_KEY_get0_group(ec);
	key->ecdsa_nid = EC_GROUP_get_curve_name(g);
}

{	/* private part is not required */
	const BIGNUM *exponent = EC_KEY_get0_private_key(ec);
	if (exponent == NULL) goto skip_private;

	r = sshkey_validate_ec_priv(ec);
	if (r != 0) goto err;
}
skip_private:

	/* success */
	SSHKEY_DUMP(key);
	*keyp = key;
	EC_KEY_free(ec);
	return 0;

err:
	EC_KEY_free(ec);
	sshkey_free(key);
	return r;
}
#endif /* OPENSSL_HAS_ECC */

#ifdef OPENSSL_HAS_ED25519
static int
sshkey_from_pkey_ed25519(EVP_PKEY *pk, struct sshkey **keyp) {
	int r;
	struct sshkey* key;
	char *raw_pk = NULL, *raw_sk = NULL;
	size_t len;

	key = sshkey_new(KEY_UNSPEC);
	if (key == NULL)
		return SSH_ERR_ALLOC_FAIL;

	if ((raw_pk = calloc(1, ED25519_PK_SZ)) == NULL ||
	    (raw_sk = calloc(1, ED25519_SK_SZ)) == NULL
	) {
		r = SSH_ERR_ALLOC_FAIL;
		goto err;
	}

	len = ED25519_PK_SZ;
	if (!EVP_PKEY_get_raw_public_key(pk, raw_pk, &len)) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		goto err;
	}
	if (len != ED25519_PK_SZ) {
		r = SSH_ERR_INVALID_FORMAT;
		goto err;
	}

	/* private part is not required */
	len = ED25519_SK_SZ - ED25519_PK_SZ;
	if (!EVP_PKEY_get_raw_private_key(pk, raw_sk, &len))
		goto skip_private;
	if (len != (ED25519_SK_SZ - ED25519_PK_SZ)) {
		r = SSH_ERR_INVALID_FORMAT;
		goto err;
	}
	/* append the public key to private to match internal format */
	memcpy(raw_sk + len, raw_pk, ED25519_PK_SZ);
skip_private:

	key->type = KEY_ED25519;
	key->pk = pk;

	/* success */
	SSHKEY_DUMP(key);
	*keyp = key;
	/* free raw values; TODO */
	key->ed25519_pk = raw_pk;
	key->ed25519_sk = raw_sk;
	return 0;

err:
	free(raw_pk);
	free(raw_sk);
	sshkey_free(key);
	return r;
}
#endif /*def OPENSSL_HAS_ED25519*/

int
sshkey_from_pkey(EVP_PKEY *pk, struct sshkey **keyp) {
	int r, evp_id;

	/* NOTE do not set flags |= SSHKEY_FLAG_EXT !!! */
	evp_id = EVP_PKEY_base_id(pk);
	switch (evp_id) {
	case EVP_PKEY_RSA:
		r = sshkey_from_pkey_rsa(pk, keyp);
		break;
	case EVP_PKEY_DSA:
		r = sshkey_from_pkey_dsa(pk, keyp);
		break;
#ifdef OPENSSL_HAS_ECC
	case EVP_PKEY_EC:
		r = sshkey_from_pkey_ecdsa(pk, keyp);
		break;
#endif /*def OPENSSL_HAS_ECC*/
#ifdef OPENSSL_HAS_ED25519
	case EVP_PKEY_ED25519:
		r = sshkey_from_pkey_ed25519(pk, keyp);
		break;
#endif /*def OPENSSL_HAS_ED25519*/
	default:
		error_f("unsupported pkey type %d", evp_id);
		r = SSH_ERR_KEY_TYPE_UNKNOWN;
	}

	return r;
}


void
sshkey_clear_pkey(struct sshkey *key) {
	EVP_PKEY_free(key->pk);
	key->pk = NULL;
}


extern int sshkey_copy_pub_rsa(const struct sshkey *from, struct sshkey *to);

int
sshkey_copy_pub_rsa(const struct sshkey *from, struct sshkey *to) {
	int r;
	BIGNUM *n = NULL, *e = NULL;

{	RSA *rsa = EVP_PKEY_get1_RSA(from->pk);
	const BIGNUM *k_n, *k_e;

	if (rsa == NULL)
		return SSH_ERR_INVALID_ARGUMENT;
	RSA_get0_key(rsa, &k_n, &k_e, NULL);
	RSA_free(rsa);

	if ((n = BN_dup(k_n)) == NULL ||
	    (e = BN_dup(k_e)) == NULL) {
		r = SSH_ERR_ALLOC_FAIL;
		goto err;
	}
}

	r = sshkey_init_rsa_key(to, n, e, NULL);
	if (r != 0) goto err;
	/* n = e = NULL; transferred */

	/* success */
	return 0;

err:
	BN_clear_free(n);
	BN_clear_free(e);
	sshkey_clear_pkey(to);
	return r;
}

extern int sshkey_copy_pub_dsa(const struct sshkey *from, struct sshkey *to);

int
sshkey_copy_pub_dsa(const struct sshkey *from, struct sshkey *to) {
	int r;
	BIGNUM *p = NULL, *q = NULL, *g = NULL, *pub_key = NULL;

{	DSA *dsa = EVP_PKEY_get1_DSA(from->pk);
	const BIGNUM *k_p, *k_q, *k_g, *k_pub_key;

	if (dsa == NULL)
		return SSH_ERR_INVALID_ARGUMENT;
	DSA_get0_pqg(dsa, &k_p, &k_q, &k_g);
	DSA_get0_key(dsa, &k_pub_key, NULL);
	DSA_free(dsa);

	if ((p = BN_dup(k_p)) == NULL ||
	    (q = BN_dup(k_q)) == NULL ||
	    (g = BN_dup(k_g)) == NULL ||
	    (pub_key = BN_dup(k_pub_key)) == NULL) {
		r = SSH_ERR_ALLOC_FAIL;
		goto err;
	}
}

	r = sshkey_init_dsa_params(to, p, q, g);
	if (r != 0) goto err;
	p = q = g = NULL; /* transferred */

	r = sshkey_set_dsa_key(to, pub_key, NULL);
	if (r != 0) goto err;
	/* pub_key = NULL; transferred */

	/* success */
	return 0;

err:
	BN_clear_free(p);
	BN_clear_free(q);
	BN_clear_free(g);
	BN_clear_free(pub_key);
	sshkey_clear_pkey(to);
	return r;
}

#ifdef OPENSSL_HAS_ECC
extern int sshkey_copy_pub_ecdsa(const struct sshkey *from, struct sshkey *to);

int
sshkey_copy_pub_ecdsa(const struct sshkey *from, struct sshkey *to) {
	int r;
	EC_KEY *ec, *from_ec = NULL;

	r = sshkey_init_ecdsa_curve(to, from->ecdsa_nid);
	if (r != 0) return r;

	ec = EVP_PKEY_get1_EC_KEY(to->pk);
	if (ec == NULL) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		goto err;
	}

	from_ec = EVP_PKEY_get1_EC_KEY(from->pk);
	if (from_ec == NULL) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		goto err;
	}

	if (EC_KEY_set_public_key(ec, EC_KEY_get0_public_key(from_ec)) != 1)
		r = SSH_ERR_LIBCRYPTO_ERROR;

err:
	EC_KEY_free(from_ec);
	EC_KEY_free(ec);
	return r;
}
#endif /* OPENSSL_HAS_ECC */


void
sshkey_move_pk(struct sshkey *from, struct sshkey *to) {
	EVP_PKEY_free(to->pk);
	to->pk = from->pk;
	from->pk = NULL;
	SSHKEY_DUMP(to);
}


int
sshkey_validate_public_rsa(const struct sshkey *key) {
	int r;

	if (key == NULL) return SSH_ERR_INVALID_ARGUMENT;

{	RSA *rsa = EVP_PKEY_get1_RSA(key->pk);
	if (rsa == NULL)
		return SSH_ERR_INVALID_ARGUMENT;
	r = sshkey_validate_rsa_pub(rsa);
	RSA_free(rsa);
}
	return r;
}


int
sshkey_validate_public_dsa(const struct sshkey *key) {
	int r;

	if (key == NULL) return SSH_ERR_INVALID_ARGUMENT;

{	DSA *dsa = EVP_PKEY_get1_DSA(key->pk);
	if (dsa == NULL)
		return SSH_ERR_INVALID_ARGUMENT;
	r = sshkey_validate_dsa_pub(dsa);
	DSA_free(dsa);
}
	return r;
}


#ifdef OPENSSL_HAS_ECC
int
sshkey_validate_public_ecdsa(const struct sshkey *key) {
	int r;

	if (key == NULL) return SSH_ERR_INVALID_ARGUMENT;

{	EC_KEY *ec = EVP_PKEY_get1_EC_KEY(key->pk);
	if (ec == NULL)
		return SSH_ERR_INVALID_ARGUMENT;
	r = sshkey_validate_ec_pub(ec);
	EC_KEY_free(ec);
}
	return r;
}
#endif /* OPENSSL_HAS_ECC */

int
sshkey_validate_public(const struct sshkey *key) {
	int evp_id = EVP_PKEY_base_id(key->pk);

	switch (evp_id) {
	case EVP_PKEY_RSA:	return sshkey_validate_public_rsa(key);
	case EVP_PKEY_DSA:	return sshkey_validate_public_dsa(key);
#ifdef OPENSSL_HAS_ECC
	case EVP_PKEY_EC:	return sshkey_validate_public_ecdsa(key);
#endif
	}
	return SSH_ERR_KEY_TYPE_UNKNOWN;
}


#ifndef HAVE_EVP_PKEY_CMP	/* OpenSSL < 0.9.8 */
static int/*bool*/
ssh_EVP_PKEY_cmp_rsa(const EVP_PKEY *ka, const EVP_PKEY *kb) {
	int ret = -1;
	RSA *a, *b;
	const BIGNUM *a_n, *a_e;
	const BIGNUM *b_n, *b_e;

	a = EVP_PKEY_get1_RSA((EVP_PKEY*)ka);
	b = EVP_PKEY_get1_RSA((EVP_PKEY*)kb);
	if (a == NULL || b == NULL) goto err;

	RSA_get0_key(a, &a_n, &a_e, NULL);
	RSA_get0_key(b, &b_n, &b_e, NULL);

	ret =
	    BN_cmp(a_n, b_n) == 0 &&
	    BN_cmp(a_e, b_e) == 0;

err:
	RSA_free(b);
	RSA_free(a);
	return ret;
}

static int/*bool*/
ssh_EVP_PKEY_cmp_dsa(const EVP_PKEY *ka, const EVP_PKEY *kb) {
	int ret = -1;
	DSA *a, *b = NULL;
	const BIGNUM *a_p, *a_q, *a_g, *a_pub_key;
	const BIGNUM *b_p, *b_q, *b_g, *b_pub_key;

	a = EVP_PKEY_get1_DSA((EVP_PKEY*)ka);
	b = EVP_PKEY_get1_DSA((EVP_PKEY*)kb);
	if (a == NULL || b == NULL) goto err;

	DSA_get0_pqg(a, &a_p, &a_q, &a_g);
	DSA_get0_key(a, &a_pub_key, NULL);

	DSA_get0_pqg(b, &b_p, &b_q, &b_g);
	DSA_get0_key(b, &b_pub_key, NULL);

	ret =
	    BN_cmp(a_p, b_p) == 0 &&
	    BN_cmp(a_q, b_q) == 0 &&
	    BN_cmp(a_g, b_g) == 0 &&
	    BN_cmp(a_pub_key, b_pub_key) == 0;

err:
	DSA_free(b);
	DSA_free(a);
	return ret;
}

static int
EVP_PKEY_cmp(const EVP_PKEY *a, const EVP_PKEY *b) {
	int evp_id = EVP_PKEY_base_id(a);

	switch (evp_id) {
	case EVP_PKEY_RSA:	return ssh_EVP_PKEY_cmp_rsa(a, b);
	case EVP_PKEY_DSA:	return ssh_EVP_PKEY_cmp_dsa(a, b);
	}
	return -2;
}
#endif /*ndef HAVE_EVP_PKEY_CMP*/

int/*bool*/
sshkey_equal_public_pkey(const struct sshkey *ka, const struct sshkey *kb) {
	const EVP_PKEY *a, *b;

	if (ka == NULL) return 0;
	if (kb == NULL) return 0;

	a = ka->pk;
	if (a == NULL) return 0;

	b = kb->pk;
	if (b == NULL) return 0;

	return EVP_PKEY_cmp(a, b) == 1;
}


#ifndef HAVE_RSA_GENERATE_KEY_EX	/* OpenSSL < 0.9.8 */
static int
RSA_generate_key_ex(RSA *rsa, int bits, BIGNUM *bn_e, void *cb)
{
	RSA *new_rsa, tmp_rsa;
	unsigned long e;

	if (cb != NULL)
		fatal_f("callback args not supported");
	e = BN_get_word(bn_e);
	if (e == 0xffffffffL)
		fatal_f("value of e too large");
	new_rsa = RSA_generate_key(bits, e, NULL, NULL);
	if (new_rsa == NULL)
		return 0;
	/* swap rsa/new_rsa then free new_rsa */
	tmp_rsa = *rsa;
	*rsa = *new_rsa;
	*new_rsa = tmp_rsa;
	RSA_free(new_rsa);
	return 1;
}
#endif

int
sshkey_generate_rsa(u_int bits, struct sshkey *key) {
	EVP_PKEY *pk;
	RSA *private = NULL;
	BIGNUM *f4 = NULL;
	int r;

	r = sshrsa_verify_length(bits);
	if (r != 0) return r;

	if (bits > SSHBUF_MAX_BIGNUM * 8)
		return SSH_ERR_KEY_LENGTH;

	;
	if ((pk = EVP_PKEY_new()) == NULL ||
	    (private = RSA_new()) == NULL ||
	    (f4 = BN_new()) == NULL
	) {
		r = SSH_ERR_ALLOC_FAIL;
		goto err;
	}
	if (!BN_set_word(f4, RSA_F4) ||
	    !RSA_generate_key_ex(private, bits, f4, NULL)) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		goto err;
	}

	if (!EVP_PKEY_set1_RSA(pk, private)) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		goto err;
	}

	key->pk = pk;
	pk = NULL;

err:
	EVP_PKEY_free(pk);
	RSA_free(private);
	BN_free(f4);
	return r;
}

#ifndef HAVE_DSA_GENERATE_PARAMETERS_EX	/* OpenSSL < 0.9.8 */
static int
DSA_generate_parameters_ex(DSA *dsa, int bits, const unsigned char *seed,
    int seed_len, int *counter_ret, unsigned long *h_ret, void *cb)
{
	DSA *new_dsa, tmp_dsa;

	if (cb != NULL)
		fatal_f("callback args not supported");
	new_dsa = DSA_generate_parameters(bits, (unsigned char *)seed, seed_len,
	    counter_ret, h_ret, NULL, NULL);
	if (new_dsa == NULL)
		return 0;
	/* swap dsa/new_dsa then free new_dsa */
	tmp_dsa = *dsa;
	*dsa = *new_dsa;
	*new_dsa = tmp_dsa;
	DSA_free(new_dsa);
	return 1;
}
#endif

int
sshkey_generate_dsa(u_int bits, struct sshkey *key) {
	EVP_PKEY *pk;
	DSA *private = NULL;
	int r;

	r = sshdsa_verify_length(bits);
	if (r != 0) return r;

	if ((pk = EVP_PKEY_new()) == NULL ||
	    (private = DSA_new()) == NULL
	) {
		r = SSH_ERR_ALLOC_FAIL;
		goto err;
	}

	if (!DSA_generate_parameters_ex(private, bits, NULL, 0, NULL, NULL, NULL) ||
	    !DSA_generate_key(private)) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		goto err;
	}

	if (!EVP_PKEY_set1_DSA(pk, private)) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		goto err;
	}

	key->pk = pk;
	pk = NULL;

err:
	EVP_PKEY_free(pk);
	DSA_free(private);
	return r;
}

#ifdef OPENSSL_HAS_ECC
int
sshkey_generate_ecdsa(u_int bits, struct sshkey *key) {
	EVP_PKEY *pk;
	EC_KEY *private = NULL;
	int r = 0, nid;

	nid = sshkey_ecdsa_bits_to_nid(bits);
	if (nid == -1) return SSH_ERR_KEY_LENGTH;

	if ((pk = EVP_PKEY_new()) == NULL ||
	    (private = ssh_EC_KEY_new_by_curve_name(nid)) == NULL
	) {
		r = SSH_ERR_ALLOC_FAIL;
		goto err;
	}

	if (EC_KEY_generate_key(private) != 1) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		goto err;
	}

	if (!EVP_PKEY_set1_EC_KEY(pk, private)) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		goto err;
	}

	key->pk = pk;
	pk = NULL;
	key->ecdsa_nid = nid;

err:
	EVP_PKEY_free(pk);
	EC_KEY_free(private);
	return r;
}
#endif /* OPENSSL_HAS_ECC */


int
sshbuf_read_pub_rsa(struct sshbuf *buf, struct sshkey *key) {
	int r;
	BIGNUM *n = NULL, *e = NULL;

	if ((r = sshbuf_get_bignum2(buf, &n)) != 0 ||
	    (r = sshbuf_get_bignum2(buf, &e)) != 0)
		goto err;

	/* key attribute allocation */
	r = sshkey_init_rsa_key(key, n, e, NULL);
	if (r != 0) goto err;
	n = e = NULL; /* transferred */

	r = ssh_EVP_PKEY_complete_pub_rsa(key->pk);
	if (r != 0) goto err;

	/* success */
	SSHKEY_DUMP(key);
	return 0;

err:
	BN_clear_free(n);
	BN_clear_free(e);
	sshkey_clear_pkey(key);
	return r;
}


int
sshbuf_write_pub_rsa(struct sshbuf *buf, const struct sshkey *key) {
	int r;
	const BIGNUM *n = NULL, *e = NULL;

{	RSA *rsa = EVP_PKEY_get1_RSA(key->pk);
	if (rsa == NULL)
		return SSH_ERR_INVALID_ARGUMENT;
	RSA_get0_key(rsa, &n, &e, NULL);
	RSA_free(rsa);
}
	if ((r = sshbuf_put_bignum2(buf, n)) != 0 ||
	    (r = sshbuf_put_bignum2(buf, e)) != 0)
		return r;

	return 0;
}


int
sshbuf_read_pub_rsa_inv(struct sshbuf *buf, struct sshkey *key) {
	int r;
	BIGNUM *n = NULL, *e = NULL;

	if ((r = sshbuf_get_bignum2(buf, &e)) != 0 ||
	    (r = sshbuf_get_bignum2(buf, &n)) != 0)
		goto err;

	/* key attribute allocation */
	r = sshkey_init_rsa_key(key, n, e, NULL);
	if (r != 0) goto err;
	n = e = NULL; /* transferred */

	r = ssh_EVP_PKEY_complete_pub_rsa(key->pk);
	if (r != 0) goto err;

	/* success */
	SSHKEY_DUMP(key);
	return 0;

err:
	BN_clear_free(n);
	BN_clear_free(e);
	sshkey_clear_pkey(key);
	return r;
}

int
sshbuf_write_pub_rsa_inv(struct sshbuf *buf, const struct sshkey *key) {
	int r;
	const BIGNUM *n = NULL, *e = NULL;

{	RSA *rsa = EVP_PKEY_get1_RSA(key->pk);
	if (rsa == NULL)
		return SSH_ERR_INVALID_ARGUMENT;
	RSA_get0_key(rsa, &n, &e, NULL);
	RSA_free(rsa);
}
	if ((r = sshbuf_put_bignum2(buf, e)) != 0 ||
	    (r = sshbuf_put_bignum2(buf, n)) != 0)
		return r;
	return 0;
}


int
sshbuf_read_priv_rsa(struct sshbuf *buf, struct sshkey *key) {
	int r;
	RSA *rsa = NULL;
	BIGNUM *d = NULL, *iqmp = NULL, *p = NULL, *q = NULL;

	if ((r = sshbuf_get_bignum2(buf, &d)) != 0 ||
	    (r = sshbuf_get_bignum2(buf, &iqmp)) != 0 ||
	    (r = sshbuf_get_bignum2(buf, &p)) != 0 ||
	    (r = sshbuf_get_bignum2(buf, &q)) != 0)
		goto err;

	rsa = EVP_PKEY_get1_RSA(key->pk);
	if (rsa == NULL) {
		r = SSH_ERR_INVALID_ARGUMENT;
		goto err;
	}

	if (!RSA_set0_key(rsa, NULL, NULL, d)) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		goto err;
	}
	d = NULL; /* transferred */

	if (!RSA_set0_factors(rsa, p, q)) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		goto err;
	}
	p = q = NULL; /* transferred */

	r = sshrsa_complete_crt_parameters(rsa, iqmp);
	if (r != 0) goto err;

	/* success */
	SSHKEY_DUMP(key);
	BN_clear_free(iqmp);
	RSA_free(rsa);
	return 0;

err:
	BN_clear_free(d);
	BN_clear_free(p);
	BN_clear_free(q);
	BN_clear_free(iqmp);
	RSA_free(rsa);
	return r;
}

int
sshbuf_write_priv_rsa(struct sshbuf *buf, const struct sshkey *key) {
	int r;
	const BIGNUM *d = NULL, *iqmp = NULL, *p = NULL, *q = NULL;

{	RSA *rsa = EVP_PKEY_get1_RSA(key->pk);
	if (rsa == NULL)
		return SSH_ERR_INVALID_ARGUMENT;
	RSA_get0_key(rsa, NULL, NULL, &d);
	RSA_get0_crt_params(rsa, NULL, NULL, &iqmp);
	RSA_get0_factors(rsa, &p, &q);
	RSA_free(rsa);
}
	if ((r = sshbuf_put_bignum2(buf, d)) != 0 ||
	    (r = sshbuf_put_bignum2(buf, iqmp)) != 0 ||
	    (r = sshbuf_put_bignum2(buf, p)) != 0 ||
	    (r = sshbuf_put_bignum2(buf, q)) != 0)
		return r;

	return 0;
}


int
sshbuf_read_pub_dsa(struct sshbuf *buf, struct sshkey *key) {
	int r;
	BIGNUM *p = NULL, *q = NULL, *g = NULL;
	BIGNUM *pub_key = NULL;

	if ((r = sshbuf_get_bignum2(buf, &p)) != 0 ||
	    (r = sshbuf_get_bignum2(buf, &q)) != 0 ||
	    (r = sshbuf_get_bignum2(buf, &g)) != 0 ||
	    (r = sshbuf_get_bignum2(buf, &pub_key)) != 0)
		goto err;

	/* key attribute allocation */
	r = sshkey_init_dsa_params(key, p, q, g);
	if (r != 0) goto err;
	p = q = g = NULL; /* transferred */

	r = sshkey_set_dsa_key(key, pub_key, NULL);
	if (r != 0) goto err;
	pub_key = NULL; /* transferred */

	r = sshkey_validate_public_dsa(key);
	if (r != 0) goto err;

	/* success */
	SSHKEY_DUMP(key);
	return 0;

err:
	BN_clear_free(p);
	BN_clear_free(q);
	BN_clear_free(g);
	BN_clear_free(pub_key);
	sshkey_clear_pkey(key);
	return r;
}

int
sshbuf_write_pub_dsa(struct sshbuf *buf, const struct sshkey *key) {
	int r;
	const BIGNUM *p = NULL, *q = NULL, *g = NULL;
	const BIGNUM *pub_key = NULL;

{	DSA *dsa = EVP_PKEY_get1_DSA(key->pk);
	if (dsa == NULL)
		return SSH_ERR_INVALID_ARGUMENT;
	DSA_get0_pqg(dsa, &p, &q, &g);
	DSA_get0_key(dsa, &pub_key, NULL);
	DSA_free(dsa);
}
	if ((r = sshbuf_put_bignum2(buf, p)) != 0 ||
	    (r = sshbuf_put_bignum2(buf, q)) != 0 ||
	    (r = sshbuf_put_bignum2(buf, g)) != 0 ||
	    (r = sshbuf_put_bignum2(buf, pub_key)) != 0)
		return r;

	return 0;
}


int
sshbuf_read_priv_dsa(struct sshbuf *buf, struct sshkey *key) {
	int r;
	BIGNUM *priv_key = NULL;

	if ((r = sshbuf_get_bignum2(buf, &priv_key)) != 0)
		goto err;

	r = sshkey_set_dsa_key(key, NULL, priv_key);
	if (r != 0) goto err;
	/* priv_key = NULL; transferred */

	/* success */
	SSHKEY_DUMP(key);
	return 0;

err:
	BN_clear_free(priv_key);
	return r;
}

int
sshbuf_write_priv_dsa(struct sshbuf *buf, const struct sshkey *key) {
	const BIGNUM *priv_key = NULL;

{	DSA *dsa = EVP_PKEY_get1_DSA(key->pk);
	if (dsa == NULL)
		return SSH_ERR_INVALID_ARGUMENT;
	DSA_get0_key(dsa, NULL, &priv_key);
	DSA_free(dsa);
}
	return sshbuf_put_bignum2(buf, priv_key);
}


#ifdef OPENSSL_HAS_ECC
int
sshbuf_read_pub_ecdsa(struct sshbuf *buf, struct sshkey *key) {
	int r;
	EC_KEY *ec;

	r = sshkey_init_ecdsa_curve(key, key->ecdsa_nid);
	if (r != 0) return r;

	ec = EVP_PKEY_get1_EC_KEY(key->pk);
	if (ec == NULL)
		return SSH_ERR_LIBCRYPTO_ERROR;

	r = sshbuf_get_eckey(buf, ec);
	if (r != 0) goto err;

	r = sshkey_validate_ec_pub(ec);
	if (r != 0) goto err;

	/* success */
	SSHKEY_DUMP(key);

err:
	EC_KEY_free(ec);
	return r;
}

int
sshbuf_write_pub_ecdsa(struct sshbuf *buf, const struct sshkey *key) {
	int r;
	EC_KEY *ec;

	ec = EVP_PKEY_get1_EC_KEY(key->pk);
	if (ec == NULL)
		return SSH_ERR_INVALID_ARGUMENT;

	r = sshbuf_put_eckey(buf, ec);

	EC_KEY_free(ec);
	return r;
}

int
sshbuf_read_priv_ecdsa(struct sshbuf *buf, struct sshkey *key) {
	int r;
	EC_KEY *ec = NULL;
	BIGNUM *exponent = NULL;

	if ((r = sshbuf_get_bignum2(buf, &exponent)) != 0)
		goto err;

	ec = EVP_PKEY_get1_EC_KEY(key->pk);
	if (ec == NULL) {
		r = SSH_ERR_INVALID_ARGUMENT;
		goto err;
	}

	if (EC_KEY_set_private_key(ec, exponent) != 1) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		goto err;
	}
	/*no! exponent = NULL; transferred */

	r = sshkey_validate_ec_priv(ec);
	if (r != 0) goto err;

	SSHKEY_DUMP(key);

err:
	BN_clear_free(exponent);
	EC_KEY_free(ec);
	return r;
}

int
sshbuf_write_priv_ecdsa(struct sshbuf *buf, const struct sshkey *key) {
	const BIGNUM *exponent = NULL;

{	EC_KEY *ec = EVP_PKEY_get1_EC_KEY(key->pk);
	if (ec == NULL)
		return SSH_ERR_INVALID_ARGUMENT;
	exponent = EC_KEY_get0_private_key(ec);
	EC_KEY_free(ec);
}
	return sshbuf_put_bignum2(buf, exponent);
}
#endif /* OPENSSL_HAS_ECC */


/* write identity in PEM formats - PKCS#8 or Traditional */
int
sshkey_private_to_bio(struct sshkey *key, BIO *bio,
    const char *passphrase, int format)
{
	int res;
	int len = strlen(passphrase);
	const EVP_CIPHER *cipher = (len > 0) ? EVP_aes_256_cbc() : NULL;
	u_char *_passphrase = (len > 0) ? (u_char*)passphrase : NULL;

	if (key->pk == NULL)
		return SSH_ERR_INVALID_ARGUMENT;
	if (len > 0 && len <= 4)
		return SSH_ERR_PASSPHRASE_TOO_SHORT;
	if (len > INT_MAX)
		return SSH_ERR_INVALID_ARGUMENT;

	if (format == SSHKEY_PRIVATE_PEM) {
		switch (key->type) {
		case KEY_RSA: {
			RSA *rsa = EVP_PKEY_get1_RSA(key->pk);
			res = PEM_write_bio_RSAPrivateKey(bio, rsa,
			    cipher, _passphrase, len, NULL, NULL);
			RSA_free(rsa);
			} break;
#ifdef OPENSSL_HAS_ECC
		case KEY_ECDSA: {
			EC_KEY *ec = EVP_PKEY_get1_EC_KEY(key->pk);
			res = PEM_write_bio_ECPrivateKey(bio, ec,
			    cipher, _passphrase, len, NULL, NULL);
			EC_KEY_free(ec);
			} break;
#endif
		case KEY_DSA: {
			DSA *dsa = EVP_PKEY_get1_DSA(key->pk);
			res = PEM_write_bio_DSAPrivateKey(bio, dsa,
			    cipher, _passphrase, len, NULL, NULL);
			DSA_free(dsa);
			} break;
		default:
			return SSH_ERR_INVALID_ARGUMENT;
		}
	} else
		res = PEM_write_bio_PKCS8PrivateKey(bio, key->pk, cipher,
		    _passphrase, len, NULL, NULL);

	if (res && sshkey_is_x509(key))
		res = x509key_write_identity_bio_pem(bio, key);

	return res ? 0 : SSH_ERR_LIBCRYPTO_ERROR;
}


/* methods used localy only in ssh-keygen.c */
extern int
sshbuf_get_bignum1x(struct sshbuf *buf, BIGNUM **valp);

extern int
sshbuf_read_custom_rsa(struct sshbuf *buf, struct sshkey *key);
extern int
sshbuf_read_custom_dsa(struct sshbuf *buf, struct sshkey *key);

extern int
sshkey_public_to_fp(struct sshkey *key, FILE *fp, int format);

extern int
sshkey_public_from_fp(FILE *fp, int format, struct sshkey **key);


int
sshbuf_read_custom_rsa(struct sshbuf *buf, struct sshkey *key) {
	int r;
	RSA *rsa = NULL;
	BIGNUM *n = NULL, *e;
	BIGNUM *d = NULL, *iqmp = NULL, *p = NULL, *q = NULL;

	e = BN_new();
	if (e == NULL)
		return SSH_ERR_ALLOC_FAIL;

{	BN_ULONG rsa_e;
	u_char e1, e2, e3;

	if ((r = sshbuf_get_u8(buf, &e1)) != 0 ||
	    (e1 < 30 && (r = sshbuf_get_u8(buf, &e2)) != 0) ||
	    (e1 < 30 && (r = sshbuf_get_u8(buf, &e3)) != 0)) {
		r = SSH_ERR_INVALID_FORMAT;
		goto err;
	}

	rsa_e = e1;
	debug3("e %lx", rsa_e);
	if (rsa_e < 30) {
		rsa_e <<= 8;
		rsa_e += e2;
		debug3("e %lx", rsa_e);
		rsa_e <<= 8;
		rsa_e += e3;
		debug3("e %lx", rsa_e);
	}

	if (!BN_set_word(e, rsa_e)) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		goto err;
	}
}

	if ((r = sshbuf_get_bignum1x(buf, &d)) != 0 ||
	    (r = sshbuf_get_bignum1x(buf, &n)) != 0 ||
	    (r = sshbuf_get_bignum1x(buf, &iqmp)) != 0 ||
	    (r = sshbuf_get_bignum1x(buf, &q)) != 0 ||
	    (r = sshbuf_get_bignum1x(buf, &p)) != 0)
		goto err;

	/* key attribute allocation */
	r = sshkey_init_rsa_key(key, n, e, d);
	if (r != 0) goto err;
	n = e = d = NULL; /* transferred */

	r = ssh_EVP_PKEY_complete_pub_rsa(key->pk);
	if (r != 0) goto err;

	rsa = EVP_PKEY_get1_RSA(key->pk);
	if (rsa == NULL) {
		r = SSH_ERR_ALLOC_FAIL;
		goto err;
	}

	if (!RSA_set0_factors(rsa, p, q)) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		goto err;
	}
	p = q = NULL; /* transferred */

	r = sshrsa_complete_crt_parameters(rsa, iqmp);
	if (r != 0) goto err;

	/* success */
	key->type = KEY_RSA;
	SSHKEY_DUMP(key);
	BN_clear_free(iqmp);
	RSA_free(rsa);
	return 0;

err:
	BN_clear_free(n);
	BN_clear_free(e);
	BN_clear_free(d);
	BN_clear_free(p);
	BN_clear_free(q);
	BN_clear_free(iqmp);
	RSA_free(rsa);
	sshkey_clear_pkey(key);
	return r;
}

int
sshbuf_read_custom_dsa(struct sshbuf *buf, struct sshkey *key) {
	int r;
	BIGNUM *p = NULL, *q = NULL, *g = NULL;
	BIGNUM *pub_key = NULL, *priv_key = NULL;

	if ((r = sshbuf_get_bignum1x(buf, &p)) != 0 ||
	    (r = sshbuf_get_bignum1x(buf, &g)) != 0 ||
	    (r = sshbuf_get_bignum1x(buf, &q)) != 0 ||
	    (r = sshbuf_get_bignum1x(buf, &pub_key)) != 0 ||
	    (r = sshbuf_get_bignum1x(buf, &priv_key)) != 0)
		goto err;

	/* key attribute allocation */
	r = sshkey_init_dsa_params(key, p, q, g);
	if (r != 0) goto err;
	p = q = g = NULL; /* transferred */

	r = sshkey_set_dsa_key(key, pub_key, priv_key);
	if (r != 0) goto err;
	pub_key = priv_key = NULL; /* transferred */

	r = sshkey_validate_public_dsa(key);
	if (r != 0) goto err;

	/* success */
	key->type = KEY_DSA;
	SSHKEY_DUMP(key);
	return 0;

err:
	BN_clear_free(p);
	BN_clear_free(q);
	BN_clear_free(g);
	BN_clear_free(pub_key);
	BN_clear_free(priv_key);
	sshkey_clear_pkey(key);
	return r;
}


int
sshkey_public_to_fp(struct sshkey *key, FILE *fp, int format) {
	int res;

	if ((format != SSHKEY_PRIVATE_PEM) &&
	    (format != SSHKEY_PRIVATE_PKCS8))
		return SSH_ERR_INVALID_ARGUMENT;

	if (key->pk == NULL)
		return SSH_ERR_INVALID_ARGUMENT;

	if ((format == SSHKEY_PRIVATE_PEM) &&
	    /* Traditional PEM is available only for RSA */
	    (key->type == KEY_RSA)
	) {
		RSA *rsa = EVP_PKEY_get1_RSA(key->pk);
		res = PEM_write_RSAPublicKey(fp, rsa);
		RSA_free(rsa);
	} else
		res = PEM_write_PUBKEY(fp, key->pk);

	return res ? 0 : SSH_ERR_LIBCRYPTO_ERROR;
}

int
sshkey_public_from_fp(FILE *fp, int format, struct sshkey **key) {
	int r;

	if (format == SSHKEY_PRIVATE_PKCS8) {
		EVP_PKEY *pk = PEM_read_PUBKEY(fp, NULL, NULL, NULL);
		if (pk != NULL) {
			r = sshkey_from_pkey(pk, key);
			if (r == 0)
				pk = NULL; /* transferred */
		} else
		    r = SSH_ERR_INVALID_FORMAT;
		EVP_PKEY_free(pk);
		return r;
	}

	if (format != SSHKEY_PRIVATE_PEM)
		return SSH_ERR_INVALID_ARGUMENT;

{	/* Traditional PEM is available only for RSA */
	RSA *rsa;
	EVP_PKEY *pk = NULL;
	struct sshkey *k = NULL;

	rsa = PEM_read_RSAPublicKey(fp, NULL, NULL, NULL);
	if (rsa == NULL) return SSH_ERR_INVALID_FORMAT;

	pk = EVP_PKEY_new();
	if (pk == NULL) {
		r = SSH_ERR_ALLOC_FAIL;
		goto err;
	}
	if (!EVP_PKEY_set1_RSA(pk, rsa)) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		goto err;
	}

	k = sshkey_new(KEY_UNSPEC);
	if (k == NULL) {
		r = SSH_ERR_ALLOC_FAIL;
		goto err;
	}

	k->type = KEY_RSA;
	k->pk = pk;
	RSA_free(rsa);

	*key = k;
	return 0;

err:
	EVP_PKEY_free(pk);
	RSA_free(rsa);
	sshkey_free(k);
	return r;
}
}

#else

typedef int sshkey_crypto_empty_translation_unit;

#endif /* WITH_OPENSSL */
