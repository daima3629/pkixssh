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

static inline int
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
sshkey_dump(const char *func, const struct sshkey *key) {
	fprintf(stderr, "dump key %s():\n", func);
	switch (sshkey_type_plain(key->type)) {
	case KEY_RSA:
		RSA_print_fp(stderr, key->rsa, 0);
		break;
	case KEY_DSA:
		DSA_print_fp(stderr, key->dsa, 0);
		break;
#ifdef OPENSSL_HAS_ECC
	case KEY_ECDSA:
		sshkey_dump_ec_key(key->ecdsa);
		break;
	}
#endif /* OPENSSL_HAS_ECC */
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
sshkey_validate_rsa_pub(RSA *rsa) {
	int r;
	const BIGNUM *n = NULL;

	RSA_get0_key(rsa, &n, NULL, NULL);

	r = sshrsa_verify_length(BN_num_bits(n));
	if (r != 0) return r;

	/* other checks ? */
	return 0;
}

static int
sshkey_validate_dsa_pub(DSA *dsa) {
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
sshkey_validate_ec_pub(EC_KEY *ec) {
	int r;

	r = sshkey_ec_validate_public(EC_KEY_get0_group(ec),
	    EC_KEY_get0_public_key(ec));
	if (r != 0) return r;

	/* other checks ? */
	return 0;
}

static int
sshkey_validate_ec_priv(EC_KEY *ec) {
	int r;

	r = sshkey_ec_validate_private(ec);
	if (r != 0) return r;

	/* other checks ? */
	return 0;
}
#endif


struct sshkey*
sshkey_new_rsa(struct sshkey *key) {
	RSA *rsa = RSA_new();
	if (rsa == NULL) {
		free(key);
		return NULL;
	}
	key->rsa = rsa;
	return key;
}

struct sshkey*
sshkey_new_dsa(struct sshkey *key) {
	DSA *dsa = DSA_new();
	if (dsa == NULL) {
		free(key);
		return NULL;
	}
	key->dsa = dsa;
	return key;
}


void
sshkey_free_rsa(struct sshkey *key) {
	RSA_free(key->rsa);
	key->rsa = NULL;

	EVP_PKEY_free(key->pk);
	key->pk = NULL;
}

void
sshkey_free_dsa(struct sshkey *key) {
	DSA_free(key->dsa);
	key->dsa = NULL;

	EVP_PKEY_free(key->pk);
	key->pk = NULL;
}

#ifdef OPENSSL_HAS_ECC
void
sshkey_free_ecdsa(struct sshkey *key) {
	EC_KEY_free(key->ecdsa);
	key->ecdsa = NULL;

	EVP_PKEY_free(key->pk);
	key->pk = NULL;
}
#endif /* OPENSSL_HAS_ECC */


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
	/* dmp1 = dmq1 = iqmp = NULL; transferred */

	/* success */
	return 0;

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
sshkey_from_pkey_rsa(EVP_PKEY *pk, struct sshkey **keyp) {
	int r;
	struct sshkey* key;
	RSA *rsa;

	key = sshkey_new(KEY_UNSPEC);
	if (key == NULL)
		return SSH_ERR_ALLOC_FAIL;

	rsa = EVP_PKEY_get1_RSA(pk);
	if (rsa == NULL)
		return SSH_ERR_LIBCRYPTO_ERROR;

	r = sshkey_validate_rsa_pub(rsa);
	if (r != 0) goto err;

	if (RSA_blinding_on(rsa, NULL) != 1) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		goto err;
	}

	/* success */
	key->type = KEY_RSA;
	key->pk = pk;
	key->rsa = rsa; /*TODO */

	SSHKEY_DUMP(key);
	*keyp = key;
	return 0;

err:
	RSA_free(rsa);
	sshkey_free(key);
	return r;
}

static int
sshkey_from_pkey_dsa(EVP_PKEY *pk, struct sshkey **keyp) {
	int r;
	struct sshkey* key;
	DSA *dsa;

	key = sshkey_new(KEY_UNSPEC);
	if (key == NULL)
		return SSH_ERR_ALLOC_FAIL;

	dsa = EVP_PKEY_get1_DSA(pk);
	if (dsa == NULL)
		return SSH_ERR_LIBCRYPTO_ERROR;

	r = sshkey_validate_dsa_pub(dsa);
	if (r != 0) goto err;

	/* success */
	key->type = KEY_DSA;
	key->pk = pk;
	key->dsa = dsa; /* TODO */

	SSHKEY_DUMP(key);
	*keyp = key;
	return 0;

err:
	DSA_free(dsa);
	sshkey_free(key);
	return r;
}

#ifdef OPENSSL_HAS_ECC
static int
sshkey_from_pkey_ecdsa(EVP_PKEY *pk, struct sshkey **keyp) {
	int r;
	struct sshkey* key;
	EC_KEY *ec;
	int nid;

	key = sshkey_new(KEY_UNSPEC);
	if (key == NULL)
		return SSH_ERR_ALLOC_FAIL;

	ec = EVP_PKEY_get1_EC_KEY(pk);
	if (ec == NULL)
		return SSH_ERR_LIBCRYPTO_ERROR;

	nid = sshkey_ecdsa_key_to_nid(ec);
	if (nid < 0) {
		error_f("unsupported elliptic curve");
		r = SSH_ERR_EC_CURVE_INVALID;
		goto err;
	}

	r = sshkey_validate_ec_pub(ec);
	if (r != 0) goto err;

{	/* private part is not required */
	const BIGNUM *exponent = EC_KEY_get0_private_key(ec);
	if (exponent == NULL) goto skip_private;

	r = sshkey_validate_ec_priv(ec);
	if (r != 0) goto err;
}
skip_private:

	/* success */
	key->type = KEY_ECDSA;
	key->ecdsa_nid = nid;
	key->pk = pk;
	key->ecdsa = ec; /* TODO */

	SSHKEY_DUMP(key);
	*keyp = key;
	return 0;

err:
	EC_KEY_free(ec);
	sshkey_free(key);
	return r;
}
#endif /* OPENSSL_HAS_ECC */

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
	default:
		error_f("unsupported pkey type %d", evp_id);
		r = SSH_ERR_KEY_TYPE_UNKNOWN;
	}

	return r;
}


int
EVP_PKEY_to_sshkey_type(int type, EVP_PKEY *pk, struct sshkey **keyp) {
	int evp_id;

	if (type == KEY_UNSPEC) goto load;

	evp_id = EVP_PKEY_base_id(pk);
	if (
	    (evp_id == EVP_PKEY_RSA && type == KEY_RSA) ||
#ifdef OPENSSL_HAS_ECC
	    (evp_id == EVP_PKEY_EC && type == KEY_ECDSA) ||
#endif /*def OPENSSL_HAS_ECC*/
	    (evp_id == EVP_PKEY_DSA && type == KEY_DSA)
	)
		goto load;

	return SSH_ERR_KEY_TYPE_MISMATCH;

load:
/* called function sets SSH_ERR_KEY_TYPE_UNKNOWN if evp id is not supported */
	return sshkey_from_pkey(pk, keyp);
}

int
sshkey_complete_pkey(struct sshkey *key) {
	int r = 0, ok = 0;
	EVP_PKEY *pk;

	if (key->pk != NULL) fatal_f("TESTING");

	pk = EVP_PKEY_new();
	if (pk == NULL)
		return SSH_ERR_ALLOC_FAIL;

	if (key->rsa != NULL)
		ok = EVP_PKEY_set1_RSA(pk, key->rsa);
#ifdef OPENSSL_HAS_ECC
	else if (key->ecdsa != NULL)
		ok = EVP_PKEY_set1_EC_KEY(pk, key->ecdsa);
#endif /* OPENSSL_HAS_ECC */
	else if (key->dsa != NULL)
		ok = EVP_PKEY_set1_DSA(pk, key->dsa);
	else {
		r = SSH_ERR_INTERNAL_ERROR;
		goto err;
	}
	if (!ok) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		goto err;
	}

	key->pk = pk;
	return 0;

err:
	EVP_PKEY_free(pk);
	return r;
}


int
sshkey_dup_pub_rsa(const struct sshkey *from, struct sshkey *to) {
	int r;
	const BIGNUM *k_n, *k_e;
	BIGNUM *n_n = NULL, *n_e = NULL;

	RSA_get0_key(from->rsa, &k_n, &k_e, NULL);

	if ((n_n = BN_dup(k_n)) == NULL ||
	    (n_e = BN_dup(k_e)) == NULL) {
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	if (!RSA_set0_key(to->rsa, n_n, n_e, NULL)) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		goto out;
	}
	n_n = n_e = NULL; /* transferred */

	r = sshkey_complete_pkey(to);

out:
	BN_clear_free(n_n);
	BN_clear_free(n_e);

	return r;
}

int
sshkey_dup_pub_dsa(const struct sshkey *from, struct sshkey *to) {
	int r;
	const BIGNUM *k_p, *k_q, *k_g, *k_pub_key;
	BIGNUM *n_p = NULL, *n_q = NULL, *n_g = NULL, *n_pub_key = NULL;

	DSA_get0_pqg(from->dsa, &k_p, &k_q, &k_g);
	DSA_get0_key(from->dsa, &k_pub_key, NULL);

	if ((n_p = BN_dup(k_p)) == NULL ||
	    (n_q = BN_dup(k_q)) == NULL ||
	    (n_g = BN_dup(k_g)) == NULL ||
	    (n_pub_key = BN_dup(k_pub_key)) == NULL) {
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	if (!DSA_set0_pqg(to->dsa, n_p, n_q, n_g)) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		goto out;
	}
	n_p = n_q = n_g = NULL; /* transferred */
	if (!DSA_set0_key(to->dsa, n_pub_key, NULL)) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		goto out;
	}
	n_pub_key = NULL; /* transferred */

	r = sshkey_complete_pkey(to);

out:
	BN_clear_free(n_p);
	BN_clear_free(n_q);
	BN_clear_free(n_g);
	BN_clear_free(n_pub_key);

	return r;
}

#ifdef OPENSSL_HAS_ECC
int
sshkey_dup_pub_ecdsa(const struct sshkey *from, struct sshkey *to) {
	int r;

	to->ecdsa_nid = from->ecdsa_nid;
	to->ecdsa = EC_KEY_new_by_curve_name(from->ecdsa_nid);
	if (to->ecdsa == NULL) {
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	if (EC_KEY_set_public_key(to->ecdsa,
	    EC_KEY_get0_public_key(from->ecdsa)) != 1) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		goto out;
	}

	r = sshkey_complete_pkey(to);

out:
	return r;
}
#endif /* OPENSSL_HAS_ECC */


static void
sshkey_move_pk(struct sshkey *from, struct sshkey *to) {
	EVP_PKEY_free(to->pk);
	to->pk = from->pk;
	from->pk = NULL;
}

void
sshkey_move_rsa(struct sshkey *from, struct sshkey *to) {
	sshkey_move_pk(from, to);
	RSA_free(to->rsa);
	to->rsa = from->rsa;
	from->rsa = NULL;
}

void
sshkey_move_dsa(struct sshkey *from, struct sshkey *to) {
	sshkey_move_pk(from, to);
	DSA_free(to->dsa);
	to->dsa = from->dsa;
	from->dsa = NULL;
}

#ifdef OPENSSL_HAS_ECC
void
sshkey_move_ecdsa(struct sshkey *from, struct sshkey *to) {
	sshkey_move_pk(from, to);
	EC_KEY_free(to->ecdsa);
	to->ecdsa = from->ecdsa;
	from->ecdsa = NULL;
	to->ecdsa_nid = from->ecdsa_nid;
	from->ecdsa_nid = -1;
}
#endif /* OPENSSL_HAS_ECC */


int/*bool*/
sshkey_equal_public_rsa(const struct sshkey *ka, const struct sshkey *kb) {
	const RSA *a, *b;
	const BIGNUM *a_n, *a_e;
	const BIGNUM *b_n, *b_e;

	if (ka == NULL || kb == NULL)
		return 0;

	a = ka->rsa;
	b = kb->rsa;
	if (a == NULL || b == NULL)
		return 0;

	RSA_get0_key(a, &a_n, &a_e, NULL);
	RSA_get0_key(b, &b_n, &b_e, NULL);

	return
	    BN_cmp(a_n, b_n) == 0 &&
	    BN_cmp(a_e, b_e) == 0;
}

int/*bool*/
sshkey_equal_public_dsa(const struct sshkey *ka, const struct sshkey *kb) {
	const DSA *a, *b;
	const BIGNUM *a_p, *a_q, *a_g, *a_pub_key;
	const BIGNUM *b_p, *b_q, *b_g, *b_pub_key;

	if (ka == NULL || kb == NULL)
		return 0;

	a = ka->dsa;
	b = kb->dsa;
	if (a == NULL || b == NULL)
		return 0;

	DSA_get0_pqg(a, &a_p, &a_q, &a_g);
	DSA_get0_key(a, &a_pub_key, NULL);

	DSA_get0_pqg(b, &b_p, &b_q, &b_g);
	DSA_get0_key(b, &b_pub_key, NULL);

	return
	    BN_cmp(a_p, b_p) == 0 &&
	    BN_cmp(a_q, b_q) == 0 &&
	    BN_cmp(a_g, b_g) == 0 &&
	    BN_cmp(a_pub_key, b_pub_key) == 0;
}

#ifdef OPENSSL_HAS_ECC
int/*bool*/
sshkey_equal_public_ecdsa(const struct sshkey *ka, const struct sshkey *kb) {
	const EC_KEY *a, *b;
	const EC_POINT *pa, *pb;
	const EC_GROUP *g;
	BN_CTX *bnctx;
	int ret;

	if (ka == NULL || kb == NULL)
		return 0;

	a = ka->ecdsa;
	b = kb->ecdsa;
	if (a == NULL || b == NULL)
		return 0;

	pa = EC_KEY_get0_public_key(a);
	pb = EC_KEY_get0_public_key(b);
	if (pa == NULL || pb == NULL)
		return 0;

	bnctx = BN_CTX_new();
	if (bnctx == NULL) return 0;

	g = EC_KEY_get0_group(a);

	ret = EC_GROUP_cmp(g, EC_KEY_get0_group(b), bnctx) == 0 &&
	    EC_POINT_cmp(g, pa, pb, bnctx) == 0;

	BN_CTX_free(bnctx);
	return ret;
}
#endif /* OPENSSL_HAS_ECC */


int
sshkey_validate_public_rsa(const struct sshkey *key) {
	if (key == NULL || key->rsa == NULL ||
	    sshkey_type_plain(key->type) != KEY_RSA)
		return SSH_ERR_INVALID_ARGUMENT;

	return sshkey_validate_rsa_pub(key->rsa); /* TODO */
}


int
sshkey_validate_public_dsa(const struct sshkey *key) {
	if (key == NULL || key->dsa == NULL ||
	    sshkey_type_plain(key->type) != KEY_DSA)
		return SSH_ERR_INVALID_ARGUMENT;

	return sshkey_validate_dsa_pub(key->dsa); /* TODO */
}


#ifdef OPENSSL_HAS_ECC
int
sshkey_validate_public_ecdsa(const struct sshkey *key) {
	if (key == NULL || key->ecdsa == NULL ||
	    sshkey_type_plain(key->type) != KEY_ECDSA)
		return SSH_ERR_INVALID_ARGUMENT;

	return sshkey_validate_ec_pub(key->ecdsa); /* TODO */
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


int
sshkey_generate_rsa(u_int bits, struct sshkey *key) {
	RSA *private = NULL;
	BIGNUM *f4 = NULL;
	int r;

	r = sshrsa_verify_length(bits);
	if (r != 0) return r;

	if (bits > SSHBUF_MAX_BIGNUM * 8)
		return SSH_ERR_KEY_LENGTH;

	if ((private = RSA_new()) == NULL || (f4 = BN_new()) == NULL) {
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	if (!BN_set_word(f4, RSA_F4) ||
	    !RSA_generate_key_ex(private, bits, f4, NULL)) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		goto out;
	}

	key->rsa = private;
	private = NULL;

	r = sshkey_complete_pkey(key);

out:
	RSA_free(private);
	BN_free(f4);
	return r;
}

int
sshkey_generate_dsa(u_int bits, struct sshkey *key) {
	DSA *private;
	int r;

	r = sshdsa_verify_length(bits);
	if (r != 0) return r;

	if ((private = DSA_new()) == NULL) {
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}

	if (!DSA_generate_parameters_ex(private, bits, NULL, 0, NULL, NULL, NULL) ||
	    !DSA_generate_key(private)) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		goto out;
	}

	key->dsa = private;
	private = NULL;

	r = sshkey_complete_pkey(key);

out:
	DSA_free(private);
	return r;
}

#ifdef OPENSSL_HAS_ECC
int
sshkey_generate_ecdsa(u_int bits, struct sshkey *key) {
	EC_KEY *private;
	int r, nid;

	nid = sshkey_ecdsa_bits_to_nid(bits);
	if (nid == -1) return SSH_ERR_KEY_LENGTH;

	if ((private = EC_KEY_new_by_curve_name(nid)) == NULL) {
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}

	if (EC_KEY_generate_key(private) != 1) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		goto out;
	}

	EC_KEY_set_asn1_flag(private, OPENSSL_EC_NAMED_CURVE);

	key->ecdsa = private;
	key->ecdsa_nid = nid;
	private = NULL;

	r = sshkey_complete_pkey(key);

out:
	EC_KEY_free(private);
	return r;
}
#endif /* OPENSSL_HAS_ECC */


int
sshbuf_read_pub_rsa(struct sshbuf *buf, struct sshkey *key) {
	int r;
	EVP_PKEY *pk = NULL;
	RSA *rsa = NULL;
	BIGNUM *n = NULL, *e = NULL;

	if ((r = sshbuf_get_bignum2(buf, &n)) != 0 ||
	    (r = sshbuf_get_bignum2(buf, &e)) != 0)
		goto err;

	/* key attribute allocation */
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

	/* transfer to key */
	if (!RSA_set0_key(rsa, n, e, NULL)) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		goto err;
	}
	n = e = NULL; /* transferred */

	r = sshkey_validate_rsa_pub(rsa);
	if (r != 0) goto err;

	if (RSA_blinding_on(rsa, NULL) != 1) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		goto err;
	}

	/* success */
	key->pk = pk;
	RSA_free(key->rsa); key->rsa = rsa; /* TODO */
	SSHKEY_DUMP(key);
	return 0;

err:
	BN_clear_free(n);
	BN_clear_free(e);
	RSA_free(rsa);
	EVP_PKEY_free(pk);
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
	EVP_PKEY *pk = NULL;
	RSA *rsa = NULL;
	BIGNUM *n = NULL, *e = NULL;

	if ((r = sshbuf_get_bignum2(buf, &e)) != 0 ||
	    (r = sshbuf_get_bignum2(buf, &n)) != 0)
		goto err;

	/* key attribute allocation */
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

	/* transfer to key */
	if (!RSA_set0_key(rsa, n, e, NULL)) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		goto err;
	}
	n = e = NULL; /* transferred */

	r = sshkey_validate_rsa_pub(rsa);
	if (r != 0) goto err;

	if (RSA_blinding_on(rsa, NULL) != 1) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		goto err;
	}

	/* success */
	/* key->type = KEY_RSA; TODO custom certificates */
	key->pk = pk;
	RSA_free(key->rsa); key->rsa = rsa; /* TODO */
	SSHKEY_DUMP(key);
	return 0;

err:
	BN_clear_free(n);
	BN_clear_free(e);
	RSA_free(rsa);
	EVP_PKEY_free(pk);
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

	SSHKEY_DUMP(key);

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
		goto out;

	if (!DSA_set0_pqg(key->dsa, p, q, g)) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		goto out;
	}
	p = q = g = NULL; /* transferred */

	if (!DSA_set0_key(key->dsa, pub_key, NULL)) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		goto out;
	}
	pub_key = NULL; /* transferred */

	r = sshkey_validate_public_dsa(key);
	if (r != 0) goto out;

	r = sshkey_complete_pkey(key);
	if (r != 0) goto out;

	SSHKEY_DUMP(key);

out:
	BN_clear_free(p);
	BN_clear_free(q);
	BN_clear_free(g);
	BN_clear_free(pub_key);

	return r;
}

int
sshbuf_write_pub_dsa(struct sshbuf *buf, const struct sshkey *key) {
	int r;
	const BIGNUM *p = NULL, *q = NULL, *g = NULL;
	const BIGNUM *pub_key = NULL;

	if (key->dsa == NULL)
		return SSH_ERR_INVALID_ARGUMENT;

	DSA_get0_pqg(key->dsa, &p, &q, &g);
	DSA_get0_key(key->dsa, &pub_key, NULL);

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
		goto out;

	if (!DSA_set0_key(key->dsa, NULL, priv_key)) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		goto out;
	}
	priv_key = NULL; /* transferred */

	SSHKEY_DUMP(key);

out:
	BN_clear_free(priv_key);

	return r;
}

int
sshbuf_write_priv_dsa(struct sshbuf *buf, const struct sshkey *key) {
	const BIGNUM *priv_key = NULL;

	DSA_get0_key(key->dsa, NULL, &priv_key);
	return sshbuf_put_bignum2(buf, priv_key);
}


#ifdef OPENSSL_HAS_ECC
int
sshbuf_read_pub_ecdsa(struct sshbuf *buf, struct sshkey *key) {
	int r;
	char *curve = NULL;

	if ((r = sshbuf_get_cstring(buf, &curve, NULL)) != 0)
		goto out;
	if (key->ecdsa_nid != sshkey_curve_name_to_nid(curve)) {
		r = SSH_ERR_EC_CURVE_MISMATCH;
		goto out;
	}

	EC_KEY_free(key->ecdsa); /*???*/
	key->ecdsa = EC_KEY_new_by_curve_name(key->ecdsa_nid);
	if (key->ecdsa  == NULL) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		goto out;
	}
#if defined(OPENSSL_VERSION_NUMBER) && (OPENSSL_VERSION_NUMBER < 0x10100000L) || \
    defined(LIBRESSL_VERSION_NUMBER)
	/* Note OpenSSL 1.1.0 uses named curve parameter encoding by default. */
	EC_KEY_set_asn1_flag(key->ecdsa, OPENSSL_EC_NAMED_CURVE);
#endif

	r = sshbuf_get_eckey(buf, key->ecdsa);
	if (r != 0) goto out;

	r = sshkey_validate_public_ecdsa(key);
	if (r != 0) goto out;

	r = sshkey_complete_pkey(key);
	if (r != 0) goto out;

	SSHKEY_DUMP(key);

out:
	free(curve);

	return r;
}

int
sshbuf_write_pub_ecdsa(struct sshbuf *buf, const struct sshkey *key) {
	int r;
	const char *curve_name = sshkey_curve_nid_to_name(key->ecdsa_nid);

	if (key->ecdsa == NULL)
		return SSH_ERR_INVALID_ARGUMENT;

	if ((r = sshbuf_put_cstring(buf, curve_name)) != 0 ||
	    (r = sshbuf_put_eckey(buf, key->ecdsa)) != 0)
		return r;

	return 0;
}

int
sshbuf_read_priv_ecdsa(struct sshbuf *buf, struct sshkey *key) {
	int r;
	BIGNUM *exponent = NULL;

	if ((r = sshbuf_get_bignum2(buf, &exponent)) != 0)
		goto out;
	if (EC_KEY_set_private_key(key->ecdsa, exponent) != 1) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		goto out;
	}
	exponent = NULL; /* transferred */

	r = sshkey_validate_ec_priv(key->ecdsa); /* TODO */
	if (r != 0) goto out;

	SSHKEY_DUMP(key);

out:
	BN_clear_free(exponent);

	return r;
}

int
sshbuf_write_priv_ecdsa(struct sshbuf *buf, const struct sshkey *key) {
	return sshbuf_put_bignum2(buf, EC_KEY_get0_private_key(key->ecdsa));
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
		case KEY_RSA:
			res = PEM_write_bio_RSAPrivateKey(bio, key->rsa,
			    cipher, _passphrase, len, NULL, NULL);
			break;
#ifdef OPENSSL_HAS_ECC
		case KEY_ECDSA:
			res = PEM_write_bio_ECPrivateKey(bio, key->ecdsa,
			    cipher, _passphrase, len, NULL, NULL);
			break;
#endif
		case KEY_DSA:
			res = PEM_write_bio_DSAPrivateKey(bio, key->dsa,
			    cipher, _passphrase, len, NULL, NULL);
			break;
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
	EVP_PKEY *pk = NULL;
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

	/* transfer to key */
	if (!RSA_set0_key(rsa, n, e, d)) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		goto err;
	}
	n = e = d = NULL; /* transferred */

	if (!RSA_set0_factors(rsa, p, q)) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		goto err;
	}
	p = q = NULL; /* transferred */

	r = sshrsa_complete_crt_parameters(rsa, iqmp);
	if (r != 0) goto err;

	r = sshkey_validate_rsa_pub(rsa);
	if (r != 0) goto err;

	if (RSA_blinding_on(rsa, NULL) != 1) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		goto err;
	}

	/* success */
	key->type = KEY_RSA;
	key->pk = pk;
	key->rsa = rsa; /* TODO */
	SSHKEY_DUMP(key);
	return 0;

err:
	BN_clear_free(n);
	BN_clear_free(e);
	BN_clear_free(d);
	BN_clear_free(p);
	BN_clear_free(q);
	BN_clear_free(iqmp);
	RSA_free(rsa);
	EVP_PKEY_free(pk);
	return r;
}

int
sshbuf_read_custom_dsa(struct sshbuf *buf, struct sshkey *key) {
	int r;
	EVP_PKEY *pk = NULL;
	DSA *dsa = NULL;
	BIGNUM *p = NULL, *q = NULL, *g = NULL;
	BIGNUM *pub_key = NULL, *priv_key = NULL;

	if ((r = sshbuf_get_bignum1x(buf, &p)) != 0 ||
	    (r = sshbuf_get_bignum1x(buf, &g)) != 0 ||
	    (r = sshbuf_get_bignum1x(buf, &q)) != 0 ||
	    (r = sshbuf_get_bignum1x(buf, &pub_key)) != 0 ||
	    (r = sshbuf_get_bignum1x(buf, &priv_key)) != 0)
		goto err;

	/* key attribute allocation */
	pk = EVP_PKEY_new();
	if (pk == NULL) {
		r = SSH_ERR_ALLOC_FAIL;
		goto err;
	}
	dsa = DSA_new();
	if (dsa == NULL) {
		r = SSH_ERR_ALLOC_FAIL;
		goto err;
	}
	if (!EVP_PKEY_set1_DSA(pk, dsa)) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		goto err;
	}

	/* transfer to key */
	if (!DSA_set0_pqg(dsa, p, q, g)) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		goto err;
	}
	p = q = g = NULL; /* transferred */

	if (!DSA_set0_key(dsa, pub_key, priv_key)) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		goto err;
	}
	pub_key = priv_key = NULL; /* transferred */

	r = sshkey_validate_dsa_pub(dsa);
	if (r != 0) goto err;

	/* success */
	key->type = KEY_DSA;
	key->pk = pk;
	key->dsa = dsa; /* TODO */
	SSHKEY_DUMP(key);
	return 0;

err:
	BN_clear_free(p);
	BN_clear_free(q);
	BN_clear_free(g);
	BN_clear_free(pub_key);
	BN_clear_free(priv_key);
	DSA_free(dsa);
	EVP_PKEY_free(pk);
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
	    (key->type == KEY_RSA))
		res = PEM_write_RSAPublicKey(fp, key->rsa);
	else
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
	struct sshkey *k;

	rsa = PEM_read_RSAPublicKey(fp, NULL, NULL, NULL);
	if (rsa == NULL) return SSH_ERR_INVALID_FORMAT;

	k = sshkey_new(KEY_UNSPEC);
	if (k == NULL) return SSH_ERR_ALLOC_FAIL;

	k->type = KEY_RSA;
	k->rsa = rsa;
	rsa = NULL;

	r = sshkey_complete_pkey(k);
	if (r != 0) goto err;

	*key = k;
	return 0;

err:
	RSA_free(rsa);
	sshkey_free(k);
	return r;
}
}

#else

typedef int sshkey_crypto_empty_translation_unit;

#endif /* WITH_OPENSSL */
