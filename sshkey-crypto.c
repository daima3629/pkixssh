/*
 * Copyright (c) 2020 Roumen Petrov.  All rights reserved.
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

#include "sshkey.h"
#include "sshbuf.h"
#include "ssherr.h"
#include "log.h"


#ifdef DEBUG_PK
void
sshkey_dump(const struct sshkey *key) {
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
#endif /* DEBUG_PK */


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
}

void
sshkey_free_dsa(struct sshkey *key) {
	DSA_free(key->dsa);
	key->dsa = NULL;
}

#ifdef OPENSSL_HAS_ECC
void
sshkey_free_ecdsa(struct sshkey *key) {
	EC_KEY_free(key->ecdsa);
	key->ecdsa = NULL;
}
#endif /* OPENSSL_HAS_ECC */


int
sshkey_from_pkey_rsa(EVP_PKEY *pk, struct sshkey **keyp) {
	int r;
	struct sshkey* key;

	key = sshkey_new(KEY_UNSPEC);
	if (key == NULL)
		return SSH_ERR_ALLOC_FAIL;

	key->type = KEY_RSA;
	key->rsa = EVP_PKEY_get1_RSA(pk);
	if (key->rsa == NULL) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		goto err;
	}

	*keyp = key;
	return 0;

err:
	sshkey_free(key);
	return r;
}

int
sshkey_from_pkey_dsa(EVP_PKEY *pk, struct sshkey **keyp) {
	int r;
	struct sshkey* key;

	key = sshkey_new(KEY_UNSPEC);
	if (key == NULL)
		return SSH_ERR_ALLOC_FAIL;

	key->type = KEY_DSA;
	key->dsa = EVP_PKEY_get1_DSA(pk);
	if (key->dsa == NULL) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		goto err;
	}

	*keyp = key;
	return 0;

err:
	sshkey_free(key);
	return r;
}
#ifdef OPENSSL_HAS_ECC

int
sshkey_from_pkey_ecdsa(EVP_PKEY *pk, struct sshkey **keyp) {
	int r;
	struct sshkey* key;

	key = sshkey_new(KEY_UNSPEC);
	if (key == NULL)
		return SSH_ERR_ALLOC_FAIL;

	key->type = KEY_ECDSA;
	key->ecdsa = EVP_PKEY_get1_EC_KEY(pk);
	if (key->ecdsa == NULL) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		goto err;
	}

	key->ecdsa_nid = sshkey_ecdsa_key_to_nid(key->ecdsa);
	if (key->ecdsa_nid < 0) {
		error_f("unsupported elliptic curve");
		r = SSH_ERR_EC_CURVE_INVALID;
		goto err;
	}

	*keyp = key;
	return 0;

err:
	sshkey_free(key);
	return r;
}
#endif /* OPENSSL_HAS_ECC */


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

	/* success */
	r = 0;

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

	/* success */
	r = 0;

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

	/* success */
	r = 0;

out:
	return r;
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
sshbuf_read_pub_rsa(struct sshbuf *buf, struct sshkey *key) {
	int r;
	BIGNUM *n = NULL, *e = NULL;

	if ((r = sshbuf_get_bignum2(buf, &n)) != 0 ||
	    (r = sshbuf_get_bignum2(buf, &e)) != 0)
		goto out;

	if (!RSA_set0_key(key->rsa, n, e, NULL)) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		goto out;
	}
	n = e = NULL; /* transferred */

out:
	BN_clear_free(n);
	BN_clear_free(e);

	return r;
}


int
sshbuf_write_pub_rsa(struct sshbuf *buf, const struct sshkey *key) {
	int r;
	const BIGNUM *n = NULL, *e = NULL;

	RSA_get0_key(key->rsa, &n, &e, NULL);
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
		goto out;

	if (!RSA_set0_key(key->rsa, n, e, NULL)) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		goto out;
	}
	n = e = NULL; /* transferred */

out:
	BN_clear_free(n);
	BN_clear_free(e);

	return r;
}

int
sshbuf_write_pub_rsa_inv(struct sshbuf *buf, const struct sshkey *key) {
	int r;
	const BIGNUM *n = NULL, *e = NULL;

	RSA_get0_key(key->rsa, &n, &e, NULL);
	if ((r = sshbuf_put_bignum2(buf, e)) != 0 ||
	    (r = sshbuf_put_bignum2(buf, n)) != 0)
		return r;

	return 0;
}


int
sshbuf_read_priv_rsa(struct sshbuf *buf, struct sshkey *key) {
	int r;
	BIGNUM *d = NULL, *iqmp = NULL, *p = NULL, *q = NULL;

	if ((r = sshbuf_get_bignum2(buf, &d)) != 0 ||
	    (r = sshbuf_get_bignum2(buf, &iqmp)) != 0 ||
	    (r = sshbuf_get_bignum2(buf, &p)) != 0 ||
	    (r = sshbuf_get_bignum2(buf, &q)) != 0)
		goto out;

	if (!RSA_set0_key(key->rsa, NULL, NULL, d)) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		goto out;
	}
	d = NULL; /* transferred */

	if (!RSA_set0_factors(key->rsa, p, q)) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		goto out;
	}
	p = q = NULL; /* transferred */

	r = sshrsa_complete_crt_parameters(key, iqmp);

out:
	BN_clear_free(d);
	BN_clear_free(p);
	BN_clear_free(q);
	BN_clear_free(iqmp);

	return r;
}

int
sshbuf_write_priv_rsa(struct sshbuf *buf, const struct sshkey *key) {
	int r;
	const BIGNUM *d = NULL, *iqmp = NULL, *p = NULL, *q = NULL;

	RSA_get0_key(key->rsa, NULL, NULL, &d);
	RSA_get0_crt_params(key->rsa, NULL, NULL, &iqmp);
	RSA_get0_factors(key->rsa, &p, &q);

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

	r = sshbuf_get_eckey(buf, key->ecdsa);

out:
	free(curve);

	return r;
}

int
sshbuf_write_pub_ecdsa(struct sshbuf *buf, const struct sshkey *key) {
	int r;
	const char *curve_name = sshkey_curve_nid_to_name(key->ecdsa_nid);

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

	if ((r = sshkey_ec_validate_public(EC_KEY_get0_group(key->ecdsa),
	    EC_KEY_get0_public_key(key->ecdsa))) != 0)
		goto out;
	r = sshkey_ec_validate_private(key->ecdsa);

out:
	BN_clear_free(exponent);

	return r;
}

int
sshbuf_write_priv_ecdsa(struct sshbuf *buf, const struct sshkey *key) {
	return sshbuf_put_bignum2(buf, EC_KEY_get0_private_key(key->ecdsa));
}
#endif /* OPENSSL_HAS_ECC */

#else

typedef int sshkey_crypto_empty_translation_unit;

#endif /* WITH_OPENSSL */
