/* $OpenBSD: ssh-rsa.c,v 1.80 2024/08/15 00:51:51 djm Exp $ */
/*
 * Copyright (c) 2000, 2003 Markus Friedl <markus@openbsd.org>
 * Copyright (c) 2011 Dr. Stephen Henson.  All rights reserved.
 * Copyright (c) 2011-2025 Roumen Petrov.  All rights reserved.
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

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#ifndef USE_OPENSSL_PROVIDER
/* TODO: implement OpenSSL 4.0 API, as OpenSSL 3.* is quite nonfunctional */
# define OPENSSL_SUPPRESS_DEPRECATED
#endif

#include "includes.h"

#ifdef WITH_OPENSSL

#include <sys/types.h>

#include "evp-compat.h"
#include <openssl/pem.h>
#include <openssl/bn.h>
#ifdef HAVE_EVP_KEYMGMT_GET0_PROVIDER
# include <openssl/core_names.h>
#endif

#include <stdarg.h>
#include <stdlib.h>
#include <string.h>

#include "sshbuf.h"
#include "ssherr.h"
#define SSHKEY_INTERNAL
#include "sshxkey.h"
#include "log.h"


struct ssh_rsa_alg_st {
	const char *name;
	const char *signame;
	const int id;
};

static struct ssh_rsa_alg_st
ssh_rsa_algs[] = {
#ifdef HAVE_EVP_SHA256
	{ "rsa-sha2-256", "rsa-sha2-256", SSH_MD_RSA_SHA256 },
	{ "rsa-sha2-512", "rsa-sha2-512", SSH_MD_RSA_SHA512 },
#endif
	{ "ssh-rsa", "ssh-rsa", SSH_MD_RSA_SHA1 },
#ifdef HAVE_EVP_SHA256
	{ "rsa-sha2-256-cert-v01@openssh.com", "rsa-sha2-256", SSH_MD_RSA_SHA256 },
	{ "rsa-sha2-512-cert-v01@openssh.com", "rsa-sha2-512", SSH_MD_RSA_SHA512 },
#endif
	{ "ssh-rsa-cert-v01@openssh.com", "ssh-rsa", SSH_MD_RSA_SHA1 },
	{ NULL, NULL, -1 }
};

static struct ssh_rsa_alg_st* ssh_rsa_alg_info(const char *alg);

struct ssh_rsa_alg_st*
ssh_rsa_alg_info(const char *alg) {
	struct ssh_rsa_alg_st* p;

	if (alg == NULL || *alg == '\0')
		return ssh_rsa_alg_info("ssh-rsa");

	for (p = ssh_rsa_algs; p->name != NULL; p++)
		if (strcmp(alg, p->name) == 0)
			return p;

	return NULL;
}

/* global option overridable by configuration */
int required_rsa_size = SSH_RSA_MINIMUM_MODULUS_SIZE;

static inline int
sshrsa_verify_length(int bits) {
	return bits < required_rsa_size
	    ? SSH_ERR_KEY_LENGTH : 0;
}


#ifdef WITH_OPENSSL_4_0_API
/* TODO: new methods compatible with OpenSSL 4.0 API.
 * Remark: OpenSSL 3* is too buggy - almost each release fail
 * or crash in regression tests.
 */
#else
/* management of elementary RSA key */

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
#endif /* ndef HAVE_RSA_GET0_KEY */

#ifndef HAVE_EVP_PKEY_CMP	/* OpenSSL < 0.9.8 */
extern int /* see sshkey-crypto.c */
ssh_EVP_PKEY_cmp_rsa(const EVP_PKEY *ka, const EVP_PKEY *kb);

int
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
#endif


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


#ifdef HAVE_EVP_KEYMGMT_GET0_PROVIDER
static int
ssh_EVP_PKEY_validate_public_rsaprov(const EVP_PKEY *pk) {
	int bits = 0;
	int r;

	if (EVP_PKEY_get_int_param(pk, OSSL_PKEY_PARAM_BITS, &bits) != 1)
		return SSH_ERR_INVALID_ARGUMENT;

	r = sshrsa_verify_length(bits);
	if (r != 0) return r;

	/* other checks ? */
	return 0;
}
#endif /*def HAVE_EVP_KEYMGMT_GET0_PROVIDER*/

static int
ssh_RSA_validate_public(const RSA *rsa) {
	int r;
	const BIGNUM *n = NULL;

	RSA_get0_key(rsa, &n, NULL, NULL);

	r = sshrsa_verify_length(BN_num_bits(n));
	if (r != 0) return r;

	/* other checks ? */
	return 0;
}

int
ssh_pkey_validate_public_rsa(EVP_PKEY *pk) {
#ifdef HAVE_EVP_KEYMGMT_GET0_PROVIDER
	if (EVP_PKEY_get0_provider(pk) != NULL)
		return ssh_EVP_PKEY_validate_public_rsaprov(pk);
#endif
{	RSA *rsa;
	int r;

	rsa = EVP_PKEY_get1_RSA(pk);
	if (rsa == NULL) return SSH_ERR_INVALID_ARGUMENT;

	r = ssh_RSA_validate_public(rsa);

	RSA_free(rsa);
	return r;
}
}


static int
ssh_EVP_PKEY_complete_pub_rsa(EVP_PKEY *pk) {
#ifdef HAVE_EVP_KEYMGMT_GET0_PROVIDER
	/* TODO: blinding on provider managed keys? */
	if (EVP_PKEY_get0_provider(pk) != NULL)
		return ssh_EVP_PKEY_validate_public_rsaprov(pk);
#endif
{	RSA *rsa;
	int r;

	rsa = EVP_PKEY_get1_RSA(pk);
	if (rsa == NULL)
		return SSH_ERR_INVALID_ARGUMENT;

	r = ssh_RSA_validate_public(rsa);
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
}


extern int /* see sshkey-crypto.c */
sshkey_from_pkey_rsa(EVP_PKEY *pk, struct sshkey **keyp);

int
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


int ssh_rsa_public_to_fp_traditional(struct sshkey *key, FILE *fp);

int
ssh_rsa_public_to_fp_traditional(struct sshkey *key, FILE *fp) {
	int res;
	RSA *rsa;

	rsa = EVP_PKEY_get1_RSA(key->pk);
	if (rsa == NULL) return 0;

	res = PEM_write_RSAPublicKey(fp, rsa);
	RSA_free(rsa);
	return res;
}


int ssh_rsa_public_from_fp_traditional(FILE *fp, struct sshkey **key);

int
ssh_rsa_public_from_fp_traditional(FILE *fp, struct sshkey **key) {
	RSA *rsa;
	EVP_PKEY *pk = NULL;
	struct sshkey *k = NULL;
	int r;

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


static int
sshbuf_read_pub_rsa(struct sshbuf *buf, struct sshkey *key) {
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

#ifdef HAVE_EVP_KEYMGMT_GET0_PROVIDER
static int
sshbuf_write_prov_rsapub(struct sshbuf *buf, const EVP_PKEY *pk) {
	int r;
	BIGNUM *n = NULL, *e = NULL;

	if (EVP_PKEY_get_bn_param(pk, OSSL_PKEY_PARAM_RSA_N, &n) != 1) {
		r = SSH_ERR_INVALID_ARGUMENT;
		goto err;
	}
	if (EVP_PKEY_get_bn_param(pk, OSSL_PKEY_PARAM_RSA_E, &e) != 1) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		goto err;
	}

	r = sshbuf_put_bignum2(buf, e);
	if (r != 0) goto err;
	r = sshbuf_put_bignum2(buf, n);

err:
	BN_free(e);
	BN_free(n);
	return r;
}
#endif /*def HAVE_EVP_KEYMGMT_GET0_PROVIDER*/

static inline int
sshbuf_put_rsakey(struct sshbuf *buf, const RSA *rsa)
{
	int r;
	const BIGNUM *n = NULL, *e = NULL;

	RSA_get0_key(rsa, &n, &e, NULL);

	r = sshbuf_put_bignum2(buf, e);
	if (r != 0) return r;
	return sshbuf_put_bignum2(buf, n);
}

static int
sshbuf_write_pkey_rsapub(struct sshbuf *buf, EVP_PKEY *pk) {
#ifdef HAVE_EVP_KEYMGMT_GET0_PROVIDER
	if (EVP_PKEY_get0_provider(pk) != NULL)
		return sshbuf_write_prov_rsapub(buf, pk);
#endif
{	int r;
	RSA *rsa = EVP_PKEY_get1_RSA(pk);
	if (rsa == NULL)
		return SSH_ERR_INVALID_ARGUMENT;

	r = sshbuf_put_rsakey(buf, rsa);

	RSA_free(rsa);
	return r;
}
}

static int
sshbuf_write_pub_rsa(struct sshbuf *buf, const struct sshkey *key) {
	if (key->pk == NULL) return SSH_ERR_INVALID_ARGUMENT;
	return sshbuf_write_pkey_rsapub(buf, key->pk);
}

static int
sshbuf_read_pub_rsa_priv(struct sshbuf *buf, struct sshkey *key) {
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


#ifndef BN_FLG_CONSTTIME
#  define BN_FLG_CONSTTIME 0x0 /* OpenSSL < 0.9.8 */
#endif

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
sshbuf_write_pub_rsa_priv(struct sshbuf *buf, const struct sshkey *key) {
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


static int
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

static int
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


extern int /* method used localy only in ssh-keygen.c */
sshbuf_read_custom_rsa(struct sshbuf *buf, struct sshkey *key);

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
	debug3("e %lx", (unsigned long)rsa_e);
	if (rsa_e < 30) {
		rsa_e <<= 8;
		rsa_e += e2;
		debug3("e %lx", (unsigned long)rsa_e);
		rsa_e <<= 8;
		rsa_e += e3;
		debug3("e %lx", (unsigned long)rsa_e);
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
#endif /* def WITH_OPENSSL_4_0_API */


/* key implementation */

static u_int
ssh_rsa_size(const struct sshkey *key)
{
	return (key->pk != NULL) ? EVP_PKEY_bits(key->pk) : 0;
}

static void
ssh_rsa_cleanup(struct sshkey *k)
{
	sshkey_clear_pkey(k);
}

static int
ssh_rsa_equal(const struct sshkey *a, const struct sshkey *b)
{
	return sshkey_equal_public_pkey(a, b);
}

static int
ssh_rsa_serialize_public(const struct sshkey *key, struct sshbuf *buf,
    enum sshkey_serialize_rep opts)
{
	UNUSED(opts);
	return sshbuf_write_pub_rsa(buf, key);
}

static int
ssh_rsa_serialize_private(const struct sshkey *key, struct sshbuf *buf,
    enum sshkey_serialize_rep opts)
{
	int r;

	UNUSED(opts);
	if (!sshkey_is_cert(key)) {
		if ((r = sshbuf_write_pub_rsa_priv(buf, key)) != 0)
			return r;
	}
	return sshbuf_write_priv_rsa(buf, key);
}

#ifdef USE_EVP_PKEY_KEYGEN
static int
ssh_pkey_ctx_set_rsa_keygen_pubexp(EVP_PKEY_CTX *ctx) {
	BIGNUM *f4;
	int ret;

	if ((f4 = BN_new()) == NULL) return SSH_ERR_ALLOC_FAIL;

	if (!BN_set_word(f4, RSA_F4)) {
		BN_free(f4);
		return SSH_ERR_LIBCRYPTO_ERROR;
	}

#ifdef EVP_PKEY_CTX_set_rsa_keygen_pubexp
	/*definition if OpenSSL < 3.0 and OpenSSL >= 1.0*/
	ret = EVP_PKEY_CTX_set_rsa_keygen_pubexp(ctx, f4);
#else
	/*OpenSSL >= 3.0*/
	ret = EVP_PKEY_CTX_set1_rsa_keygen_pubexp(ctx, f4);
	BN_free(f4);
#endif
	return (ret > 0) ? SSH_ERR_SUCCESS: SSH_ERR_LIBCRYPTO_ERROR;
}

static int
ssh_pkey_keygen_rsa(int bits, EVP_PKEY **ret) {
	EVP_PKEY *pk = NULL;
	EVP_PKEY_CTX *ctx = NULL;
	int r;

	ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
	if (ctx == NULL) return SSH_ERR_ALLOC_FAIL;

	if (EVP_PKEY_keygen_init(ctx) <= 0)  {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		goto err;
	}

	if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, bits) <= 0) {
		r = SSH_ERR_KEY_LENGTH;
		goto err;
	}

	r = ssh_pkey_ctx_set_rsa_keygen_pubexp(ctx);
	if (r != 0) goto err;

	if (EVP_PKEY_keygen(ctx, &pk) <= 0) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		goto err;
	}

	/* success */
	*ret = pk;
	/*r = 0;*/

err:
	EVP_PKEY_CTX_free(ctx);
	return r;
}
#else /*ndef USE_EVP_PKEY_KEYGEN*/
static int
ssh_pkey_rsa_generate(int bits, EVP_PKEY **ret) {
	EVP_PKEY *pk;
	RSA *private = NULL;
	BIGNUM *f4 = NULL;
	int r = 0;

	if ((pk = EVP_PKEY_new()) == NULL ||
	    (private = RSA_new()) == NULL ||
	    (f4 = BN_new()) == NULL
	) {
		r = SSH_ERR_ALLOC_FAIL;
		goto err;
	}

	if (!BN_set_word(f4, RSA_F4)) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		goto err;
	}

	if (!RSA_generate_key_ex(private, bits, f4, NULL)) {
		r = SSH_ERR_KEY_LENGTH;
		goto err;
	}

	if (!EVP_PKEY_set1_RSA(pk, private)) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		goto err;
	}

	/* success */
	*ret = pk;
	pk = NULL;

err:
	EVP_PKEY_free(pk);
	RSA_free(private);
	BN_free(f4);
	return r;
}
#endif /*ndef USE_EVP_PKEY_KEYGEN*/

static int
ssh_rsa_generate(struct sshkey *key, int bits) {
	EVP_PKEY *pk;
	int r;

	r = sshrsa_verify_length(bits);
	if (r != 0) return r;

	if (bits > SSHBUF_MAX_BIGNUM * 8)
		return SSH_ERR_KEY_LENGTH;

#ifdef USE_EVP_PKEY_KEYGEN
	r = ssh_pkey_keygen_rsa(bits, &pk);
#else
	r = ssh_pkey_rsa_generate(bits, &pk);
#endif
	if (r == 0)
		key->pk = pk;

	return r;
}

static void
ssh_rsa_move_public(struct sshkey *from, struct sshkey *to) {
	sshkey_move_pk(from, to);
}

static int
ssh_rsa_copy_public(const struct sshkey *from, struct sshkey *to) {
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

static int
ssh_rsa_deserialize_public(const char *pkalg, struct sshbuf *buf,
    struct sshkey *key)
{
	UNUSED(pkalg);
	return sshbuf_read_pub_rsa(buf, key);
}

static int
ssh_rsa_deserialize_private(const char *pkalg, struct sshbuf *buf,
    struct sshkey *key)
{
	int r;

	UNUSED(pkalg);
	if (!sshkey_is_cert(key)) {
		if ((r = sshbuf_read_pub_rsa_priv(buf, key)) != 0)
			return r;
	}
	return sshbuf_read_priv_rsa(buf, key);
}

static int
ssh_rsa_sign(const ssh_sign_ctx *ctx, u_char **sigp, size_t *lenp,
    const u_char *data, size_t datalen)
{
	const struct sshkey *key = ctx->key;
	const ssh_evp_md *dgst;
	size_t slen = 0, len;
	struct ssh_rsa_alg_st *alg_info;
	int ret;

	if (lenp != NULL)
		*lenp = 0;
	if (sigp != NULL)
		*sigp = NULL;

	if (key == NULL) return SSH_ERR_INVALID_ARGUMENT;

	alg_info = ssh_rsa_alg_info(ctx->alg);
	if (alg_info == NULL)
		return SSH_ERR_INVALID_ARGUMENT;
	debug3_f("alg=%s/%s", (ctx->alg != NULL ? ctx->alg : "(nil)"), alg_info->name);

	ret = ssh_pkey_validate_public_rsa(key->pk);
	if (ret != 0) return ret;

	dgst = ssh_evp_md_find(alg_info->id);

#ifdef HAVE_EVP_KEYMGMT_GET0_PROVIDER
	/* work-around for tpm2-openssl(<1.3) issue #135 */
	if (getenv("TPM2_RSA_SIZE_BUG") != NULL)
		slen = (EVP_PKEY_bits(key->pk)+7)/8;
	else
#endif
	slen = EVP_PKEY_size(key->pk);
	debug3_f("slen=%zu", slen);

{	u_char *sig = malloc(slen);
	if (sig == NULL) return SSH_ERR_ALLOC_FAIL;
#ifdef HAVE_EVP_DIGESTSIGNINIT /* OpenSSL >= 1.0 */
	/* NOTE: Function EVP_SignFinal() in OpenSSL before 1.0 does not
	 * return signature length if signature argument is NULL.
	 */
	if (ssh_pkey_sign(dgst, key->pk, NULL, &len, data, datalen) <= 0) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		goto out;
	}
	debug3_f("len=%zu", len);
	/* paranoid check */
	if (len > slen) {
		ret = SSH_ERR_INTERNAL_ERROR;
		goto out;
	}
#endif /*def HAVE_EVP_DIGESTSIGNINIT*/
	if (ssh_pkey_sign(dgst, key->pk, sig, &len, data, datalen) <= 0) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		goto out;
	}

	if (len < slen) {
		size_t diff = slen - len;
		memmove(sig + diff, sig, len);
		explicit_bzero(sig, diff);
#ifndef HAVE_EVP_DIGESTSIGNINIT
	} else if (len > slen) {
		ret = SSH_ERR_INTERNAL_ERROR;
		goto out;
#endif /*ndef HAVE_EVP_DIGESTSIGNINIT*/
	}

	ret = ssh_encode_signature(sigp, lenp,
	    alg_info->signame, sig, slen);
 out:
	free(sig);
}
	return ret;
}

static int
ssh_rsa_verify(const ssh_verify_ctx *ctx,
    const u_char *sig, size_t siglen,
    const u_char *data, size_t datalen)
{
	const struct sshkey *key = ctx->key;
	const ssh_evp_md *dgst;
	const char *alg = ctx->alg;
	char *sigtype = NULL;
	struct ssh_rsa_alg_st *alg_info;
	int ret;
	size_t len = 0, diff, modlen;
	struct sshbuf *b = NULL;
	u_char *osigblob, *sigblob = NULL;

	if (sig == NULL || siglen == 0)
		return SSH_ERR_INVALID_ARGUMENT;

	if (key == NULL) return SSH_ERR_INVALID_ARGUMENT;

	ret = ssh_pkey_validate_public_rsa(key->pk);
	if (ret != 0) return ret;

	if ((b = sshbuf_from(sig, siglen)) == NULL)
		return SSH_ERR_ALLOC_FAIL;
	if (sshbuf_get_cstring(b, &sigtype, NULL) != 0) {
		ret = SSH_ERR_INVALID_FORMAT;
		goto out;
	}
	/* algorithm for plain keys */
	alg_info = ssh_rsa_alg_info(sigtype);
	if (alg_info == NULL) {
		ret = SSH_ERR_INVALID_ARGUMENT;
		goto out;
	}
	debug3_f("alg=%s/%s", (alg != NULL ? alg : "(nil)"), alg_info->name);
	/*
	 * For legacy reasons allow ssh-rsa-cert-v01 certs to accept SHA2 signatures
	 * but otherwise the signature algorithm should match.
	 */
	if (alg != NULL && strcmp(alg, "ssh-rsa-cert-v01@openssh.com") != 0) {
		struct ssh_rsa_alg_st *want_info;
		want_info = ssh_rsa_alg_info(alg);
		if (want_info == NULL) {
			ret = SSH_ERR_INVALID_ARGUMENT;
			goto out;
		}
		if (alg_info->id != want_info->id) {
			ret = SSH_ERR_SIGNATURE_INVALID;
			goto out;
		}
	}
	if (sshbuf_get_string(b, &sigblob, &len) != 0) {
		ret = SSH_ERR_INVALID_FORMAT;
		goto out;
	}
	if (sshbuf_len(b) != 0) {
		ret = SSH_ERR_UNEXPECTED_TRAILING_DATA;
		goto out;
	}

	dgst = ssh_evp_md_find(alg_info->id);

	modlen = EVP_PKEY_size(key->pk);
	if (len > modlen) {
		ret = SSH_ERR_KEY_BITS_MISMATCH;
		goto out;
	} else if (len < modlen) {
		diff = modlen - len;
		osigblob = sigblob;
		if ((sigblob = realloc(sigblob, modlen)) == NULL) {
			sigblob = osigblob; /* put it back for clear/free */
			ret = SSH_ERR_ALLOC_FAIL;
			goto out;
		}
		memmove(sigblob + diff, sigblob, len);
		explicit_bzero(sigblob, diff);
		len = modlen;
	}

	ret = ssh_pkey_verify_r(dgst, key->pk,
	    sigblob, len, data, datalen);

 out:
	freezero(sigblob, len);
	free(sigtype);
	sshbuf_free(b);
	return ret;
}

static const struct sshkey_impl_funcs sshkey_rsa_funcs = {
	/* .size = */		ssh_rsa_size,
	/* .alloc =		NULL, */
	/* .cleanup = */	ssh_rsa_cleanup,
	/* .equal = */		ssh_rsa_equal,
	/* .serialize_public = */	ssh_rsa_serialize_public,
	/* .deserialize_public = */	ssh_rsa_deserialize_public,
	/* .serialize_private = */	ssh_rsa_serialize_private,
	/* .deserialize_private = */	ssh_rsa_deserialize_private,
	/* .generate = */	ssh_rsa_generate,
	/* .move_public = */	ssh_rsa_move_public,
	/* .copy_public = */	ssh_rsa_copy_public,
	/* .sign = */		ssh_rsa_sign,
	/* .verify = */		ssh_rsa_verify
};

const struct sshkey_impl sshkey_rsa_impl = {
	/* .name = */		"ssh-rsa",
	/* .shortname = */	"RSA",
	/* .sigalg = */		NULL,
	/* .type = */		KEY_RSA,
	/* .nid = */		0,
	/* .cert = */		0,
	/* .sigonly = */	0,
	/* .keybits = */	0,
	/* .funcs = */		&sshkey_rsa_funcs
};

const struct sshkey_impl sshkey_rsa_cert_impl = {
	/* .name = */		"ssh-rsa-cert-v01@openssh.com",
	/* .shortname = */	"RSA-CERT",
	/* .sigalg = */		NULL,
	/* .type = */		KEY_RSA_CERT,
	/* .nid = */		0,
	/* .cert = */		1,
	/* .sigonly = */	0,
	/* .keybits = */	0,
	/* .funcs = */		&sshkey_rsa_funcs
};

#ifdef HAVE_EVP_SHA256
const struct sshkey_impl sshkey_rsa_sha256_impl = {
	/* .name = */		"rsa-sha2-256",
	/* .shortname = */	"RSA",
	/* .sigalg = */		NULL,
	/* .type = */		KEY_RSA,
	/* .nid = */		0,
	/* .cert = */		0,
	/* .sigonly = */	1,
	/* .keybits = */	0,
	/* .funcs = */		&sshkey_rsa_funcs
};

const struct sshkey_impl sshkey_rsa_sha512_impl = {
	/* .name = */		"rsa-sha2-512",
	/* .shortname = */	"RSA",
	/* .sigalg = */		NULL,
	/* .type = */		KEY_RSA,
	/* .nid = */		0,
	/* .cert = */		0,
	/* .sigonly = */	1,
	/* .keybits = */	0,
	/* .funcs = */		&sshkey_rsa_funcs
};

const struct sshkey_impl sshkey_rsa_sha256_cert_impl = {
	/* .name = */		"rsa-sha2-256-cert-v01@openssh.com",
	/* .shortname = */	"RSA-CERT",
	/* .sigalg = */		"rsa-sha2-256",
	/* .type = */		KEY_RSA_CERT,
	/* .nid = */		0,
	/* .cert = */		1,
	/* .sigonly = */	1,
	/* .keybits = */	0,
	/* .funcs = */		&sshkey_rsa_funcs
};

const struct sshkey_impl sshkey_rsa_sha512_cert_impl = {
	/* .name = */		"rsa-sha2-512-cert-v01@openssh.com",
	/* .shortname = */	"RSA-CERT",
	/* .sigalg = */		"rsa-sha2-512",
	/* .type = */		KEY_RSA_CERT,
	/* .nid = */		0,
	/* .cert = */		1,
	/* .sigonly = */	1,
	/* .keybits = */	0,
	/* .funcs = */		&sshkey_rsa_funcs
};
#endif /*def HAVE_EVP_SHA256*/
#else

typedef int ssh_rsa_empty_translation_unit;

#endif /* WITH_OPENSSL */
