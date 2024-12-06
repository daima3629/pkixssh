/* $OpenBSD: ssh-dss.c,v 1.50 2024/01/11 01:45:36 djm Exp $ */
/*
 * Copyright (c) 2000 Markus Friedl.  All rights reserved.
 * Copyright (c) 2011 Dr. Stephen Henson.  All rights reserved.
 * Copyright (c) 2011-2024 Roumen Petrov.  All rights reserved.
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

#include "includes.h"

#ifdef WITH_DSA
/* NOTE: just in case as build with OpenSSL is required */
# ifndef WITH_OPENSSL
#  error "need WITH_OPENSSL"
# endif
#endif

#ifdef WITH_DSA

#include <sys/types.h>

#include "evp-compat.h"
#include <openssl/bn.h>

#include <stdarg.h>
#include <string.h>

#include "sshbuf.h"
#include "ssherr.h"
#include "digest.h"
#define SSHKEY_INTERNAL
#include "sshxkey.h"
#include "xmalloc.h"
#include "log.h"


#define INTBLOB_LEN	20
#define SIGBLOB_LEN	(2*INTBLOB_LEN)


static inline int
sshdsa_verify_length(int bits) {
	return bits != SSH_DSA_BITS
	    ? SSH_ERR_KEY_LENGTH : 0;
}


#ifdef WITH_OPENSSL_4_0_API
/* TODO: new methods compatible with OpenSSL 4.0 API.
 * Remark: OpenSSL 3* is too buggy - almost each release fail
 * or crash in regression tests.
 */
#else
/* management of elementary DSA key */

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
#endif /* ndef HAVE_DSA_GET0_KEY */

#ifndef HAVE_EVP_PKEY_CMP	/* OpenSSL < 0.9.8 */
extern int /* see sshkey-crypto.c */
ssh_EVP_PKEY_cmp_dsa(const EVP_PKEY *ka, const EVP_PKEY *kb);

int
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
#endif


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

int
ssh_pkey_validate_public_dsa(EVP_PKEY *pk) {
	int r;

{	DSA *dsa = EVP_PKEY_get1_DSA(pk);
	if (dsa == NULL)
		return SSH_ERR_INVALID_ARGUMENT;
	r = sshkey_validate_dsa_pub(dsa);
	DSA_free(dsa);
}
	return r;
}


extern int /* see sshkey-crypto.c */
ssh_EVP_PKEY_complete_pub_dsa(EVP_PKEY *pk);

int
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

	r = ssh_pkey_validate_public_dsa(key->pk);
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

static int
sshbuf_write_pub_dsa(struct sshbuf *buf, const struct sshkey *key) {
	int r;
	const BIGNUM *p = NULL, *q = NULL, *g = NULL;
	const BIGNUM *pub_key = NULL;

	if (key->pk == NULL)
		return SSH_ERR_INVALID_ARGUMENT;

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


static int
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

static int
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


extern int /* method used localy only in ssh-keygen.c */
sshbuf_read_custom_dsa(struct sshbuf *buf, struct sshkey *key);

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

	r = ssh_pkey_validate_public_dsa(key->pk);
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
#endif /* def WITH_OPENSSL_4_0_API */


/* key implementation */

static u_int
ssh_dss_size(const struct sshkey *key)
{
	return (key->pk != NULL) ? EVP_PKEY_bits(key->pk) : 0;
}

static void
ssh_dss_cleanup(struct sshkey *k)
{
	sshkey_clear_pkey(k);
}

static int
ssh_dss_equal(const struct sshkey *a, const struct sshkey *b)
{
	return sshkey_equal_public_pkey(a, b);
}

static int
ssh_dss_serialize_public(const struct sshkey *key, struct sshbuf *buf,
    enum sshkey_serialize_rep opts)
{
	UNUSED(opts);
	return sshbuf_write_pub_dsa(buf, key);
}

static int
ssh_dss_serialize_private(const struct sshkey *key, struct sshbuf *buf,
    enum sshkey_serialize_rep opts)
{
	int r;

	UNUSED(opts);
	if (!sshkey_is_cert(key)) {
		if ((r = sshbuf_write_pub_dsa(buf, key)) != 0)
			return r;
	}
	return sshbuf_write_priv_dsa(buf, key);
}

#ifdef USE_EVP_PKEY_KEYGEN
/* RFC4253
The "ssh-dss" key format has the following specific encoding:
      string    "ssh-dss"
      mpint     p
      mpint     q
      mpint     g
      mpint     y
Here, the 'p', 'q', 'g', and 'y' parameters form the signature key blob.
Signing and verifying using this key format is done according to the
Digital Signature Standard [FIPS-186-2] using the SHA-1 hash [FIPS-180-2].

=> 1024(=SSH_DSA_BITS)-bits DSA uses 160 q-bits
*/
static int
ssh_pkey_paramgen_dsa(int bits, EVP_PKEY **params) {
	EVP_PKEY *pk = NULL;
	EVP_PKEY_CTX *ctx = NULL;
	int r;

	ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_DSA, NULL);
	if (ctx == NULL) return SSH_ERR_ALLOC_FAIL;

	if (EVP_PKEY_paramgen_init(ctx) <= 0) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		goto err;
	}

	if (EVP_PKEY_CTX_set_dsa_paramgen_bits(ctx, bits) <= 0) {
		r = SSH_ERR_KEY_LENGTH;
		goto err;
	}

	/*NOTE OpenSSL 1.0.2+ default to 224 bits for the subprime parameter q*/
	if (EVP_PKEY_CTX_set_dsa_paramgen_q_bits(ctx, 160) <= 0) {
		r = SSH_ERR_KEY_LENGTH;
		goto err;
	}

	if (EVP_PKEY_paramgen(ctx, &pk) <= 0) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		goto err;
	}

	/* success */
	*params = pk;
	r = 0;

err:
	EVP_PKEY_CTX_free(ctx);
	return r;
}

static int
ssh_pkey_keygen_dsa(int bits, EVP_PKEY **ret) {
	EVP_PKEY *pk = NULL;
	EVP_PKEY_CTX *ctx = NULL;
	int r;

{	EVP_PKEY *pk_params = NULL;

	r = ssh_pkey_paramgen_dsa(bits, &pk_params);
	if (r != 0) return r;

	/* use DSA parameters in a EVP_PKEY context */
	ctx = EVP_PKEY_CTX_new(pk_params, NULL);
	EVP_PKEY_free(pk_params);
	if (ctx == NULL) return SSH_ERR_ALLOC_FAIL;
}

	if (EVP_PKEY_keygen_init(ctx) <= 0) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		goto err;
	}

	if (EVP_PKEY_keygen(ctx, &pk) <= 0)  {
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
ssh_pkey_dsa_generate(int bits, EVP_PKEY **ret) {
	EVP_PKEY *pk;
	DSA *private = NULL;
	int r = 0;

	if ((pk = EVP_PKEY_new()) == NULL ||
	    (private = DSA_new()) == NULL
	) {
		r = SSH_ERR_ALLOC_FAIL;
		goto err;
	}

	if (!DSA_generate_parameters_ex(private, bits, NULL, 0, NULL, NULL, NULL)) {
		r = SSH_ERR_KEY_LENGTH;
		goto err;
	}

	if (!DSA_generate_key(private)) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		goto err;
	}

	if (!EVP_PKEY_set1_DSA(pk, private)) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		goto err;
	}

	/* success */
	*ret = pk;
	pk = NULL;

err:
	EVP_PKEY_free(pk);
	DSA_free(private);
	return r;
}
#endif /*ndef USE_EVP_PKEY_KEYGEN*/

static int
ssh_dss_generate(struct sshkey *key, int bits) {
	EVP_PKEY *pk;
	int r;

	r = sshdsa_verify_length(bits);
	if (r != 0) return r;

#ifdef USE_EVP_PKEY_KEYGEN
	r = ssh_pkey_keygen_dsa(bits, &pk);
#else
	r = ssh_pkey_dsa_generate(bits, &pk);
#endif
	if (r == 0)
		key->pk = pk;

	return r;
}

static void
ssh_dss_move_public(struct sshkey *from, struct sshkey *to) {
	sshkey_move_pk(from, to);
}

static int
ssh_dss_copy_public(const struct sshkey *from, struct sshkey *to) {
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

static int
ssh_dss_deserialize_public(const char *pkalg, struct sshbuf *buf,
    struct sshkey *key)
{
	UNUSED(pkalg);
	return sshbuf_read_pub_dsa(buf, key);
}

static int
ssh_dss_deserialize_private(const char *pkalg, struct sshbuf *buf,
    struct sshkey *key)
{
	int r;

	UNUSED(pkalg);
	if (!sshkey_is_cert(key)) {
		if ((r = sshbuf_read_pub_dsa(buf, key))!= 0)
			return r;
	}
	return sshbuf_read_priv_dsa(buf, key);
}


static int
ssh_dss_sign(const ssh_sign_ctx *ctx, u_char **sigp, size_t *lenp,
    const u_char *data, size_t datalen)
{
	const struct sshkey *key = ctx->key;
	const ssh_evp_md *dgst;
	u_char sigblob[SIGBLOB_LEN];
	size_t siglen = sizeof(sigblob);
	int ret;

	if (lenp != NULL)
		*lenp = 0;
	if (sigp != NULL)
		*sigp = NULL;

	if (key == NULL) return SSH_ERR_INVALID_ARGUMENT;

	ret = ssh_pkey_validate_public_dsa(key->pk);
	if (ret != 0) return ret;

	dgst = ssh_evp_md_find(SSH_MD_DSA_RAW);

	if (ssh_pkey_sign(dgst, key->pk, sigblob, &siglen, data, datalen) <= 0) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		goto out;
	}

	ret = ssh_encode_signature(sigp, lenp,
	    "ssh-dss", sigblob, siglen);

 out:
	return ret;
}


static int
ssh_dss_verify(const ssh_verify_ctx *ctx,
    const u_char *sig, size_t siglen,
    const u_char *data, size_t datalen)
{
	const struct sshkey *key = ctx->key;
	const ssh_evp_md *dgst;
	const u_char *sigblob;
	size_t len;
	int ret;
	struct sshbuf *b = NULL;
	char *ktype = NULL;

	if (sig == NULL || siglen == 0)
		return SSH_ERR_INVALID_ARGUMENT;

	if (key == NULL) return SSH_ERR_INVALID_ARGUMENT;

	dgst = ssh_evp_md_find(SSH_MD_DSA_RAW);
	if (dgst == NULL) return SSH_ERR_INTERNAL_ERROR;

	ret = ssh_pkey_validate_public_dsa(key->pk);
	if (ret != 0) return ret;

	/* fetch signature */
	if ((b = sshbuf_from(sig, siglen)) == NULL)
		return SSH_ERR_ALLOC_FAIL;
	if (sshbuf_get_cstring(b, &ktype, NULL) != 0 ||
	    sshbuf_get_string_direct(b, &sigblob, &len) != 0) {
		ret = SSH_ERR_INVALID_FORMAT;
		goto out;
	}
	if (strcmp("ssh-dss", ktype) != 0) {
		ret = SSH_ERR_KEY_TYPE_MISMATCH;
		goto out;
	}
	if (sshbuf_len(b) != 0) {
		ret = SSH_ERR_UNEXPECTED_TRAILING_DATA;
		goto out;
	}
	if (len != SIGBLOB_LEN) {
		ret = SSH_ERR_INVALID_FORMAT;
		goto out;
	}

	ret = ssh_pkey_verify_r(dgst, key->pk,
	    sigblob, len, data, datalen);

 out:
	sshbuf_free(b);
	free(ktype);
	return ret;
}

static const struct sshkey_impl_funcs sshkey_dss_funcs = {
	/* .size = */		ssh_dss_size,
	/* .alloc =		NULL, */
	/* .cleanup = */	ssh_dss_cleanup,
	/* .equal = */		ssh_dss_equal,
	/* .serialize_public = */	ssh_dss_serialize_public,
	/* .deserialize_public = */	ssh_dss_deserialize_public,
	/* .serialize_private = */	ssh_dss_serialize_private,
	/* .deserialize_private = */	ssh_dss_deserialize_private,
	/* .generate = */	ssh_dss_generate,
	/* .move_public = */	ssh_dss_move_public,
	/* .copy_public = */	ssh_dss_copy_public,
	/* .sign = */		ssh_dss_sign,
	/* .verify = */		ssh_dss_verify
};

const struct sshkey_impl sshkey_dss_impl = {
	/* .name = */		"ssh-dss",
	/* .shortname = */	"DSA",
	/* .sigalg = */		NULL,
	/* .type = */		KEY_DSA,
	/* .nid = */		0,
	/* .cert = */		0,
	/* .sigonly = */	0,
	/* .keybits = */	0,
	/* .funcs = */		&sshkey_dss_funcs
};

const struct sshkey_impl sshkey_dsa_cert_impl = {
	/* .name = */		"ssh-dss-cert-v01@openssh.com",
	/* .shortname = */	"DSA-CERT",
	/* .sigalg = */		NULL,
	/* .type = */		KEY_DSA_CERT,
	/* .nid = */		0,
	/* .cert = */		1,
	/* .sigonly = */	0,
	/* .keybits = */	0,
	/* .funcs = */		&sshkey_dss_funcs
};
#else

typedef int ssh_dss_empty_translation_unit;

#endif /* WITH_DSA */
