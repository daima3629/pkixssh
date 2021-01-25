#ifndef EVP_COMPAT_H
#define EVP_COMPAT_H
/*
 * Copyright (c) 2011-2020 Roumen Petrov.  All rights reserved.
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
#include "openbsd-compat/openssl-compat.h"
#ifdef OPENSSL_HAS_ECC
# include <openssl/ec.h>
# include <openssl/ecdsa.h>
#endif
#include <string.h>	/*for memset*/
/* Unlike OPENSSL_strdup (0.8.k+), BUF_strdup is defined in
 * all OpenSSL versions (SSLeay 0.8.1) until 1.1.0.
 * As is always available at run-time in compatible
 * functions below it is preferred function.
 */
#include <openssl/buffer.h>	/*for BUF_strdup*/


#if defined(OPENSSL_VERSION_NUMBER) && (OPENSSL_VERSION_NUMBER < 0x10000000L)
/* work-arounds for limited EVP digests in OpenSSL 0.9.8* ...
 * (missing ecdsa support)
 */

#ifdef OPENSSL_HAS_NISTP256
const EVP_MD* ssh_ecdsa_EVP_sha256(void);
#endif
#ifdef OPENSSL_HAS_NISTP384
const EVP_MD* ssh_ecdsa_EVP_sha384(void);
#endif
#ifdef OPENSSL_HAS_NISTP521
const EVP_MD* ssh_ecdsa_EVP_sha512(void);
#endif

#else

#ifdef OPENSSL_HAS_NISTP256
static inline const EVP_MD* ssh_ecdsa_EVP_sha256(void) { return EVP_sha256(); }
#endif
#ifdef OPENSSL_HAS_NISTP384
static inline const EVP_MD* ssh_ecdsa_EVP_sha384(void) { return EVP_sha384(); }
#endif
#ifdef OPENSSL_HAS_NISTP521
static inline const EVP_MD* ssh_ecdsa_EVP_sha512(void) { return EVP_sha512(); }
#endif

#endif /*defined(OPENSSL_VERSION_NUMBER) && (OPENSSL_VERSION_NUMBER < 0x10000000L)*/


#ifndef HAVE_EVP_MD_CTX_NEW		/* OpenSSL < 1.1 */
static inline EVP_MD_CTX*
EVP_MD_CTX_new(void) {
	EVP_MD_CTX *ctx;

	ctx = OPENSSL_malloc(sizeof(EVP_MD_CTX));
	if (ctx != NULL) {
		EVP_MD_CTX_init(ctx);
	}
	return(ctx);
}


static inline void
EVP_MD_CTX_free(EVP_MD_CTX *ctx) {
	EVP_MD_CTX_cleanup(ctx);
	OPENSSL_free(ctx);
}
#endif/* ndef HAVE_EVP_MD_CTX_NEW	OpenSSL < 1.1 */


#ifndef HAVE_EVP_MD_FLAGS		/* OpenSSL < 1.0 */
static inline unsigned long
EVP_MD_flags(const EVP_MD *md) {
	return md->flags;
}
#endif /* ndef HAVE_EVP_MD_FLAGS	OpenSSL < 1.0 */


#ifndef OPENSSL_NO_RSA
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
#endif /*ndef OPENSSL_NO_RSA*/


#ifndef OPENSSL_NO_DSA
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

#ifndef HAVE_DSA_SIG_GET0		/* OpenSSL < 1.1 */
static inline void
DSA_SIG_get0(const DSA_SIG *sig, const BIGNUM **pr, const BIGNUM **ps) {
	if (pr != NULL) *pr = sig->r;
	if (ps != NULL) *ps = sig->s;
}
#endif /*ndef HAVE_DSA_SIG_GET0	OpenSSL < 1.1 */

#ifndef HAVE_DSA_SIG_SET0		/* OpenSSL < 1.1 */
static inline int/*bool*/
DSA_SIG_set0(DSA_SIG *sig, BIGNUM *r, BIGNUM *s) {
	if (r == NULL || s == NULL) return 0;

	BN_clear_free(sig->r);
	BN_clear_free(sig->s);

	sig->r = r;
	sig->s = s;
	return 1;
}
#endif /*ndef HAVE_DSA_SIG_SET0	OpenSSL < 1.1 */
#endif /*ndef OPENSSL_NO_DSA*/


#ifdef OPENSSL_HAS_ECC
#ifndef HAVE_ECDSA_SIG_GET0		/* OpenSSL < 1.1 */
static inline void
ECDSA_SIG_get0(const ECDSA_SIG *sig, const BIGNUM **pr, const BIGNUM **ps) {
    if (pr != NULL) *pr = sig->r;
    if (ps != NULL) *ps = sig->s;
}
#endif /*ndef HAVE_ECDSA_SIG_GET0	OpenSSL < 1.1 */

#ifndef HAVE_ECDSA_SIG_SET0		/* OpenSSL < 1.1 */
static inline int/*bool*/
ECDSA_SIG_set0(ECDSA_SIG *sig, BIGNUM *r, BIGNUM *s) {
	if (r == NULL || s == NULL) return 0;

	BN_clear_free(sig->r);
	BN_clear_free(sig->s);

	sig->r = r;
	sig->s = s;
	return 1;
}
#endif /*ndef HAVE_ECDSA_SIG_SET0	OpenSSL < 1.1 */
#endif /*OPENSSL_HAS_ECC*/


#ifndef HAVE_EVP_PKEY_BASE_ID
/* OpenSSL >= 1.0 */
static inline int
EVP_PKEY_id(const EVP_PKEY *pkey) {
	return pkey->type;
}

static inline int
EVP_PKEY_base_id(const EVP_PKEY *pkey) {
	return(EVP_PKEY_type(EVP_PKEY_id(pkey)));
}
#endif /*ndef HAVE_EVP_PKEY_BASE_ID */


#ifndef HAVE_EC_POINT_GET_AFFINE_COORDINATES		/* OpenSSL < 1.1.1 */
#ifdef OPENSSL_HAS_ECC
/* Functions are available even in 0.9.7* but EC is not activated
 * as NIST curves are not supported yet.
 */
static inline int
EC_POINT_get_affine_coordinates(
    const EC_GROUP *group, const EC_POINT *p,
    BIGNUM *x, BIGNUM *y, BN_CTX *ctx
) {
	return EC_POINT_get_affine_coordinates_GFp(group, p, x, y, ctx);
}

static inline int
EC_POINT_set_affine_coordinates(
    const EC_GROUP *group, EC_POINT *p,
    const BIGNUM *x, const BIGNUM *y, BN_CTX *ctx
) {
	return EC_POINT_set_affine_coordinates_GFp(group, p, x, y, ctx);
}
#endif /*def OPENSSL_HAS_ECC*/
#endif /*ndef HAVE_EC_POINT_GET_AFFINE_COORDINATES*/

#ifndef HAVE_EC_GROUP_GET_FIELD_TYPE		/* OpenSSL < 3.0.0 */
#ifdef OPENSSL_HAS_ECC
static inline int
EC_GROUP_get_field_type(const EC_GROUP *group) {
	return EC_METHOD_get_field_type(EC_GROUP_method_of(group));
}
#endif /*def OPENSSL_HAS_ECC*/
#endif /*ndef HAVE_EC_GROUP_GET_FIELD_TYPE*/


#ifndef HAVE_EVP_DSS1
/* removed in OpenSSL 1.1 */
static inline const EVP_MD* EVP_dss1(void) { return EVP_sha1(); }
#endif

#if !HAVE_DECL_UTF8_GETC
/* hidden in some OpenSSL compatible libraries */
int UTF8_getc(const unsigned char *str, int len, unsigned long *val);
int UTF8_putc(unsigned char *str, int len, unsigned long value);
#endif

#endif /* ndef EVP_COMPAT_H*/
