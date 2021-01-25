#ifndef SSH_PKCS11_H
#define SSH_PKCS11_H
/* $OpenBSD: ssh-pkcs11.h,v 1.6 2020/01/25 00:03:36 djm Exp $ */
/*
 * Copyright (c) 2010 Markus Friedl.  All rights reserved.
 * Copyright (c) 2018-2021 Roumen Petrov.  All rights reserved.
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

int	pkcs11_init(int);
void	pkcs11_terminate(void);

#ifdef ENABLE_PKCS11
#include "sshkey.h"
#include "evp-compat.h"

/* Errors for pkcs11_add_provider() */
#define	SSH_PKCS11_ERR_GENERIC			-1
#define	SSH_PKCS11_ERR_LOGIN_FAIL		-2
#define	SSH_PKCS11_ERR_NO_SLOTS			-3
#define	SSH_PKCS11_ERR_PIN_REQUIRED		-4
#define	SSH_PKCS11_ERR_PIN_LOCKED		-5

int	pkcs11_add_provider(char *, char *, struct sshkey ***, char ***);
int	pkcs11_del_provider(char *);

/* crypto library errors */
/* Function codes. */
#define PKCS11_LOGIN			100
#define PKCS11_REAUTHENTICATE		101
#define PKCS11_RSA_PRIVATE_ENCRYPT	110
#define PKCS11_DSA_DO_SIGN		111
#define PKCS11_ECDSA_DO_SIGN		112
#define PKCS11_GET_KEY			113
/* Reason codes. */
#define PKCS11_SIGNREQ_FAIL		100
#define PKCS11_C_SIGNINIT_FAIL		101
#define PKCS11_C_SIGN_FAIL		102
#define PKCS11_C_LOGIN_FAIL		103
#define PKCS11_FINDKEY_FAIL		104

void ERR_PKCS11_PUT_error(int function, int reason, char *file, int line, const char* funcname);
#define PKCS11err(f,r) ERR_PKCS11_PUT_error((f),(r),__FILE__,__LINE__, __func__)

void ERR_load_PKCS11_strings(void);


#ifdef USE_RSA_METHOD
#ifndef HAVE_RSA_METH_NEW		/* OpenSSL < 1.1 */
/* Partial backport of opaque RSA from OpenSSL >= 1.1 by commits
 * "Make the RSA_METHOD structure opaque", "RSA, DSA, DH: Allow some
 * given input to be NULL on already initialised keys" and etc.
 */

/* opaque RSA method structure */
static inline RSA_METHOD*
RSA_meth_new(const char *name, int flags) {
	RSA_METHOD *meth;

	meth = OPENSSL_malloc(sizeof(RSA_METHOD));
	if (meth == NULL) return NULL;

	memset(meth, 0, sizeof(*meth));
	meth->name = BUF_strdup(name);
	meth->flags = flags;

	return(meth);
}


static inline void
RSA_meth_free(RSA_METHOD *meth) {
	if (meth == NULL) return;

	if (meth->name != NULL)
		OPENSSL_free((char*)meth->name);
	OPENSSL_free(meth);
}


static inline RSA_METHOD*
RSA_meth_dup(const RSA_METHOD *meth) {
	RSA_METHOD *ret;

	if (meth == NULL) return NULL;

	ret = OPENSSL_malloc(sizeof(RSA_METHOD));
	if (ret == NULL) return NULL;

	memcpy(ret, meth, sizeof(*meth));
	ret->name = BUF_strdup(meth->name);

	return(ret);
}
#endif /*ndef HAVE_RSA_METH_NEW*/


#ifndef HAVE_RSA_METH_SET1_NAME
static inline int
RSA_meth_set1_name(RSA_METHOD *meth, const char *name) {
	if (meth->name != NULL)
		OPENSSL_free((char*)meth->name);
	meth->name = BUF_strdup(name);

	return meth->name != NULL;
}
#endif /*ndef HAVE_RSA_METH_SET1_NAME*/


#ifndef HAVE_RSA_METH_SET_PRIV_ENC
typedef int (*priv_enc_f) (int flen, const unsigned char *from,
	unsigned char *to, RSA *rsa, int padding);

static inline int
RSA_meth_set_priv_enc(RSA_METHOD *meth, priv_enc_f priv_enc) {
	meth->rsa_priv_enc = priv_enc;
	return 1;
}


typedef int (*priv_dec_f) (int flen, const unsigned char *from,
	unsigned char *to, RSA *rsa, int padding);

static inline int
RSA_meth_set_priv_dec(RSA_METHOD *meth, priv_dec_f priv_dec) {
	meth->rsa_priv_dec = priv_dec;
	return 1;
}
#endif /*ndef HAVE_RSA_METH_SET_PRIV_ENC*/


#ifndef HAVE_RSA_METH_GET_PUB_ENC
typedef int (*pub_enc_f) (int flen, const unsigned char *from,
	unsigned char *to, RSA *rsa, int padding);

static inline pub_enc_f
RSA_meth_get_pub_enc(const RSA_METHOD *meth) { return meth->rsa_pub_enc; }

static inline int
RSA_meth_set_pub_enc(RSA_METHOD *meth, pub_enc_f pub_enc) {
	meth->rsa_pub_enc = pub_enc;
	return 1;
}


typedef int (*pub_dec_f) (int flen, const unsigned char *from,
	unsigned char *to, RSA *rsa, int padding);

static inline pub_dec_f
RSA_meth_get_pub_dec(const RSA_METHOD *meth) { return meth->rsa_pub_dec; }

static inline int
RSA_meth_set_pub_dec(RSA_METHOD *meth, pub_dec_f pub_dec) {
	meth->rsa_pub_dec = pub_dec;
	return 1;
}


typedef int (*rsa_mod_exp_f) (BIGNUM *r0, const BIGNUM *I, RSA *rsa,
	BN_CTX *ctx);

static inline rsa_mod_exp_f
RSA_meth_get_mod_exp(const RSA_METHOD *meth) { return meth->rsa_mod_exp; }

static inline int
RSA_meth_set_mod_exp(RSA_METHOD *meth, rsa_mod_exp_f rsa_mod_exp ) {
	meth->rsa_mod_exp = rsa_mod_exp;
	return 1;
}


typedef int (*rsa_bn_mod_exp_f) (BIGNUM *r, const BIGNUM *a,
	const BIGNUM *p, const BIGNUM *m, BN_CTX *ctx,
	BN_MONT_CTX *m_ctx);

static inline rsa_bn_mod_exp_f
RSA_meth_get_bn_mod_exp(const RSA_METHOD *meth) { return meth->bn_mod_exp; }

static inline int
RSA_meth_set_bn_mod_exp(RSA_METHOD *meth, rsa_bn_mod_exp_f bn_mod_exp) {
	meth->bn_mod_exp = bn_mod_exp;
	return 1;
}
#endif /*ndef HAVE_RSA_METH_GET_PUB_ENC*/
#endif /*def USE_RSA_METHOD*/


#ifdef USE_DSA_METHOD
#ifndef HAVE_DSA_METH_NEW		/* OpenSSL < 1.1 */
/* Partial backport of opaque DSA from OpenSSL >= 1.1, commits
 * "Make DSA_METHOD opaque", "Various DSA opacity fixups",
 * "RSA, DSA, DH: Allow some given input to be NULL on already
 * initialised keys" and etc.
 */

/* opaque DSA method structure */
static inline DSA_METHOD*
DSA_meth_new(const char *name, int flags) {
	DSA_METHOD *meth;

	meth = OPENSSL_malloc(sizeof(DSA_METHOD));
	if (meth == NULL) return NULL;

	memset(meth, 0, sizeof(*meth));
	meth->name = BUF_strdup(name);
	meth->flags = flags;

	return(meth);
}


static inline void
DSA_meth_free(DSA_METHOD *meth) {
	if (meth == NULL) return;

	if (meth->name != NULL)
		OPENSSL_free((char*)meth->name);
	OPENSSL_free(meth);
}


typedef DSA_SIG* (*dsa_sign_f) (const unsigned char*, int, DSA*);

static inline int
DSA_meth_set_sign(DSA_METHOD *meth, dsa_sign_f sign) {
	meth->dsa_do_sign = sign;
	return 1;
}
#endif /*ndef HAVE_DSA_METH_NEW*/


#ifndef HAVE_DSA_METH_GET_VERIFY
typedef int (*dsa_verify_f) (const unsigned char*, int, DSA_SIG*, DSA*);

static inline dsa_verify_f
DSA_meth_get_verify(const DSA_METHOD *meth) { return meth->dsa_do_verify; }

static inline int
DSA_meth_set_verify(DSA_METHOD *meth, dsa_verify_f verify) {
	meth->dsa_do_verify = verify;
	return 1;
}


typedef int (*mod_exp_f) (DSA*, BIGNUM*, BIGNUM*, BIGNUM*,
	BIGNUM*, BIGNUM*, BIGNUM*, BN_CTX*, BN_MONT_CTX*);

static inline mod_exp_f
DSA_meth_get_mod_exp(const DSA_METHOD *meth) { return meth->dsa_mod_exp; }

static inline int
DSA_meth_set_mod_exp(DSA_METHOD *meth, mod_exp_f mod_exp) {
	meth->dsa_mod_exp = mod_exp;
	return 1;
}


typedef int (*bn_mod_exp_f) (DSA*, BIGNUM*, BIGNUM*,
	const BIGNUM*, const BIGNUM*, BN_CTX*, BN_MONT_CTX*);

static inline bn_mod_exp_f
DSA_meth_get_bn_mod_exp(const DSA_METHOD *meth) { return meth->bn_mod_exp; }

static inline int
DSA_meth_set_bn_mod_exp(DSA_METHOD *meth, bn_mod_exp_f bn_mod_exp) {
	meth->bn_mod_exp = bn_mod_exp;
	return 1;
}
#endif /*ndef HAVE_DSA_METH_GET_VERIFY*/
#endif /*def USE_DSA_METHOD*/


#ifdef OPENSSL_HAS_ECC
# ifndef HAVE_EC_KEY_METHOD_NEW	/* OpenSSL < 1.1 */
#  include <openssl/ecdsa.h>


#ifndef HAVE_ECDSA_METHOD_NEW	/* OpenSSL < 1.0.2 */

#ifndef HAVE_ECDSA_METHOD_NAME
/*declared in some OpenSSL compatible headers*/
struct ecdsa_method {
    const char *name;
    ECDSA_SIG *(*ecdsa_do_sign) (const unsigned char *dgst, int dgst_len,
                                 const BIGNUM *inv, const BIGNUM *rp,
                                 EC_KEY *eckey);
    int (*ecdsa_sign_setup) (EC_KEY *eckey, BN_CTX *ctx, BIGNUM **kinv,
                             BIGNUM **r);
    int (*ecdsa_do_verify) (const unsigned char *dgst, int dgst_len,
                            const ECDSA_SIG *sig, EC_KEY *eckey);
# if 0
    int (*init) (EC_KEY *eckey);
    int (*finish) (EC_KEY *eckey);
# endif
    int flags;
    void *app_data;
};
#endif /*ndef HAVE_ECDSA_METHOD_NAME*/


static inline ECDSA_METHOD*
ECDSA_METHOD_new(const ECDSA_METHOD *ecdsa_method)
{
    UNUSED(ecdsa_method);
    return OPENSSL_malloc(sizeof(ECDSA_METHOD));
}

static inline void
ECDSA_METHOD_free(ECDSA_METHOD *ecdsa_method)
{
    OPENSSL_free(ecdsa_method);
}

static inline void
ECDSA_METHOD_set_sign(
    ECDSA_METHOD *ecdsa_method,
    ECDSA_SIG *(*ecdsa_do_sign) (
        const unsigned char *dgst, int dgst_len,
        const BIGNUM *inv, const BIGNUM *rp, EC_KEY *eckey)
) {
    ecdsa_method->ecdsa_do_sign = ecdsa_do_sign;
}
#endif /*ndef HAVE_ECDSA_METHOD_NEW	OpenSSL < 1.0.2 */


/* mimic some ECDSA functions in OpenSSL API v1.1 style */
typedef ECDSA_METHOD EC_KEY_METHOD;

static inline const EC_KEY_METHOD*
EC_KEY_OpenSSL(void) {
	return /*ECDSA_METHOD*/ECDSA_OpenSSL();
}

static inline EC_KEY_METHOD*
EC_KEY_METHOD_new(const EC_KEY_METHOD *meth) {
	return ECDSA_METHOD_new(/*ECDSA_METHOD*/meth);
}

static inline void
EC_KEY_METHOD_free(EC_KEY_METHOD *meth) {
	ECDSA_METHOD_free(/*ECDSA_METHOD*/meth);
}

static inline int
EC_KEY_set_method(EC_KEY *key, const EC_KEY_METHOD *meth) {
	return ECDSA_set_method(key, /*ECDSA_METHOD*/meth);
}

/* NOTE: In OpenSSL 1.1 EC_KEY_get_ex_new_index(...) is define to
 * CRYPTO_get_ex_new_index(CRYPTO_EX_INDEX_EC_KEY, ...)
 */
static inline int
EC_KEY_get_ex_new_index(long argl, void *argp,
	CRYPTO_EX_new *new_func,
	CRYPTO_EX_dup *dup_func,
	CRYPTO_EX_free *free_func
) {
	return ECDSA_get_ex_new_index(argl, argp, new_func, dup_func, free_func);
}

static inline void*
EC_KEY_get_ex_data(const EC_KEY *key, int idx) {
	return ECDSA_get_ex_data((EC_KEY *)key, idx);
}

static inline int
EC_KEY_set_ex_data(EC_KEY *key, int idx, void *arg) {
	return ECDSA_set_ex_data(key, idx, arg);
}

# endif /*def HAVE_EC_KEY_METHOD_NEW*/
#endif /*def OPENSSL_HAS_ECC*/

#endif /*def ENABLE_PKCS11*/
#endif /*ndef SSH_PKCS11_H*/
