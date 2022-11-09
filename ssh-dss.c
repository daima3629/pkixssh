/* $OpenBSD: ssh-dss.c,v 1.39 2020/02/26 13:40:09 jsg Exp $ */
/*
 * Copyright (c) 2000 Markus Friedl.  All rights reserved.
 * Copyright (c) 2011 Dr. Stephen Henson.  All rights reserved.
 * Copyright (c) 2011-2022 Roumen Petrov.  All rights reserved.
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
/* TODO implement OpenSSL 3.1 API */
# define OPENSSL_SUPPRESS_DEPRECATED
#endif

#include "includes.h"

#ifdef WITH_OPENSSL

#include <sys/types.h>

#include <openssl/bn.h>
#include <openssl/evp.h>
#include "evp-compat.h"

#include <stdarg.h>
#include <string.h>

#include "sshbuf.h"
#include "compat.h"
#include "ssherr.h"
#include "digest.h"
#define SSHKEY_INTERNAL
#include "sshkey.h"
#include "xmalloc.h"
#include "log.h"


#define INTBLOB_LEN	20
#define SIGBLOB_LEN	(2*INTBLOB_LEN)

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

int
sshdsa_verify_length(int bits) {
	return bits != SSH_DSA_BITS
	    ? SSH_ERR_KEY_LENGTH : 0;
}

extern int /*TODO static - see sshkey-crypto.c */
sshkey_init_dsa_params(struct sshkey *key, BIGNUM *p, BIGNUM *q, BIGNUM *g);

int
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

extern int /*TODO static - see sshkey-crypto.c */
sshkey_set_dsa_key(struct sshkey *key, BIGNUM *pub_key, BIGNUM *priv_key);

int
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
ssh_dss_generate(struct sshkey *key, int bits) {
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

/* caller must free result */
static DSA_SIG*
ssh_dss_sign_pkey(const struct sshkey *key, const u_char *data, u_int datalen)
{
	DSA_SIG *sig = NULL;
	u_char *tsig = NULL;
	u_int slen, len;
	int ret;

	slen = EVP_PKEY_size(key->pk);
	tsig = xmalloc(slen);	/*fatal on error*/

{
	EVP_MD_CTX *md;

	md = EVP_MD_CTX_new();
	if (md == NULL) {
		ret = -1;
		error_f("out of memory");
		goto clean;
	}

	ret = EVP_SignInit_ex(md, EVP_dss1(), NULL);
	if (ret <= 0) {
#ifdef TRACE_EVP_ERROR
		error_crypto("EVP_SignInit_ex");
#endif
		goto clean;
	}

	ret = EVP_SignUpdate(md, data, datalen);
	if (ret <= 0) {
#ifdef TRACE_EVP_ERROR
		error_crypto("EVP_SignUpdate");
#endif
		goto clean;
	}

	ret = EVP_SignFinal(md, tsig, &len, key->pk);
	if (ret <= 0) {
#ifdef TRACE_EVP_ERROR
		error_crypto("EVP_SignFinal");
#endif
		goto clean;
	}

clean:
	EVP_MD_CTX_free(md);
}

	if (ret > 0) {
		/* decode DSA signature */
		const u_char *psig = tsig;
		sig = d2i_DSA_SIG(NULL, &psig, len);
	}

	if (tsig != NULL) {
		/* clean up */
		memset(tsig, 'd', slen);
		free(tsig);
	}

	return sig;
}


int
ssh_dss_sign(const ssh_sign_ctx *ctx, u_char **sigp, size_t *lenp,
    const u_char *data, size_t datalen)
{
	const struct sshkey *key = ctx->key;
	DSA_SIG *sig = NULL;
	u_char sigblob[SIGBLOB_LEN];
	size_t rlen, slen, len, dlen = ssh_digest_bytes(SSH_DIGEST_SHA1);
	struct sshbuf *b = NULL;
	int ret = SSH_ERR_INVALID_ARGUMENT;

	if (lenp != NULL)
		*lenp = 0;
	if (sigp != NULL)
		*sigp = NULL;

	if (dlen == 0)
		return SSH_ERR_INTERNAL_ERROR;

	ret = sshkey_validate_public_dsa(key);
	if (ret != 0) return ret;

	sig = ssh_dss_sign_pkey(key, data, datalen);
	if (sig == NULL) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		goto out;
	}

{	const BIGNUM *ps, *pr;
	DSA_SIG_get0(sig, &pr, &ps);

	rlen = BN_num_bytes(pr);
	slen = BN_num_bytes(ps);
	if (rlen > INTBLOB_LEN || slen > INTBLOB_LEN) {
		ret = SSH_ERR_INTERNAL_ERROR;
		goto out;
	}
	explicit_bzero(sigblob, SIGBLOB_LEN);
	BN_bn2bin(pr, sigblob + SIGBLOB_LEN - INTBLOB_LEN - rlen);
	BN_bn2bin(ps, sigblob + SIGBLOB_LEN - slen);
}

	if ((b = sshbuf_new()) == NULL) {
		ret = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	if ((ret = sshbuf_put_cstring(b, "ssh-dss")) != 0 ||
	    (ret = sshbuf_put_string(b, sigblob, SIGBLOB_LEN)) != 0)
		goto out;

	len = sshbuf_len(b);
	if (sigp != NULL) {
		if ((*sigp = malloc(len)) == NULL) {
			ret = SSH_ERR_ALLOC_FAIL;
			goto out;
		}
		memcpy(*sigp, sshbuf_ptr(b), len);
	}
	if (lenp != NULL)
		*lenp = len;
	ret = 0;
 out:
	DSA_SIG_free(sig);
	sshbuf_free(b);
	return ret;
}


static int
ssh_dss_verify_pkey(const struct sshkey *key, DSA_SIG *sig, const u_char *data, u_int datalen)
{
	int ret;
	u_char *tsig = NULL;
	u_int len;

	/* Sig is in DSA_SIG structure, convert to encoded buffer */
	len = i2d_DSA_SIG(sig, NULL);
	tsig = xmalloc(len);	/*fatal on error*/

	{ /* encode a DSA signature */
		u_char *psig = tsig;
		i2d_DSA_SIG(sig, &psig);
	}

{ /* now verify signature */
	int ok;
	EVP_MD_CTX *md;

	md = EVP_MD_CTX_new();
	if (md == NULL) {
		error_f("out of memory");
		ret = SSH_ERR_ALLOC_FAIL;
		goto clean;
	}

	ok = EVP_VerifyInit(md, EVP_dss1());
	if (ok <= 0) {
#ifdef TRACE_EVP_ERROR
		error_crypto("EVP_VerifyInit");
#endif
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		goto clean;
	}

	ok = EVP_VerifyUpdate(md, data, datalen);
	if (ok <= 0) {
#ifdef TRACE_EVP_ERROR
		error_crypto("EVP_VerifyUpdate");
#endif
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		goto clean;
	}

	ok = EVP_VerifyFinal(md, tsig, len, key->pk);
	if (ok < 0) {
#ifdef TRACE_EVP_ERROR
		error_crypto("EVP_VerifyFinal");
#endif
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		goto clean;
	}
	ret = (ok == 0)
		? SSH_ERR_SIGNATURE_INVALID
		: SSH_ERR_SUCCESS;

clean:
	EVP_MD_CTX_free(md);
}

	if (tsig != NULL) {
		/* clean up */
		memset(tsig, 'd', len);
		free(tsig);
	}

	return ret;
}


int
ssh_dss_verify(const ssh_verify_ctx *ctx,
    const u_char *sig, size_t siglen,
    const u_char *data, size_t dlen)
{
	const struct sshkey *key = ctx->key;
	DSA_SIG *dsig = NULL;
	u_char *sigblob = NULL;
	size_t len, hlen = ssh_digest_bytes(SSH_DIGEST_SHA1);
	int ret = SSH_ERR_INTERNAL_ERROR;
	struct sshbuf *b = NULL;
	char *ktype = NULL;

	if (sig == NULL || siglen == 0)
		return SSH_ERR_INVALID_ARGUMENT;
	if (hlen == 0)
		return SSH_ERR_INTERNAL_ERROR;

	ret = sshkey_validate_public_dsa(key);
	if (ret != 0) return ret;

	/* fetch signature */
	if ((b = sshbuf_from(sig, siglen)) == NULL)
		return SSH_ERR_ALLOC_FAIL;
	if (sshbuf_get_cstring(b, &ktype, NULL) != 0 ||
	    sshbuf_get_string(b, &sigblob, &len) != 0) {
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

{	/* parse signature */
	BIGNUM *pr, *ps;

	ret = 0;
	pr = BN_bin2bn(sigblob, INTBLOB_LEN, NULL);
	ps = BN_bin2bn(sigblob+ INTBLOB_LEN, INTBLOB_LEN, NULL);
	if ((pr == NULL) || (ps == NULL)) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		goto parse_out;
	}

	dsig = DSA_SIG_new();
	if (dsig == NULL) {
		ret = SSH_ERR_ALLOC_FAIL;
		goto parse_out;
	}

	if (!DSA_SIG_set0(dsig, pr, ps))
		ret = SSH_ERR_LIBCRYPTO_ERROR;

parse_out:
	if (ret != 0) {
		BN_free(pr);
		BN_free(ps);
		goto out;
	}
}

	ret = ssh_dss_verify_pkey(key, dsig, data, dlen);

 out:
	DSA_SIG_free(dsig);
	sshbuf_free(b);
	free(ktype);
	if (sigblob != NULL)
		freezero(sigblob, len);
	return ret;
}

static const struct sshkey_impl_funcs sshkey_dss_funcs = {
	/* .size = */		ssh_dss_size,
	/* .alloc =		NULL, */
	/* .cleanup = */	ssh_dss_cleanup,
	/* .equal = */		ssh_dss_equal,
	/* .generate = */	ssh_dss_generate,
	/* .move_public = */	ssh_dss_move_public,
	/* .copy_public = */	ssh_dss_copy_public
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

#endif /* WITH_OPENSSL */
