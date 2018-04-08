/* $OpenBSD: ssh-rsa.c,v 1.66 2018/02/14 16:27:24 jsing Exp $ */
/*
 * Copyright (c) 2000, 2003 Markus Friedl <markus@openbsd.org>
 * Copyright (c) 2011 Dr. Stephen Henson.  All rights reserved.
 * Copyright (c) 2011-2017 Roumen Petrov.  All rights reserved.
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

#ifdef WITH_OPENSSL

#include <sys/types.h>

#include <openssl/evp.h>
#include <openssl/err.h>

#include <stdarg.h>
#include <string.h>

#include "sshbuf.h"
#include "compat.h"
#include "ssherr.h"
#define SSHKEY_INTERNAL
#include "sshkey.h"
#include "digest.h"
#include "evp-compat.h"
#include "xmalloc.h"
#include "log.h"

static const char *
rsa_hash_alg_ident(int hash_alg)
{
	switch (hash_alg) {
	case SSH_DIGEST_SHA1:
		return "ssh-rsa";
#ifdef HAVE_EVP_SHA256
	case SSH_DIGEST_SHA256:
		return "rsa-sha2-256";
	case SSH_DIGEST_SHA512:
		return "rsa-sha2-512";
#endif /*def HAVE_EVP_SHA256*/
	}
	return NULL;
}

static int
rsa_hash_alg_from_ident(const char *ident)
{
	if (strcmp(ident, "ssh-rsa") == 0 ||
	    strcmp(ident, "ssh-rsa-cert-v01@openssh.com") == 0)
		return SSH_DIGEST_SHA1;
#ifdef HAVE_EVP_SHA256
	if (strcmp(ident, "rsa-sha2-256") == 0)
		return SSH_DIGEST_SHA256;
	if (strcmp(ident, "rsa-sha2-512") == 0)
		return SSH_DIGEST_SHA512;
#endif /*def HAVE_EVP_SHA256*/
	return -1;
}

static int
rsa_hash_alg_nid(int type)
{
	switch (type) {
	case SSH_DIGEST_SHA1:
		return NID_sha1;
	case SSH_DIGEST_SHA256:
		return NID_sha256;
	case SSH_DIGEST_SHA512:
		return NID_sha512;
	default:
		return -1;
	}
}

#ifndef BN_FLG_CONSTTIME
#  define BN_FLG_CONSTTIME 0x0 /* OpenSSL < 0.9.8 */
#endif
int
ssh_rsa_generate_additional_parameters(struct sshkey *key)
{
	BIGNUM *aux = NULL;
	BN_CTX *ctx = NULL;
	BIGNUM *d = NULL;
	int r;

	if (key == NULL || key->rsa == NULL ||
	    sshkey_type_plain(key->type) != KEY_RSA)
		return SSH_ERR_INVALID_ARGUMENT;

	if ((ctx = BN_CTX_new()) == NULL)
		return SSH_ERR_ALLOC_FAIL;
	if ((aux = BN_new()) == NULL) {
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	BN_set_flags(aux, BN_FLG_CONSTTIME);

	if ((d = BN_new()) == NULL) {
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}

{	const BIGNUM *p = NULL, *q = NULL;
	BIGNUM *dmp1 = NULL, *dmq1 = NULL;
	RSA *rsa = key->rsa;

	RSA_get0_factors(rsa, &p, &q);
	RSA_get0_crt_params(rsa, (const BIGNUM**)&dmp1, (const BIGNUM**)&dmq1, NULL);

	{	const BIGNUM *key_d;
		RSA_get0_key(rsa, NULL, NULL, &key_d);
		BN_with_flags(d, key_d, BN_FLG_CONSTTIME);
	}

	if ((BN_sub(aux, q, BN_value_one()) == 0) ||
	    (BN_mod(dmq1, d, aux, ctx) == 0) ||
	    (BN_sub(aux, p, BN_value_one()) == 0) ||
	    (BN_mod(dmp1, d, aux, ctx) == 0)) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		goto out;
	}
}
	r = 0;
 out:
/* !	BN_clear_free(d) - erroneous clear of shared data in OpenSSL < 1.1.1 */
	BN_free(d);
	BN_clear_free(aux);
	BN_CTX_free(ctx);
	return r;
}

/* RSASSA-PKCS1-v1_5 (PKCS #1 v2.0 signature) with SHA1 */
int
ssh_rsa_sign(const struct sshkey *key, u_char **sigp, size_t *lenp,
    const u_char *data, size_t datalen, const char *alg_ident)
{
	u_char *sig = NULL;
	size_t slen = 0;
	u_int len;
	int nid, hash_alg, ret = SSH_ERR_INTERNAL_ERROR;
	struct sshbuf *b = NULL;

	if (lenp != NULL)
		*lenp = 0;
	if (sigp != NULL)
		*sigp = NULL;

	if (alg_ident == NULL || strlen(alg_ident) == 0)
		hash_alg = SSH_DIGEST_SHA1;
	else
		hash_alg = rsa_hash_alg_from_ident(alg_ident);
	debug3("%s  hash_alg=%d/%s", __func__, hash_alg, rsa_hash_alg_ident(hash_alg));
	if (key == NULL || key->rsa == NULL || hash_alg == -1 ||
	    sshkey_type_plain(key->type) != KEY_RSA)
		return SSH_ERR_INVALID_ARGUMENT;
{	const BIGNUM *n = NULL;
	RSA_get0_key(key->rsa, &n, NULL, NULL);
	if (BN_num_bits(n) < SSH_RSA_MINIMUM_MODULUS_SIZE)
		return SSH_ERR_KEY_LENGTH;
}
	slen = RSA_size(key->rsa);
	if (slen <= 0 || slen > SSHBUF_MAX_BIGNUM)
		return SSH_ERR_INVALID_ARGUMENT;

	/* hash the data */
	nid = rsa_hash_alg_nid(hash_alg);
{
	const EVP_MD *evp_md;
	EVP_PKEY *pkey = NULL;
	int ok = -1;

	sig = NULL;

	if ((evp_md = EVP_get_digestbynid(nid)) == NULL) {
		error("%s: EVP_get_digestbynid %d failed", __func__, nid);
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		goto out;
	}

	pkey = EVP_PKEY_new();
	if (pkey == NULL) {
		error("%s: out of memory", __func__);
		goto done;
	}

	EVP_PKEY_set1_RSA(pkey, key->rsa);

	slen = EVP_PKEY_size(pkey);
	sig = xmalloc(slen);	/*fatal on error*/

{
	EVP_MD_CTX *md;

	md = EVP_MD_CTX_new();
	if (md == NULL) {
		ok = -1;
		error("%s: out of memory", __func__);
		goto clean;
	}

	ok = EVP_SignInit_ex(md, evp_md, NULL);
	if (ok <= 0) {
#ifdef TRACE_EVP_ERROR
		char ebuf[1024];
		openssl_errormsg(ebuf, sizeof(ebuf));
		error("%s: EVP_SignInit_ex fail with errormsg='%.*s'"
		, __func__
		, (int)sizeof(ebuf), ebuf);
#endif
		goto clean;
	}

	ok = EVP_SignUpdate(md, data, datalen);
	if (ok <= 0) {
#ifdef TRACE_EVP_ERROR
		char ebuf[1024];
		openssl_errormsg(ebuf, sizeof(ebuf));
		error("%s: EVP_SignUpdate fail with errormsg='%.*s'"
		, __func__
		, (int)sizeof(ebuf), ebuf);
#endif
		goto clean;
	}

	ok = EVP_SignFinal(md, sig, &len, pkey);
	if (ok <= 0) {
#ifdef TRACE_EVP_ERROR
		char ebuf[1024];
		openssl_errormsg(ebuf, sizeof(ebuf));
		error("%s: SignFinal fail with errormsg='%.*s'"
		, __func__
		, (int)sizeof(ebuf), ebuf);
#endif
		goto clean;
	}

clean:
	EVP_MD_CTX_free(md);
}

done:
	if (pkey != NULL) EVP_PKEY_free(pkey);

	if (ok <= 0) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		goto out;
	}
}

	if (len < slen) {
		size_t diff = slen - len;
		memmove(sig + diff, sig, len);
		explicit_bzero(sig, diff);
	} else if (len > slen) {
		ret = SSH_ERR_INTERNAL_ERROR;
		goto out;
	}
	/* encode signature */
	if ((b = sshbuf_new()) == NULL) {
		ret = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	if ((ret = sshbuf_put_cstring(b, rsa_hash_alg_ident(hash_alg))) != 0 ||
	    (ret = sshbuf_put_string(b, sig, slen)) != 0)
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
	freezero(sig, slen);
	sshbuf_free(b);
	return ret;
}

int
ssh_rsa_verify(const struct sshkey *key,
    const u_char *sig, size_t siglen, const u_char *data, size_t datalen,
    const char *alg)
{
	char *sigtype = NULL;
	int hash_alg, ret = SSH_ERR_INTERNAL_ERROR;
	size_t len = 0, diff, modlen;
	struct sshbuf *b = NULL;
	u_char *osigblob, *sigblob = NULL;

	if (key == NULL || key->rsa == NULL ||
	    sshkey_type_plain(key->type) != KEY_RSA ||
	    sig == NULL || siglen == 0)
		return SSH_ERR_INVALID_ARGUMENT;
{	const BIGNUM *n = NULL;
	RSA_get0_key(key->rsa, &n, NULL, NULL);
	if (BN_num_bits(n) < SSH_RSA_MINIMUM_MODULUS_SIZE)
		return SSH_ERR_KEY_LENGTH;
}

	if ((b = sshbuf_from(sig, siglen)) == NULL)
		return SSH_ERR_ALLOC_FAIL;
	if (sshbuf_get_cstring(b, &sigtype, NULL) != 0) {
		ret = SSH_ERR_INVALID_FORMAT;
		goto out;
	}
	/* XXX djm: need cert types that reliably yield SHA-2 signatures */
	if (alg != NULL && strcmp(alg, sigtype) != 0 &&
	    strcmp(alg, "ssh-rsa-cert-v01@openssh.com") != 0) {
		error("%s: RSA signature type mismatch: "
		    "expected %s received %s", __func__, alg, sigtype);
		ret = SSH_ERR_SIGNATURE_INVALID;
		goto out;
	}
	if ((hash_alg = rsa_hash_alg_from_ident(sigtype)) == -1) {
		ret = SSH_ERR_KEY_TYPE_MISMATCH;
		goto out;
	}
	debug3("%s  hash_alg=%d/%s", __func__, hash_alg, rsa_hash_alg_ident(hash_alg));
	if (sshbuf_get_string(b, &sigblob, &len) != 0) {
		ret = SSH_ERR_INVALID_FORMAT;
		goto out;
	}
	if (sshbuf_len(b) != 0) {
		ret = SSH_ERR_UNEXPECTED_TRAILING_DATA;
		goto out;
	}
	/* RSA_verify expects a signature of RSA_size */
	modlen = RSA_size(key->rsa);
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
{
	int nid;
	const EVP_MD *evp_md;
	EVP_PKEY *pkey;
	int ok = -1;

	nid = rsa_hash_alg_nid(hash_alg);
	if ((evp_md = EVP_get_digestbynid(nid)) == NULL) {
		error("%s: EVP_get_digestbynid %d failed", __func__, nid);
		free(sigblob);
		return -1;
	}

	ok = -1;
	pkey = EVP_PKEY_new();
	if (pkey == NULL) {
		error("%s: out of memory", __func__);
		goto done;
	}

	EVP_PKEY_set1_RSA(pkey, key->rsa);

{
	EVP_MD_CTX *md;

	md = EVP_MD_CTX_new();
	if (md == NULL) {
		ok = -1;
		error("%s: out of memory", __func__);
		goto clean;
	}

	ok = EVP_VerifyInit(md, evp_md);
	if (ok <= 0) {
#ifdef TRACE_EVP_ERROR
		char ebuf[1024];
		openssl_errormsg(ebuf, sizeof(ebuf));
		error("%s: EVP_VerifyInit fail with errormsg='%.*s'"
		, __func__
		, (int)sizeof(ebuf), ebuf);
#endif
		goto clean;
	}

	ok = EVP_VerifyUpdate(md, data, datalen);
	if (ok <= 0) {
#ifdef TRACE_EVP_ERROR
		char ebuf[1024];
		openssl_errormsg(ebuf, sizeof(ebuf));
		error("%s: EVP_VerifyUpdate fail with errormsg='%.*s'"
		, __func__
		, (int)sizeof(ebuf), ebuf);
#endif
		goto clean;
	}

	ok = EVP_VerifyFinal(md, sigblob, len, pkey);
	if (ok <= 0) {
#ifdef TRACE_EVP_ERROR
		char ebuf[1024];
		openssl_errormsg(ebuf, sizeof(ebuf));
		error("%s: EVP_VerifyFinal fail with errormsg='%.*s'"
		, __func__
		, (int)sizeof(ebuf), ebuf);
#endif
		goto clean;
	}

clean:
	EVP_MD_CTX_free(md);
}

done:
	if (pkey != NULL) EVP_PKEY_free(pkey);

	if (ok <= 0) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		goto out;
	} else
		ret = SSH_ERR_SUCCESS;
}

 out:
	freezero(sigblob, len);
	free(sigtype);
	sshbuf_free(b);
	return ret;
}

#endif /* WITH_OPENSSL */
