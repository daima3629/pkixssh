/* $OpenBSD: ssh-ecdsa.c,v 1.16 2019/01/21 09:54:11 djm Exp $ */
/*
 * Copyright (c) 2000 Markus Friedl.  All rights reserved.
 * Copyright (c) 2010 Damien Miller.  All rights reserved.
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

#include "includes.h"

#if defined(WITH_OPENSSL) && defined(OPENSSL_HAS_ECC)

#include <sys/types.h>

#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/evp.h>
#include "evp-compat.h"

#include <string.h>

#include "sshbuf.h"
#include "ssherr.h"
#include "digest.h"
#define SSHKEY_INTERNAL
#include "sshkey.h"

#if 1
# define USE_EC_PKEY_SIGN
#endif
#if 1
# define USE_EC_PKEY_VERIFY
#endif

#if defined(USE_EC_PKEY_SIGN) || defined(USE_EC_PKEY_VERIFY)
# include "log.h"
# include "xmalloc.h"
#endif

#ifdef USE_EC_PKEY_SIGN
/* caller must free result */
static ECDSA_SIG*
ssh_ecdsa_pkey_sign(EC_KEY *ec, const EVP_MD *type, const u_char *data, u_int datalen) {
	ECDSA_SIG *sig = NULL;

	EVP_PKEY *pkey = NULL;
	u_char *tsig = NULL;
	u_int slen, len;
	int ret;

	pkey = EVP_PKEY_new();
	if (pkey == NULL) {
		error("%s: out of memory", __func__);
		return NULL;
	}

	EVP_PKEY_set1_EC_KEY(pkey, ec);

	slen = EVP_PKEY_size(pkey);
	tsig = xmalloc(slen);	/*fatal on error*/

{
	EVP_MD_CTX *md;

	md = EVP_MD_CTX_new();
	if (md == NULL) {
		ret = -1;
		error("%s: out of memory", __func__);
		goto clean;
	}

	ret = EVP_SignInit_ex(md, type, NULL);
	if (ret <= 0) {
#ifdef TRACE_EVP_ERROR
		char ebuf[1024];
		crypto_errormsg(ebuf, sizeof(ebuf));
		error("%s: EVP_SignInit_ex fail with errormsg: '%s'"
		    , __func__, ebuf);
#endif
		goto clean;
	}

	ret = EVP_SignUpdate(md, data, datalen);
	if (ret <= 0) {
#ifdef TRACE_EVP_ERROR
		char ebuf[1024];
		crypto_errormsg(ebuf, sizeof(ebuf));
		error("%s: EVP_SignUpdate fail with errormsg: '%s'"
		    , __func__, ebuf);
#endif
		goto clean;
	}

	ret = EVP_SignFinal(md, tsig, &len, pkey);
	if (ret <= 0) {
#ifdef TRACE_EVP_ERROR
		char ebuf[1024];
		crypto_errormsg(ebuf, sizeof(ebuf));
		error("%s: sign failed: %s", __func__, ebuf);
#endif
		goto clean;
	}

clean:
	EVP_MD_CTX_free(md);
}

	if (ret > 0) {
		/* decode DSA signature */
		const u_char *psig = tsig;
		sig = d2i_ECDSA_SIG(NULL, &psig, (long)len);
	}

	if (tsig != NULL) {
		/* clean up */
		memset(tsig, 'd', slen);
		free(tsig);
	}

	if (pkey != NULL) EVP_PKEY_free(pkey);

	return sig;
}
#endif /*def USE_EC_PKEY_SIGN*/

int
ssh_ecdsa_sign(const struct sshkey *key, u_char **sigp, size_t *lenp,
    const u_char *data, size_t datalen, u_int compat)
{
	ECDSA_SIG *sig = NULL;
	int hash_alg;
	size_t len;
	struct sshbuf *b = NULL, *bb = NULL;
	int ret = SSH_ERR_INTERNAL_ERROR;

	UNUSED(compat);
	if (lenp != NULL)
		*lenp = 0;
	if (sigp != NULL)
		*sigp = NULL;

	if (key == NULL || key->ecdsa == NULL ||
	    sshkey_type_plain(key->type) != KEY_ECDSA)
		return SSH_ERR_INVALID_ARGUMENT;

#ifndef USE_EC_PKEY_SIGN
{
	u_char digest[SSH_DIGEST_MAX_LENGTH];
	size_t dlen;

	if ((hash_alg = sshkey_ec_nid_to_hash_alg(key->ecdsa_nid)) == -1 ||
	    (dlen = ssh_digest_bytes(hash_alg)) == 0)
		return SSH_ERR_INTERNAL_ERROR;
	if ((ret = ssh_digest_memory(hash_alg, data, datalen,
	    digest, sizeof(digest))) != 0)
		goto out;

	if ((sig = ECDSA_do_sign(digest, dlen, key->ecdsa)) == NULL) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		explicit_bzero(digest, sizeof(digest));
		goto out;
	}
	explicit_bzero(digest, sizeof(digest));
}
#else
{
	const EVP_MD *md;

	hash_alg = sshkey_ec_nid_to_hash_alg(key->ecdsa_nid);
	switch (hash_alg) {
	case SSH_DIGEST_SHA256: md = ssh_ecdsa_EVP_sha256(); break;
	case SSH_DIGEST_SHA384: md = ssh_ecdsa_EVP_sha384(); break;
	case SSH_DIGEST_SHA512: md = ssh_ecdsa_EVP_sha512(); break;
	default:
		return SSH_ERR_INTERNAL_ERROR;
	}
	if ((sig = ssh_ecdsa_pkey_sign(key->ecdsa, md, data, datalen)) == NULL) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		goto out;
	}
}
#endif

	if ((bb = sshbuf_new()) == NULL || (b = sshbuf_new()) == NULL) {
		ret = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
{
	const BIGNUM *pr, *ps;
	ECDSA_SIG_get0(sig, &pr, &ps);
	if ((ret = sshbuf_put_bignum2(bb, pr)) != 0 ||
	    (ret = sshbuf_put_bignum2(bb, ps)) != 0)
		goto out;
}
	if ((ret = sshbuf_put_cstring(b, sshkey_ssh_name_plain(key))) != 0 ||
	    (ret = sshbuf_put_stringb(b, bb)) != 0)
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
	sshbuf_free(b);
	sshbuf_free(bb);
	ECDSA_SIG_free(sig);
	return ret;
}

#ifdef USE_EC_PKEY_VERIFY
static int
ssh_ecdsa_pkey_verify(EC_KEY *ec, const EVP_MD *type,
    ECDSA_SIG *sig, const u_char *data, u_int datalen)
{
	int ret;
	u_char *tsig = NULL;
	u_int len;
	EVP_PKEY *pkey = NULL;

	/* Sig is in ECDSA_SIG structure, convert to encoded buffer */
	len = i2d_ECDSA_SIG(sig, NULL);
	tsig = xmalloc(len);	/*fatal on error*/

	{ /* encode a DSA signature */
		u_char *psig = tsig;
		i2d_ECDSA_SIG(sig, &psig);
	}

	pkey = EVP_PKEY_new();
	if (pkey == NULL) {
		error("%s: out of memory", __func__);
		ret = SSH_ERR_ALLOC_FAIL;
		goto done;
	}
	EVP_PKEY_set1_EC_KEY(pkey, ec);

{ /* now verify signature */
	int ok;
	EVP_MD_CTX *md;

	md = EVP_MD_CTX_new();
	if (md == NULL) {
		error("%s: out of memory", __func__);
		ret = SSH_ERR_ALLOC_FAIL;
		goto clean;
	}

	ok = EVP_VerifyInit(md, type);
	if (ok <= 0) {
#ifdef TRACE_EVP_ERROR
		char ebuf[1024];
		crypto_errormsg(ebuf, sizeof(ebuf));
		error("%s: EVP_VerifyInit fail with errormsg: '%s'"
		    , __func__, ebuf);
#endif
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		goto clean;
	}

	ok = EVP_VerifyUpdate(md, data, datalen);
	if (ok <= 0) {
#ifdef TRACE_EVP_ERROR
		char ebuf[1024];
		crypto_errormsg(ebuf, sizeof(ebuf));
		error("%s: EVP_VerifyUpdate fail with errormsg: '%s'"
		    , __func__, ebuf);
#endif
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		goto clean;
	}

	ok = EVP_VerifyFinal(md, tsig, len, pkey);
	if (ok < 0) {
#ifdef TRACE_EVP_ERROR
		char ebuf[1024];
		crypto_errormsg(ebuf, sizeof(ebuf));
		error("%s: EVP_VerifyFinal fail with errormsg: '%s'"
		    , __func__, ebuf);
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

done:
	if (pkey != NULL) EVP_PKEY_free(pkey);

	if (tsig != NULL) {
		/* clean up */
		memset(tsig, 'd', len);
		free(tsig);
	}

	return ret;
}
#endif

int
ssh_ecdsa_verify(const struct sshkey *key,
    const u_char *signature, size_t signaturelen,
    const u_char *data, size_t datalen, u_int compat)
{
	ECDSA_SIG *sig = NULL;
	int hash_alg;
	size_t dlen;
	int ret = SSH_ERR_INTERNAL_ERROR;
	struct sshbuf *b = NULL, *sigbuf = NULL;
	char *ktype = NULL;

	UNUSED(compat);
	if (key == NULL || key->ecdsa == NULL ||
	    sshkey_type_plain(key->type) != KEY_ECDSA ||
	    signature == NULL || signaturelen == 0)
		return SSH_ERR_INVALID_ARGUMENT;

	if ((hash_alg = sshkey_ec_nid_to_hash_alg(key->ecdsa_nid)) == -1 ||
	    (dlen = ssh_digest_bytes(hash_alg)) == 0)
		return SSH_ERR_INTERNAL_ERROR;

	/* fetch signature */
	if ((b = sshbuf_from(signature, signaturelen)) == NULL)
		return SSH_ERR_ALLOC_FAIL;
	if (sshbuf_get_cstring(b, &ktype, NULL) != 0 ||
	    sshbuf_froms(b, &sigbuf) != 0) {
		ret = SSH_ERR_INVALID_FORMAT;
		goto out;
	}
	if (strcmp(sshkey_ssh_name_plain(key), ktype) != 0) {
		ret = SSH_ERR_KEY_TYPE_MISMATCH;
		goto out;
	}
	if (sshbuf_len(b) != 0) {
		ret = SSH_ERR_UNEXPECTED_TRAILING_DATA;
		goto out;
	}

{	/* parse signature */
	BIGNUM *pr = NULL, *ps = NULL;

	ret = 0;

	if (sshbuf_get_bignum2(sigbuf, &pr) != 0 ||
	    sshbuf_get_bignum2(sigbuf, &ps) != 0) {
		ret = SSH_ERR_INVALID_FORMAT;
		goto parse_out;
	}

	if ((sig = ECDSA_SIG_new()) == NULL) {
		ret = SSH_ERR_ALLOC_FAIL;
		goto parse_out;
	}

	if (!ECDSA_SIG_set0(sig, pr, ps))
		ret = SSH_ERR_LIBCRYPTO_ERROR;

parse_out:
	if (ret != 0) {
		BN_free(pr);
		BN_free(ps);
		goto out;
	}
}

	if (sshbuf_len(sigbuf) != 0) {
		ret = SSH_ERR_UNEXPECTED_TRAILING_DATA;
		goto out;
	}
#ifndef USE_EC_PKEY_VERIFY
{
	u_char digest[SSH_DIGEST_MAX_LENGTH];

	if ((ret = ssh_digest_memory(hash_alg, data, datalen,
	    digest, sizeof(digest))) != 0)
		goto out;

	switch (ECDSA_do_verify(digest, dlen, sig, key->ecdsa)) {
	case 1:
		ret = 0;
		break;
	case 0:
		ret = SSH_ERR_SIGNATURE_INVALID;
		break;
	default:
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		break;
	}
	explicit_bzero(digest, sizeof(digest));
}
#else
{
	const EVP_MD *md;

	switch (hash_alg) {
	case SSH_DIGEST_SHA256: md = ssh_ecdsa_EVP_sha256(); break;
	case SSH_DIGEST_SHA384: md = ssh_ecdsa_EVP_sha384(); break;
	case SSH_DIGEST_SHA512: md = ssh_ecdsa_EVP_sha512(); break;
	default: {
		ret = SSH_ERR_INTERNAL_ERROR;
		goto out;
		}
	}
	ret = ssh_ecdsa_pkey_verify(key->ecdsa, md, sig, data, datalen);
}
#endif

 out:
	sshbuf_free(sigbuf);
	sshbuf_free(b);
	ECDSA_SIG_free(sig);
	free(ktype);
	return ret;
}

#else

typedef int ssh_ecdsa_empty_translation_unit;

#endif /* WITH_OPENSSL && OPENSSL_HAS_ECC */
