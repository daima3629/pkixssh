/* $OpenBSD: ssh-ecdsa.c,v 1.16 2019/01/21 09:54:11 djm Exp $ */
/*
 * Copyright (c) 2000 Markus Friedl.  All rights reserved.
 * Copyright (c) 2010 Damien Miller.  All rights reserved.
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

#if defined(WITH_OPENSSL) && defined(OPENSSL_HAS_ECC)

#include <sys/types.h>

#include "evp-compat.h"
#include <openssl/bn.h>

#include <string.h>

#include "sshkey.h"
#include "sshbuf.h"
#include "ssherr.h"
#include "log.h"
#include "xmalloc.h"


static const EVP_MD*
ssh_ecdsa_evp_md(const struct sshkey *key)
{
	switch (key->ecdsa_nid) {
	case NID_X9_62_prime256v1: return ssh_ecdsa_EVP_sha256();
	case NID_secp384r1:	   return ssh_ecdsa_EVP_sha384();
#ifdef OPENSSL_HAS_NISTP521
	case NID_secp521r1:	   return ssh_ecdsa_EVP_sha512();
#endif /* OPENSSL_HAS_NISTP521 */
	}
	return NULL;
}

/* caller must free result */
static int
ssh_ecdsa_sign_pkey(const struct sshkey *key,
    ECDSA_SIG **sigp, const u_char *data, u_int datalen
) {
	ECDSA_SIG *sig = NULL;
	const EVP_MD *type;
	u_char *tsig = NULL;
	u_int slen, len;
	int ret;

	type = ssh_ecdsa_evp_md(key);
	if (type == NULL) return SSH_ERR_INTERNAL_ERROR;

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

	ret = EVP_SignInit_ex(md, type, NULL);
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
		sig = d2i_ECDSA_SIG(NULL, &psig, (long)len);
	}

	if (tsig != NULL) {
		/* clean up */
		memset(tsig, 'd', slen);
		free(tsig);
	}

	if (sig == NULL)
		return SSH_ERR_LIBCRYPTO_ERROR;

	*sigp = sig;
	return 0;
}

int
ssh_ecdsa_sign(const struct sshkey *key, u_char **sigp, size_t *lenp,
    const u_char *data, size_t datalen, u_int compat)
{
	ECDSA_SIG *sig = NULL;
	size_t len;
	struct sshbuf *b = NULL, *bb = NULL;
	int ret;

	UNUSED(compat);
	if (lenp != NULL)
		*lenp = 0;
	if (sigp != NULL)
		*sigp = NULL;

	ret = sshkey_validate_public_ecdsa(key);
	if (ret != 0) return ret;

	ret = ssh_ecdsa_sign_pkey(key, &sig, data, datalen);
	if (ret != 0) goto out;

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

static int
ssh_ecdsa_verify_pkey(const struct sshkey *key,
    ECDSA_SIG *sig, const u_char *data, u_int datalen)
{
	int ret;
	u_char *tsig = NULL;
	u_int len;
	const EVP_MD *type;

	type = ssh_ecdsa_evp_md(key);
	if (type == NULL) return SSH_ERR_INTERNAL_ERROR;

	/* Sig is in ECDSA_SIG structure, convert to encoded buffer */
	len = i2d_ECDSA_SIG(sig, NULL);
	tsig = xmalloc(len);	/*fatal on error*/

	{ /* encode a DSA signature */
		u_char *psig = tsig;
		i2d_ECDSA_SIG(sig, &psig);
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

	ok = EVP_VerifyInit(md, type);
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
ssh_ecdsa_verify(const struct sshkey *key,
    const u_char *signature, size_t signaturelen,
    const u_char *data, size_t datalen, u_int compat)
{
	ECDSA_SIG *sig = NULL;
	struct sshbuf *b = NULL, *sigbuf = NULL;
	char *ktype = NULL;
	int ret;

	UNUSED(compat);
	if (signature == NULL || signaturelen == 0)
		return SSH_ERR_INVALID_ARGUMENT;

	ret = sshkey_validate_public_ecdsa(key);
	if (ret != 0) return ret;

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
	ret = ssh_ecdsa_verify_pkey(key, sig, data, datalen);

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
