/* $OpenBSD: ssh-rsa.c,v 1.67 2018/07/03 11:39:54 djm Exp $ */
/*
 * Copyright (c) 2000, 2003 Markus Friedl <markus@openbsd.org>
 * Copyright (c) 2011 Dr. Stephen Henson.  All rights reserved.
 * Copyright (c) 2011-2021 Roumen Petrov.  All rights reserved.
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

#include "evp-compat.h"
#include "sshbuf.h"
#include "compat.h"
#include "ssherr.h"
#define SSHKEY_INTERNAL
#include "sshkey.h"
#include "digest.h"
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

/*
 * Returns the hash algorithm ID for a given algorithm identifier as used
 * inside the signature blob,
 */
static int
rsa_hash_id_from_ident(const char *ident)
{
	if (strcmp(ident, "ssh-rsa") == 0)
		return SSH_DIGEST_SHA1;
#ifdef HAVE_EVP_SHA256
	if (strcmp(ident, "rsa-sha2-256") == 0)
		return SSH_DIGEST_SHA256;
	if (strcmp(ident, "rsa-sha2-512") == 0)
		return SSH_DIGEST_SHA512;
#endif /*def HAVE_EVP_SHA256*/
	return -1;
}

/*
 * Return the hash algorithm ID for the specified key name. This includes
 * all the cases of rsa_hash_id_from_ident() but also the certificate key
 * types.
 */
static int
rsa_hash_id_from_keyname(const char *alg)
{
	int r;

	if ((r = rsa_hash_id_from_ident(alg)) != -1)
		return r;
	if (strcmp(alg, "ssh-rsa-cert-v01@openssh.com") == 0)
		return SSH_DIGEST_SHA1;
	if (strcmp(alg, "rsa-sha2-256-cert-v01@openssh.com") == 0)
		return SSH_DIGEST_SHA256;
	if (strcmp(alg, "rsa-sha2-512-cert-v01@openssh.com") == 0)
		return SSH_DIGEST_SHA512;
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

int
sshrsa_verify_length(int bits) {
	return bits < SSH_RSA_MINIMUM_MODULUS_SIZE
	    ? SSH_ERR_KEY_LENGTH : 0;
}

/* RSASSA-PKCS1-v1_5 (PKCS #1 v2.0 signature) with SHA1 */
int
ssh_rsa_sign(const struct sshkey *key, u_char **sigp, size_t *lenp,
    const u_char *data, size_t datalen, const char *alg_ident)
{
	u_char *sig = NULL;
	size_t slen = 0;
	u_int len;
	int nid, hash_alg, ret;
	struct sshbuf *b = NULL;

	if (lenp != NULL)
		*lenp = 0;
	if (sigp != NULL)
		*sigp = NULL;

	if (alg_ident == NULL || strlen(alg_ident) == 0)
		hash_alg = SSH_DIGEST_SHA1;
	else
		hash_alg = rsa_hash_id_from_keyname(alg_ident);
{	const char *s = rsa_hash_alg_ident(hash_alg);
	debug3_f("hash_alg=%d/%s", hash_alg, s != NULL ? s: "");
}
	if (hash_alg == -1)
		return SSH_ERR_INVALID_ARGUMENT;

	ret = sshkey_validate_public_rsa(key);
	if (ret != 0) return ret;

	/* hash the data */
	nid = rsa_hash_alg_nid(hash_alg);

{	/* EVP_Sign... */
	const EVP_MD *evp_md;
	int ok = -1;

	sig = NULL;

	if ((evp_md = EVP_get_digestbynid(nid)) == NULL) {
		error_f("EVP_get_digestbynid %d failed", nid);
		ret = SSH_ERR_INTERNAL_ERROR;
		goto out;
	}

	slen = EVP_PKEY_size(key->pk);
	debug3_f("slen=%ld", (long)slen);
	sig = xmalloc(slen);	/*fatal on error*/

{	EVP_MD_CTX *md = EVP_MD_CTX_new();
	if (md == NULL) {
		error_f("out of memory");
		ret = SSH_ERR_ALLOC_FAIL;
		goto evp_end;
	}

	ok = EVP_SignInit_ex(md, evp_md, NULL);
	if (ok <= 0) {
#ifdef TRACE_EVP_ERROR
		error_crypto("EVP_SignInit_ex");
#endif
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		goto evp_md_end;
	}

	ok = EVP_SignUpdate(md, data, datalen);
	if (ok <= 0) {
#ifdef TRACE_EVP_ERROR
		error_crypto("EVP_SignUpdate");
#endif
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		goto evp_md_end;
	}

	ok = EVP_SignFinal(md, sig, &len, key->pk);
	if (ok <= 0) {
#ifdef TRACE_EVP_ERROR
		error_crypto("EVP_SignFinal");
#endif
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		goto evp_md_end;
	}
	ret = SSH_ERR_SUCCESS;

evp_md_end:
	EVP_MD_CTX_free(md);
}
evp_end:

	if (ret != SSH_ERR_SUCCESS) goto out;
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
	int hash_alg, ret;
	size_t len = 0, diff, modlen;
	struct sshbuf *b = NULL;
	u_char *osigblob, *sigblob = NULL;

	if (sig == NULL || siglen == 0)
		return SSH_ERR_INVALID_ARGUMENT;

	ret = sshkey_validate_public_rsa(key);
	if (ret != 0) return ret;

	if ((b = sshbuf_from(sig, siglen)) == NULL)
		return SSH_ERR_ALLOC_FAIL;
	if (sshbuf_get_cstring(b, &sigtype, NULL) != 0) {
		ret = SSH_ERR_INVALID_FORMAT;
		goto out;
	}
	if ((hash_alg = rsa_hash_id_from_ident(sigtype)) == -1) {
		ret = SSH_ERR_KEY_TYPE_MISMATCH;
		goto out;
	}
	debug3_f("hash_alg=%d/%s", hash_alg, rsa_hash_alg_ident(hash_alg));
	/*
	 * For legacy reasons allow ssh-rsa-cert-v01 certs to accept SHA2 signatures
	 * but otherwise the signature algorithm should match.
	 */
	if (alg != NULL && strcmp(alg, "ssh-rsa-cert-v01@openssh.com") != 0) {
		int want_alg;
		if ((want_alg = rsa_hash_id_from_keyname(alg)) == -1) {
			ret = SSH_ERR_INVALID_ARGUMENT;
			goto out;
		}
		if (hash_alg != want_alg) {
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

{	/* EVP_Verify... */
	int nid;
	int ok;
	const EVP_MD *evp_md;

	nid = rsa_hash_alg_nid(hash_alg);
	if ((evp_md = EVP_get_digestbynid(nid)) == NULL) {
		error_f("EVP_get_digestbynid %d failed", nid);
		ret = SSH_ERR_INTERNAL_ERROR;
		goto out;
	}

	/* now verify signature */
	EVP_MD_CTX *md = EVP_MD_CTX_new();
	if (md == NULL) {
		ret = SSH_ERR_ALLOC_FAIL;
		goto out;
	}

	ok = EVP_VerifyInit(md, evp_md);
	if (ok <= 0) {
#ifdef TRACE_EVP_ERROR
		error_crypto("EVP_VerifyInit");
#endif
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		goto evp_md_end;
	}

	ok = EVP_VerifyUpdate(md, data, datalen);
	if (ok <= 0) {
#ifdef TRACE_EVP_ERROR
		error_crypto("EVP_VerifyUpdate");
#endif
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		goto evp_md_end;
	}

	ok = EVP_VerifyFinal(md, sigblob, len, key->pk);
	if (ok < 0) {
#ifdef TRACE_EVP_ERROR
		error_crypto("EVP_VerifyFinal");
#endif
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		goto evp_md_end;
	}
	ret = (ok == 0)
		? SSH_ERR_SIGNATURE_INVALID
		: SSH_ERR_SUCCESS;

evp_md_end:
	EVP_MD_CTX_free(md);
}

 out:
	freezero(sigblob, len);
	free(sigtype);
	sshbuf_free(b);
	return ret;
}

#endif /* WITH_OPENSSL */
