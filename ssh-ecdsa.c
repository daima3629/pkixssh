/* $OpenBSD: ssh-ecdsa.c,v 1.16 2019/01/21 09:54:11 djm Exp $ */
/*
 * Copyright (c) 2000 Markus Friedl.  All rights reserved.
 * Copyright (c) 2010 Damien Miller.  All rights reserved.
 * Copyright (c) 2020-2022 Roumen Petrov.  All rights reserved.
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


#ifdef WITH_OPENSSL_3_1_API
/* TODO: new methods compatible with OpenSSL 3.1 API.
 * Remark: OpenSSL 3.0* is too buggy - almost each release fail
 * or crash in regression tests.
 */
#else
/* management of elementary EC key */

static inline EC_KEY*
ssh_EC_KEY_new_by_curve_name(int nid) {
	EC_KEY *ec;

	ec = EC_KEY_new_by_curve_name(nid);
	if (ec == NULL) return NULL;

#if defined(OPENSSL_VERSION_NUMBER) && (OPENSSL_VERSION_NUMBER < 0x10100000L) || \
    defined(LIBRESSL_VERSION_NUMBER)
	/* Note since 1.1.0 OpenSSL uses named curve parameter encoding by default.
	 * It seems to me default is changed in upcomming 3.0 but key is marked
	 * properly when created by nid.
	 */
	EC_KEY_set_asn1_flag(ec, OPENSSL_EC_NAMED_CURVE);
#endif
	return ec;
}

static int
sshkey_init_ecdsa_curve(struct sshkey *key, int nid) {
	int r;
	EVP_PKEY *pk;
	EC_KEY *ec;

	pk = EVP_PKEY_new();
	if (pk == NULL)
		return SSH_ERR_ALLOC_FAIL;

	ec = ssh_EC_KEY_new_by_curve_name(nid);
	if (ec == NULL) {
		r = SSH_ERR_ALLOC_FAIL;
		goto err;
	}

	if (!EVP_PKEY_set1_EC_KEY(pk, ec)) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		goto err;
	}

	/* success */
	key->pk = pk;
	pk = NULL;
	key->ecdsa_nid = nid;
	r = 0;

err:
	EC_KEY_free(ec);
	EVP_PKEY_free(pk);
	return r;
}

static int
sshbuf_read_ec_curve(struct sshbuf *buf, const char *pkalg, struct sshkey *key) {
	int r, nid;

	nid = sshkey_ecdsa_nid_from_name(pkalg);
	debug3_f("pkalg/nid: %s/%d", pkalg, nid);
	if (nid == -1)
		return SSH_ERR_INVALID_ARGUMENT;

{	char *curve;

	r = sshbuf_get_cstring(buf, &curve, NULL);
	if (r != 0) return r;

	if (nid != sshkey_curve_name_to_nid(curve))
		r = SSH_ERR_EC_CURVE_MISMATCH;

	free(curve);
}
	if (r == 0)
		key->ecdsa_nid = nid;
	return r;
}

static inline int
sshbuf_write_ec_curve(struct sshbuf *buf, const struct sshkey *key) {
	const char *curve_name = sshkey_curve_nid_to_name(key->ecdsa_nid);
	return sshbuf_put_cstring(buf, curve_name);
}


static int
sshkey_validate_ec_pub(const EC_KEY *ec) {
	int r;

	r = sshkey_ec_validate_public(EC_KEY_get0_group(ec),
	    EC_KEY_get0_public_key(ec));
	if (r != 0) return r;

	/* other checks ? */
	return 0;
}

int
sshkey_validate_public_ecdsa(const struct sshkey *key) {
	int r;

	if (key == NULL) return SSH_ERR_INVALID_ARGUMENT;

{	EC_KEY *ec = EVP_PKEY_get1_EC_KEY(key->pk);
	if (ec == NULL)
		return SSH_ERR_INVALID_ARGUMENT;
	r = sshkey_validate_ec_pub(ec);
	EC_KEY_free(ec);
}
	return r;
}


extern int /*TODO static - see sshkey-crypto.c */
ssh_EVP_PKEY_complete_pub_ecdsa(EVP_PKEY *pk);

int
ssh_EVP_PKEY_complete_pub_ecdsa(EVP_PKEY *pk) {
	int r, nid;
	EC_KEY *ec;

	ec = EVP_PKEY_get1_EC_KEY(pk);
	if (ec == NULL)
		return SSH_ERR_INVALID_ARGUMENT;

	nid = ssh_EC_KEY_preserve_nid(ec);
	if (nid < 0) {
		error_f("unsupported elliptic curve");
		r = SSH_ERR_EC_CURVE_INVALID;
		goto err;
	}

	r = sshkey_validate_ec_pub(ec);

err:
	EC_KEY_free(ec);
	return r;
}


extern int /* TODO static - see sshkey-crypto.c */
sshkey_validate_ec_priv(const EC_KEY *ec);


static int
sshbuf_read_pub_ecdsa(struct sshbuf *buf, struct sshkey *key) {
	int r;
	EC_KEY *ec;

	r = sshkey_init_ecdsa_curve(key, key->ecdsa_nid);
	if (r != 0) return r;

	ec = EVP_PKEY_get1_EC_KEY(key->pk);
	if (ec == NULL)
		return SSH_ERR_LIBCRYPTO_ERROR;

	r = sshbuf_get_eckey(buf, ec);
	if (r != 0) goto err;

	r = sshkey_validate_ec_pub(ec);
	if (r != 0) goto err;

	/* success */
	SSHKEY_DUMP(key);

err:
	EC_KEY_free(ec);
	return r;
}


static int
sshbuf_read_priv_ecdsa(struct sshbuf *buf, struct sshkey *key) {
	int r;
	EC_KEY *ec = NULL;
	BIGNUM *exponent = NULL;

	if ((r = sshbuf_get_bignum2(buf, &exponent)) != 0)
		goto err;

	ec = EVP_PKEY_get1_EC_KEY(key->pk);
	if (ec == NULL) {
		r = SSH_ERR_INVALID_ARGUMENT;
		goto err;
	}

	if (EC_KEY_set_private_key(ec, exponent) != 1) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		goto err;
	}
	/*no! exponent = NULL; transferred */

	r = sshkey_validate_ec_priv(ec);
	if (r != 0) goto err;

	SSHKEY_DUMP(key);

err:
	BN_clear_free(exponent);
	EC_KEY_free(ec);
	return r;
}

static int
sshbuf_write_priv_ecdsa(struct sshbuf *buf, const struct sshkey *key) {
	const BIGNUM *exponent = NULL;

{	EC_KEY *ec = EVP_PKEY_get1_EC_KEY(key->pk);
	if (ec == NULL)
		return SSH_ERR_INVALID_ARGUMENT;
	exponent = EC_KEY_get0_private_key(ec);
	EC_KEY_free(ec);
}
	return sshbuf_put_bignum2(buf, exponent);
}
#endif /* def WITH_OPENSSL_3_1_API */


/* key implementation */

static u_int
ssh_ecdsa_size(const struct sshkey *key)
{
	return (key->pk != NULL) ? EVP_PKEY_bits(key->pk) : 0;
}

static void
ssh_ecdsa_cleanup(struct sshkey *k)
{
	sshkey_clear_pkey(k);
}

static int
ssh_ecdsa_equal(const struct sshkey *a, const struct sshkey *b)
{
	return sshkey_equal_public_pkey(a, b);
}

static int
ssh_ecdsa_serialize_private(const struct sshkey *key, struct sshbuf *buf,
    enum sshkey_serialize_rep opts)
{
	int r;

	UNUSED(opts);
	if (!sshkey_is_cert(key)) {
		if ((r = sshbuf_write_ec_curve(buf, key)) != 0 ||
		    (r = sshbuf_write_pub_ecdsa(buf, key)) != 0)
			return r;
	}
	return sshbuf_write_priv_ecdsa(buf, key);
}

static int
ssh_ecdsa_generate(struct sshkey *key, int bits) {
	EVP_PKEY *pk;
	EC_KEY *private = NULL;
	int r = 0, nid;

	nid = sshkey_ecdsa_bits_to_nid(bits);
	if (nid == -1) return SSH_ERR_KEY_LENGTH;

	if ((pk = EVP_PKEY_new()) == NULL ||
	    (private = ssh_EC_KEY_new_by_curve_name(nid)) == NULL
	) {
		r = SSH_ERR_ALLOC_FAIL;
		goto err;
	}

	if (EC_KEY_generate_key(private) != 1) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		goto err;
	}

	if (!EVP_PKEY_set1_EC_KEY(pk, private)) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		goto err;
	}

	key->pk = pk;
	pk = NULL;
	key->ecdsa_nid = nid;

err:
	EVP_PKEY_free(pk);
	EC_KEY_free(private);
	return r;
}

static void
ssh_ecdsa_move_public(struct sshkey *from, struct sshkey *to) {
	sshkey_move_pk(from, to);
	to->ecdsa_nid = from->ecdsa_nid;
	from->ecdsa_nid = -1;
}

extern int sshkey_copy_pub_ecdsa(const struct sshkey *from, struct sshkey *to);

static int
ssh_ecdsa_copy_public(const struct sshkey *from, struct sshkey *to) {
	int r;
	EC_KEY *ec, *from_ec = NULL;

	r = sshkey_init_ecdsa_curve(to, from->ecdsa_nid);
	if (r != 0) return r;

	ec = EVP_PKEY_get1_EC_KEY(to->pk);
	if (ec == NULL) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		goto err;
	}

	from_ec = EVP_PKEY_get1_EC_KEY(from->pk);
	if (from_ec == NULL) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		goto err;
	}

	if (EC_KEY_set_public_key(ec, EC_KEY_get0_public_key(from_ec)) != 1)
		r = SSH_ERR_LIBCRYPTO_ERROR;

err:
	EC_KEY_free(from_ec);
	EC_KEY_free(ec);
	return r;
}

static int
ssh_ecdsa_deserialize_public(const char *pkalg, struct sshbuf *buf,
    struct sshkey *key)
{
	int r;

	if ((r = sshbuf_read_ec_curve(buf, pkalg, key)) != 0)
		return r;
	return sshbuf_read_pub_ecdsa(buf, key);
}

static int
ssh_ecdsa_deserialize_private(const char *pkalg, struct sshbuf *buf,
    struct sshkey *key)
{
	int r;

	if (!sshkey_is_cert(key)) {
		if ((r = sshbuf_read_ec_curve(buf, pkalg, key)) != 0 ||
		    (r = sshbuf_read_pub_ecdsa(buf, key)) != 0)
			return r;
	}
	return sshbuf_read_priv_ecdsa(buf, key);
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

static int
ssh_ecdsa_sign(const ssh_sign_ctx *ctx, u_char **sigp, size_t *lenp,
    const u_char *data, size_t datalen)
{
	const struct sshkey *key = ctx->key;
	ECDSA_SIG *sig = NULL;
	size_t len;
	struct sshbuf *b = NULL, *bb = NULL;
	int ret;

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

static int
ssh_ecdsa_verify(const ssh_verify_ctx *ctx,
    const u_char *sig, size_t siglen,
    const u_char *data, size_t dlen)
{
	const struct sshkey *key = ctx->key;
	ECDSA_SIG *esig = NULL;
	struct sshbuf *b = NULL, *sigbuf = NULL;
	char *ktype = NULL;
	int ret;

	if (sig == NULL || siglen == 0)
		return SSH_ERR_INVALID_ARGUMENT;

	ret = sshkey_validate_public_ecdsa(key);
	if (ret != 0) return ret;

	/* fetch signature */
	if ((b = sshbuf_from(sig, siglen)) == NULL)
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

	if ((esig = ECDSA_SIG_new()) == NULL) {
		ret = SSH_ERR_ALLOC_FAIL;
		goto parse_out;
	}

	if (!ECDSA_SIG_set0(esig, pr, ps))
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
	ret = ssh_ecdsa_verify_pkey(key, esig, data, dlen);

 out:
	sshbuf_free(sigbuf);
	sshbuf_free(b);
	ECDSA_SIG_free(esig);
	free(ktype);
	return ret;
}

static const struct sshkey_impl_funcs sshkey_ecdsa_funcs = {
	/* .size = */		ssh_ecdsa_size,
	/* .alloc =		NULL, */
	/* .cleanup = */	ssh_ecdsa_cleanup,
	/* .equal = */		ssh_ecdsa_equal,
	/* .deserialize_public = */	ssh_ecdsa_deserialize_public,
	/* .serialize_private = */	ssh_ecdsa_serialize_private,
	/* .deserialize_private = */	ssh_ecdsa_deserialize_private,
	/* .generate = */	ssh_ecdsa_generate,
	/* .move_public = */	ssh_ecdsa_move_public,
	/* .copy_public = */	ssh_ecdsa_copy_public,
	/* .sign = */		ssh_ecdsa_sign,
	/* .verify = */		ssh_ecdsa_verify
};

const struct sshkey_impl sshkey_ecdsa_nistp256_impl = {
	/* .name = */		"ecdsa-sha2-nistp256",
	/* .shortname = */	"ECDSA",
	/* .sigalg = */		NULL,
	/* .type = */		KEY_ECDSA,
	/* .nid = */		NID_X9_62_prime256v1,
	/* .cert = */		0,
	/* .sigonly = */	0,
	/* .keybits = */	0,
	/* .funcs = */		&sshkey_ecdsa_funcs
};

const struct sshkey_impl sshkey_ecdsa_nistp256_cert_impl = {
	/* .name = */		"ecdsa-sha2-nistp256-cert-v01@openssh.com",
	/* .shortname = */	"ECDSA-CERT",
	/* .sigalg = */		NULL,
	/* .type = */		KEY_ECDSA_CERT,
	/* .nid = */		NID_X9_62_prime256v1,
	/* .cert = */		1,
	/* .sigonly = */	0,
	/* .keybits = */	0,
	/* .funcs = */		&sshkey_ecdsa_funcs
};

const struct sshkey_impl sshkey_ecdsa_nistp384_impl = {
	/* .name = */		"ecdsa-sha2-nistp384",
	/* .shortname = */	"ECDSA",
	/* .sigalg = */		NULL,
	/* .type = */		KEY_ECDSA,
	/* .nid = */		NID_secp384r1,
	/* .cert = */		0,
	/* .sigonly = */	0,
	/* .keybits = */	0,
	/* .funcs = */		&sshkey_ecdsa_funcs
};

const struct sshkey_impl sshkey_ecdsa_nistp384_cert_impl = {
	/* .name = */		"ecdsa-sha2-nistp384-cert-v01@openssh.com",
	/* .shortname = */	"ECDSA-CERT",
	/* .sigalg = */		NULL,
	/* .type = */		KEY_ECDSA_CERT,
	/* .nid = */		NID_secp384r1,
	/* .cert = */		1,
	/* .sigonly = */	0,
	/* .keybits = */	0,
	/* .funcs = */		&sshkey_ecdsa_funcs
};

#ifdef OPENSSL_HAS_NISTP521
const struct sshkey_impl sshkey_ecdsa_nistp521_impl = {
	/* .name = */		"ecdsa-sha2-nistp521",
	/* .shortname = */	"ECDSA",
	/* .sigalg = */		NULL,
	/* .type = */		KEY_ECDSA,
	/* .nid = */		NID_secp521r1,
	/* .cert = */		0,
	/* .sigonly = */	0,
	/* .keybits = */	0,
	/* .funcs = */		&sshkey_ecdsa_funcs
};

const struct sshkey_impl sshkey_ecdsa_nistp521_cert_impl = {
	/* .name = */		"ecdsa-sha2-nistp521-cert-v01@openssh.com",
	/* .shortname = */	"ECDSA-CERT",
	/* .sigalg = */		NULL,
	/* .type = */		KEY_ECDSA_CERT,
	/* .nid = */		NID_secp521r1,
	/* .cert = */		1,
	/* .sigonly = */	0,
	/* .keybits = */	0,
	/* .funcs = */		&sshkey_ecdsa_funcs
};
#endif /* OPENSSL_HAS_NISTP521 */
#else

typedef int ssh_ecdsa_empty_translation_unit;

#endif /* WITH_OPENSSL && OPENSSL_HAS_ECC */
