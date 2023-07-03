/* $OpenBSD: ssh-ecdsa.c,v 1.25 2022/10/28 00:44:44 djm Exp $ */
/*
 * Copyright (c) 2000 Markus Friedl.  All rights reserved.
 * Copyright (c) 2010 Damien Miller.  All rights reserved.
 * Copyright (c) 2020-2023 Roumen Petrov.  All rights reserved.
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

#define SSHKEY_INTERNAL
#include "includes.h"

#if defined(WITH_OPENSSL) && defined(OPENSSL_HAS_ECC)

#include <sys/types.h>

#include "evp-compat.h"
#include <openssl/bn.h>

#include <string.h>

#include "sshxkey.h"
#include "sshbuf.h"
#include "ssherr.h"
#include "log.h"
#include "xmalloc.h"


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
#endif /*def OPENSSL_HAS_ECC*/
#endif /*ndef HAVE_EC_POINT_GET_AFFINE_COORDINATES*/


#ifndef HAVE_EC_GROUP_GET_FIELD_TYPE		/* OpenSSL < 3.0.0 */
static inline int
EC_GROUP_get_field_type(const EC_GROUP *group) {
	return EC_METHOD_get_field_type(EC_GROUP_method_of(group));
}
#endif /*ndef HAVE_EC_GROUP_GET_FIELD_TYPE*/


#ifdef DEBUG_KEXECDH
static void
dump_ec_point(const EC_GROUP *g, const EC_POINT *p)
{
	BIGNUM *x, *y = NULL;

	if (p == NULL) {
		fputs("point=(NULL)\n", stderr);
		return;
	}
	if (EC_GROUP_get_field_type(g) != NID_X9_62_prime_field) {
		fprintf(stderr, "%s: group is not a prime field\n", __func__);
		return;
	}

	x = BN_new();
	y = BN_new();
	if (x == NULL || y == NULL) {
		fprintf(stderr, "%s: BN_new failed\n", __func__);
		goto err;
	}
	if (EC_POINT_get_affine_coordinates(g, p, x, y, NULL) != 1) {
		fprintf(stderr, "%s: EC_POINT_get_affine_coordinates\n", __func__);
		goto err;
	}

	fputs("x=", stderr);
	BN_print_fp(stderr, x);
	fputs("\n", stderr);

	fputs("y=", stderr);
	BN_print_fp(stderr, y);
	fputs("\n", stderr);

err:
	BN_clear_free(x);
	BN_clear_free(y);
}
#endif


static const ssh_evp_md*
ssh_ecdsa_dgst(const struct sshkey *key)
{
	int id;

	switch (key->ecdsa_nid) {
	case NID_X9_62_prime256v1: id = SSH_MD_EC_SHA256_SSH; break;
	case NID_secp384r1:	   id = SSH_MD_EC_SHA384_SSH; break;
#ifdef OPENSSL_HAS_NISTP521
	case NID_secp521r1:	   id = SSH_MD_EC_SHA512_SSH; break;
#endif /* OPENSSL_HAS_NISTP521 */
	default:
		return NULL;
	}
	return ssh_evp_md_find(id);
}


#ifdef WITH_OPENSSL_4_0_API
/* TODO: new methods compatible with OpenSSL 4.0 API.
 * Remark: OpenSSL 3* is too buggy - almost each release fail
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


int
sshkey_ec_validate_public(const EC_GROUP *group, const EC_POINT *public)
{
	EC_POINT *nq = NULL;
	BIGNUM *order = NULL, *x = NULL, *y = NULL, *tmp = NULL;
	int ret = SSH_ERR_KEY_INVALID_EC_VALUE;

	/*
	 * NB. This assumes OpenSSL has already verified that the public
	 * point lies on the curve. This is done by EC_POINT_oct2point()
	 * implicitly calling EC_POINT_is_on_curve(). If this code is ever
	 * reachable with public points not unmarshalled using
	 * EC_POINT_oct2point then the caller will need to explicitly check.
	 */
#ifdef DEBUG_KEXECDH
	fputs("public key:\n", stderr);
	dump_ec_point(group, public);
#endif

	/*
	 * We shouldn't ever hit this case because bignum_get_ecpoint()
	 * refuses to load GF2m points.
	 */
	if (EC_GROUP_get_field_type(group) !=
	    NID_X9_62_prime_field)
		goto out;

	/* Q != infinity */
	if (EC_POINT_is_at_infinity(group, public))
		goto out;

	if ((x = BN_new()) == NULL ||
	    (y = BN_new()) == NULL ||
	    (order = BN_new()) == NULL ||
	    (tmp = BN_new()) == NULL) {
		ret = SSH_ERR_ALLOC_FAIL;
		goto out;
	}

	/* log2(x) > log2(order)/2, log2(y) > log2(order)/2 */
	if (EC_GROUP_get_order(group, order, NULL) != 1 ||
	    EC_POINT_get_affine_coordinates(group, public,
	    x, y, NULL) != 1) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		goto out;
	}
	if (BN_num_bits(x) <= BN_num_bits(order) / 2 ||
	    BN_num_bits(y) <= BN_num_bits(order) / 2)
		goto out;

	/* nQ == infinity (n == order of subgroup) */
	if ((nq = EC_POINT_new(group)) == NULL) {
		ret = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	if (EC_POINT_mul(group, nq, NULL, public, order, NULL) != 1) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		goto out;
	}
	if (EC_POINT_is_at_infinity(group, nq) != 1)
		goto out;

	/* x < order - 1, y < order - 1 */
	if (!BN_sub(tmp, order, BN_value_one())) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		goto out;
	}
	if (BN_cmp(x, tmp) >= 0 || BN_cmp(y, tmp) >= 0)
		goto out;
	ret = 0;
 out:
	BN_clear_free(x);
	BN_clear_free(y);
	BN_clear_free(order);
	BN_clear_free(tmp);
	EC_POINT_free(nq);
	return ret;
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


extern int /* see sshkey-crypto.c */
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
sshbuf_write_pub_ecdsa(struct sshbuf *buf, const struct sshkey *key) {
	int r;
	EC_KEY *ec;

	if (key->pk == NULL)
		return SSH_ERR_INVALID_ARGUMENT;

	ec = EVP_PKEY_get1_EC_KEY(key->pk);
	if (ec == NULL)
		return SSH_ERR_INVALID_ARGUMENT;

	r = sshbuf_put_eckey(buf, ec);

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
ssh_ecdsa_serialize_public(const struct sshkey *key, struct sshbuf *buf,
    enum sshkey_serialize_rep opts)
{
	int r;

	UNUSED(opts);
	if ((r = sshbuf_write_ec_curve(buf, key)) != 0)
		return r;
	return sshbuf_write_pub_ecdsa(buf, key);
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

static int
ssh_ecdsa_sign(const ssh_sign_ctx *ctx, u_char **sigp, size_t *lenp,
    const u_char *data, size_t datalen)
{
	const struct sshkey *key = ctx->key;
	const ssh_evp_md *dgst;
	u_char sigblob[20+2*64/*SHA512_DIGEST_LENGTH*/];
	size_t siglen = sizeof(sigblob);
	int ret;

	if (lenp != NULL)
		*lenp = 0;
	if (sigp != NULL)
		*sigp = NULL;

	dgst = ssh_ecdsa_dgst(key);
	if (dgst == NULL) return SSH_ERR_INTERNAL_ERROR;

	ret = sshkey_validate_public_ecdsa(key);
	if (ret != 0) return ret;

	if (ssh_pkey_sign(dgst, key->pk, sigblob, &siglen, data, datalen) <= 0) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		goto out;
	}

	ret = ssh_encode_signature(sigp, lenp,
	    sshkey_ssh_name_plain(key), sigblob, siglen);

 out:
	return ret;
}

static int
ssh_ecdsa_verify(const ssh_verify_ctx *ctx,
    const u_char *sig, size_t siglen,
    const u_char *data, size_t datalen)
{
	const struct sshkey *key = ctx->key;
	const ssh_evp_md *dgst;
	struct sshbuf *b = NULL, *sigbuf = NULL;
	char *ktype = NULL;
	int ret;

	if (sig == NULL || siglen == 0)
		return SSH_ERR_INVALID_ARGUMENT;

	dgst = ssh_ecdsa_dgst(key);
	if (dgst == NULL) return SSH_ERR_INTERNAL_ERROR;

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

{	size_t len = sshbuf_len(sigbuf);
	if (ssh_pkey_verify(dgst, key->pk,
		sshbuf_ptr(sigbuf), len, data, datalen) <= 0)
		ret = SSH_ERR_SIGNATURE_INVALID;
}

 out:
	sshbuf_free(sigbuf);
	sshbuf_free(b);
	free(ktype);
	return ret;
}

static const struct sshkey_impl_funcs sshkey_ecdsa_funcs = {
	/* .size = */		ssh_ecdsa_size,
	/* .alloc =		NULL, */
	/* .cleanup = */	ssh_ecdsa_cleanup,
	/* .equal = */		ssh_ecdsa_equal,
	/* .serialize_public = */	ssh_ecdsa_serialize_public,
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
