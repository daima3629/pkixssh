/* $OpenBSD: ssh-ecdsa.c,v 1.27 2024/08/15 00:51:51 djm Exp $ */
/*
 * Copyright (c) 2000 Markus Friedl.  All rights reserved.
 * Copyright (c) 2010 Damien Miller.  All rights reserved.
 * Copyright (c) 2020-2025 Roumen Petrov.  All rights reserved.
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
/* for i2d_PUBKEY used in key serialisation work-around */
#include <openssl/x509.h>
#ifdef HAVE_EVP_KEYMGMT_GET0_PROVIDER
#include <openssl/core_names.h>
#endif

#include <string.h>

#include "sshxkey.h"
#include "sshbuf.h"
#include "ssherr.h"
#include "log.h"
#include "xmalloc.h"


#ifndef HAVE_EC_POINT_GET_AFFINE_COORDINATES		/* OpenSSL < 1.1.1 */
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
#endif /*ndef HAVE_EC_POINT_GET_AFFINE_COORDINATES*/

#ifdef HAVE_EVP_KEYMGMT_GET0_PROVIDER
static size_t
ssh_EVP_PKEY_get1_encoded_public_key(EVP_PKEY *pkey, unsigned char **ppub) {
	size_t len;

	len = EVP_PKEY_get1_encoded_public_key(pkey, ppub);
	if (len > 0) return len;

	debug3_f("try a workaround ...");
/* NOTE: "pkcs11-provider" fail on call above.
 * Try a workaround - convert to key that uses default provider.
 */
{	int datalen;
	unsigned char *data = NULL;
	EVP_PKEY *p;

	datalen = i2d_PUBKEY(pkey, &data);
	if (datalen <= 0) return 0;

	{	const unsigned char *q = data;
		p = d2i_PUBKEY(NULL, &q, datalen);
	}
	if (p == NULL) goto err;

	len = EVP_PKEY_get1_encoded_public_key(p, ppub);

	EVP_PKEY_free(p);

err:
	OPENSSL_free(data);
}
	return len;
}
#endif /*def HAVE_EVP_KEYMGMT_GET0_PROVIDER*/


static int
nid_list[] = {
	NID_X9_62_prime256v1,
	NID_secp384r1,
#ifdef OPENSSL_HAS_NISTP521
	NID_secp521r1,
#endif /* OPENSSL_HAS_NISTP521 */
	-1
};

/* NOTE: keep synchronised with nid_list */
static int
dgst_list[] = {
	SSH_MD_EC_SHA256_SSH,
	SSH_MD_EC_SHA384_SSH,
	SSH_MD_EC_SHA512_SSH,
};

static int
ssh_ecdsa_nid_dgst(int ecdsa_nid) {
	int k;

	for (k = 0; nid_list[k] != -1; k++) {
		if (ecdsa_nid == nid_list[k])
			return dgst_list[k];
	}

	/* NOTE: return digest not applicable for ECDSA */
	return SSH_MD_NONE;
}

static inline const ssh_evp_md*
ssh_ecdsa_dgst(const struct sshkey *key) {
	int id = ssh_ecdsa_nid_dgst(key->ecdsa_nid);
	if (id == SSH_MD_NONE) return NULL;

	return ssh_evp_md_find(id);
}


#ifdef WITH_OPENSSL_4_0_API
/* TODO: new methods compatible with OpenSSL 4.0 API.
 * Remark: OpenSSL 3* is too buggy - almost each release fail
 * or crash in regression tests.
 */
#else
/* management of elementary EC key */

int
ssh_EC_KEY_preserve_nid(EC_KEY *ec)
{
	const EC_GROUP *g = EC_KEY_get0_group(ec);

	/*
	 * The group may be stored in a ASN.1 encoded private key in one of two
	 * ways: as a "named group", which is reconstituted by ASN.1 object ID
	 * or explicit group parameters encoded into the key blob. Only the
	 * "named group" case sets the group NID for us, but we can figure
	 * it out for the other case by comparing against all the groups that
	 * are supported.
	 */
{	int nid = EC_GROUP_get_curve_name(g);
	if (nid != NID_undef)
		return (ssh_ecdsa_nid_dgst(nid) != SSH_MD_NONE) ? nid : -1;
}
{	int k;
	for (k = 0; nid_list[k] != -1; k++) {
		EC_GROUP *eg = EC_GROUP_new_by_curve_name(nid_list[k]);
		if (eg == NULL) continue;

		if (EC_GROUP_cmp(g, eg, NULL) != 0) {
			EC_GROUP_free(eg);
			continue;
		}

		/* Use the group with the NID attached */
		EC_GROUP_set_asn1_flag(eg, OPENSSL_EC_NAMED_CURVE);
		if (EC_KEY_set_group(ec, eg) != 1) {
			EC_GROUP_free(eg);
			return -1;
		}
		EC_GROUP_free(eg);
		return nid_list[k];
	}
}
	return -1;
}

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
ssh_EC_GROUP_check_public(const EC_GROUP *group, const EC_POINT *public)
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

	/* other checks ? */

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
ssh_EC_GROUP_check_private(const EC_GROUP *group, const BIGNUM *exponent) {
	BIGNUM *order, *tmp = NULL;
	int ret;

	order = BN_new();
	if (order == NULL) return SSH_ERR_ALLOC_FAIL;

	if (EC_GROUP_get_order(group, order, NULL) != 1) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		goto err;
	}

	/* log2(private) > log2(order)/2 */
	if (BN_num_bits(exponent) <= BN_num_bits(order) / 2) {
		ret = SSH_ERR_KEY_INVALID_EC_VALUE;
		goto err;
	}

	tmp = BN_new();
	if (tmp == NULL) {
		ret = SSH_ERR_ALLOC_FAIL;
		goto err;
	}

	/* private < order - 1 */
	if (!BN_sub(tmp, order, BN_value_one())) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		goto err;
	}
	if (BN_cmp(exponent, tmp) >= 0) {
		ret = SSH_ERR_KEY_INVALID_EC_VALUE;
		goto err;
	}

	/* other checks ? */

	ret = 0;

err:
	BN_clear_free(order);
	BN_clear_free(tmp);
	return ret;
}


#ifdef HAVE_EVP_KEYMGMT_GET0_PROVIDER
static EC_GROUP*
ssh_EVP_PKEY_prov_get_EC_GROUP(EVP_PKEY *pkey) {
	char group_name[1024];
	int order;

	if (EVP_PKEY_get_utf8_string_param(pkey, OSSL_PKEY_PARAM_GROUP_NAME,
	    group_name, sizeof(group_name), NULL) != 1) {
		debug3_f("cannot get group parameter");
		return NULL;
	}

	order = OBJ_txt2nid(group_name);
	if (order == NID_undef) {
		error_f("unknown group '%s'", group_name);
		return NULL;
	}
	if (ssh_ecdsa_nid_dgst(order) == SSH_MD_NONE) {
		error_f("unsupported group '%s'", group_name);
		return NULL;
	}

	return EC_GROUP_new_by_curve_name(order);
}
#endif /*def HAVE_EVP_KEYMGMT_GET0_PROVIDER*/

#ifdef HAVE_EVP_KEYMGMT_GET0_PROVIDER
static int
ssh_EVP_PKEY_check_public_ecprov(EVP_PKEY *pkey, const EC_POINT *public) {
	EC_GROUP *group;
	int r;

	group = ssh_EVP_PKEY_prov_get_EC_GROUP(pkey);
	if (group == NULL) return SSH_ERR_ALLOC_FAIL;

	r = ssh_EC_GROUP_check_public(group, public);

	EC_GROUP_free(group);
	return r;
}
#endif /*def HAVE_EVP_KEYMGMT_GET0_PROVIDER*/

static inline int
ssh_EC_KEY_check_public(const EC_KEY *ec, const EC_POINT *public) {
	const EC_GROUP *group = EC_KEY_get0_group(ec);
	if (group == NULL) return SSH_ERR_INTERNAL_ERROR;

	return ssh_EC_GROUP_check_public(group, public);
}

int
ssh_EVP_PKEY_check_public_ec(EVP_PKEY *pk, const EC_POINT *public) {
	if (pk == NULL) return SSH_ERR_INVALID_ARGUMENT;
#ifdef HAVE_EVP_KEYMGMT_GET0_PROVIDER
	if (EVP_PKEY_get0_provider(pk) != NULL)
		return ssh_EVP_PKEY_check_public_ecprov(pk, public);
#endif
{	EC_KEY *ec;
	int r;

	ec = EVP_PKEY_get1_EC_KEY(pk);
	if (ec == NULL) return SSH_ERR_INVALID_ARGUMENT;

	r = ssh_EC_KEY_check_public(ec, public);

	EC_KEY_free(ec);
	return r;
}
}

#ifdef HAVE_EVP_KEYMGMT_GET0_PROVIDER
static int
ssh_EVP_PKEY_validate_public_ecprov(EVP_PKEY *pk) {
	EC_GROUP *group = NULL;
	EC_POINT *public = NULL;
	int r;

	group = ssh_EVP_PKEY_prov_get_EC_GROUP(pk);
	if (group == NULL)
		return SSH_ERR_ALLOC_FAIL;

	public = EC_POINT_new(group);
	if (public == NULL) {
		r = SSH_ERR_ALLOC_FAIL;
		goto err;
	}

{	unsigned char *data;
	size_t len;

	len = ssh_EVP_PKEY_get1_encoded_public_key(pk, &data);
	if (len == 0) {
		r = SSH_ERR_KEY_INVALID_EC_VALUE;
		goto err;
	}

	/* Only handle uncompressed points */
	if (*data != POINT_CONVERSION_UNCOMPRESSED) {
		r = SSH_ERR_INVALID_FORMAT;
		goto data_err;
	}

	if (EC_POINT_oct2point(group, public, data, len, NULL) != 1) {
		r = SSH_ERR_INVALID_FORMAT;
		goto data_err;
	}

	r = ssh_EVP_PKEY_check_public_ecprov(pk, public);

data_err:
	OPENSSL_free(data);
}

err:
	EC_GROUP_free(group);
	EC_POINT_free(public);
	return r;
}
#endif /*def HAVE_EVP_KEYMGMT_GET0_PROVIDER*/

static inline int
ssh_EC_KEY_validate_public(const EC_KEY *ec) {
	return ssh_EC_KEY_check_public(ec, EC_KEY_get0_public_key(ec));
}

int
ssh_pkey_validate_public_ecdsa(EVP_PKEY *pk) {
#ifdef HAVE_EVP_KEYMGMT_GET0_PROVIDER
	if (EVP_PKEY_get0_provider(pk) != NULL)
		return ssh_EVP_PKEY_validate_public_ecprov(pk);
#endif /*def HAVE_EVP_KEYMGMT_GET0_PROVIDER*/
{	EC_KEY *ec;
	int r;

	ec = EVP_PKEY_get1_EC_KEY(pk);
	if (ec == NULL) return SSH_ERR_INVALID_ARGUMENT;

	r = ssh_EC_KEY_validate_public(ec);

	EC_KEY_free(ec);
	return r;
}
}


#ifdef HAVE_EVP_KEYMGMT_GET0_PROVIDER
static int
ssh_EVP_PKEY_complete_pub_ecprov(EVP_PKEY *pk) {
	char encoding[1024];

	if (EVP_PKEY_get_utf8_string_param(pk, OSSL_PKEY_PARAM_EC_ENCODING,
	    encoding, sizeof(encoding), NULL) != 1) {
		unsigned char *data;
		size_t len;

		len = ssh_EVP_PKEY_get1_encoded_public_key(pk, &data);
		if (len == 0)
			return SSH_ERR_KEY_INVALID_EC_VALUE;

		/* Only handle uncompressed points */
		if (*data != POINT_CONVERSION_UNCOMPRESSED) {
			OPENSSL_free(data);
			return SSH_ERR_EC_CURVE_INVALID;
		}
		OPENSSL_free(data);
	} else {
		if (strcmp(encoding, OSSL_PKEY_EC_ENCODING_GROUP) != 0)
			return SSH_ERR_EC_CURVE_INVALID;
	}

	return ssh_EVP_PKEY_validate_public_ecprov(pk);
}
#endif /*def HAVE_EVP_KEYMGMT_GET0_PROVIDER*/

static int
ssh_EVP_PKEY_complete_pub_ecdsa(EVP_PKEY *pk) {
#ifdef HAVE_EVP_KEYMGMT_GET0_PROVIDER
	if (EVP_PKEY_get0_provider(pk) != NULL)
		return ssh_EVP_PKEY_complete_pub_ecprov(pk);
#endif
{	EC_KEY *ec;
	int r, nid;

	ec = EVP_PKEY_get1_EC_KEY(pk);
	if (ec == NULL)
		return SSH_ERR_INVALID_ARGUMENT;

	nid = ssh_EC_KEY_preserve_nid(ec);
	if (nid < 0) {
		error_f("unsupported elliptic curve");
		r = SSH_ERR_EC_CURVE_INVALID;
		goto err;
	}

	r = ssh_EC_KEY_validate_public(ec);

err:
	EC_KEY_free(ec);
	return r;
}
}


#ifdef HAVE_EVP_KEYMGMT_GET0_PROVIDER
static int
sshkey_set_prov_param_nid(const EVP_PKEY *pk, int *pnid) {
	char param[1024];
	size_t param_len;
	int nid;

	if (EVP_PKEY_get_utf8_string_param(pk, OSSL_PKEY_PARAM_GROUP_NAME,
	    param, sizeof(param), &param_len) != 1)
		return SSH_ERR_LIBCRYPTO_ERROR;

	nid = OBJ_txt2nid(param);
	if (nid == NID_undef)
		return SSH_ERR_LIBCRYPTO_ERROR;

	if (sshkey_curve_nid_to_name(nid) == NULL)
		return SSH_ERR_EC_CURVE_INVALID;

	*pnid = nid;
	return 0;
}
#endif /*def HAVE_EVP_KEYMGMT_GET0_PROVIDER*/

static int
sshkey_set_nid(EVP_PKEY *pk, int *pnid) {
#ifdef HAVE_EVP_KEYMGMT_GET0_PROVIDER
	if (EVP_PKEY_get0_provider(pk) != NULL)
		return sshkey_set_prov_param_nid(pk, pnid);
#endif
{	EC_KEY *ec;
	const EC_GROUP *g;

	ec = EVP_PKEY_get1_EC_KEY(pk);
	if (ec == NULL) return SSH_ERR_LIBCRYPTO_ERROR;

	/* indirectly set in sshkey_ecdsa_key_to_nid(if needed)
	   when pkey is completed */
	g = EC_KEY_get0_group(ec);
	if (g == NULL) return SSH_ERR_LIBCRYPTO_ERROR;

	*pnid = EC_GROUP_get_curve_name(g);
	return 0;
}
}


#ifdef HAVE_EVP_KEYMGMT_GET0_PROVIDER
static int
ssh_EVP_PKEY_check_private_ecprov(EVP_PKEY *pkey, const BIGNUM *exponent) {
	EC_GROUP *group;
	int r;

	group = ssh_EVP_PKEY_prov_get_EC_GROUP(pkey);
	if (group == NULL) return SSH_ERR_ALLOC_FAIL;

	r = ssh_EC_GROUP_check_private(group, exponent);

	EC_GROUP_free(group);
	return r;
}
#endif /*def HAVE_EVP_KEYMGMT_GET0_PROVIDER*/

static inline int
ssh_EC_KEY_check_private(const EC_KEY *ec, const BIGNUM *exponent) {
	const EC_GROUP *group = EC_KEY_get0_group(ec);
	if (group == NULL) return SSH_ERR_INTERNAL_ERROR;

	return ssh_EC_GROUP_check_private(group, exponent);
}


#ifdef HAVE_EVP_KEYMGMT_GET0_PROVIDER
static int
sshkey_validate_ecprov_priv(EVP_PKEY *pk, int skip_priv) {
	BIGNUM *exponent = NULL;
	int r;

	if (EVP_PKEY_get_bn_param(pk, OSSL_PKEY_PARAM_PRIV_KEY, &exponent) != 1)
		return skip_priv ? 0 : SSH_ERR_INVALID_ARGUMENT;

	r = ssh_EVP_PKEY_check_private_ecprov(pk, exponent);

	BN_free(exponent);
	return r;
}
#endif /*def HAVE_EVP_KEYMGMT_GET0_PROVIDER*/

static inline int
ssh_EC_KEY_validate_private(const EC_KEY *ec, int skip_priv) {
	const BIGNUM *exponent = EC_KEY_get0_private_key(ec);
	if (exponent == NULL)
		return skip_priv ? 0 : SSH_ERR_INVALID_ARGUMENT;

	return ssh_EC_KEY_check_private(ec, exponent);
}


static int
ssh_pkey_validate_private_ecdsa(EVP_PKEY *pk, int skip_priv) {
#ifdef HAVE_EVP_KEYMGMT_GET0_PROVIDER
	if (EVP_PKEY_get0_provider(pk) != NULL)
		return sshkey_validate_ecprov_priv(pk, skip_priv);
#endif
{	EC_KEY *ec;
	int r;

	ec = EVP_PKEY_get1_EC_KEY(pk);
	if (ec == NULL) return SSH_ERR_INVALID_ARGUMENT;

	r = ssh_EC_KEY_validate_private(ec, skip_priv);

	EC_KEY_free(ec);
	return r;
}
}


extern int /* see sshkey-crypto.c */
sshkey_from_pkey_ecdsa(EVP_PKEY *pk, struct sshkey **keyp);

int
sshkey_from_pkey_ecdsa(EVP_PKEY *pk, struct sshkey **keyp) {
	int r;
	struct sshkey* key;

	r = ssh_EVP_PKEY_complete_pub_ecdsa(pk);
	if (r != 0) return r;

	key = sshkey_new(KEY_UNSPEC);
	if (key == NULL)
		return SSH_ERR_ALLOC_FAIL;

	key->type = KEY_ECDSA;
	key->pk = pk;

	r = sshkey_set_nid(key->pk, &key->ecdsa_nid);
	if (r != 0) goto err;

	/* private part is not required */
	r = ssh_pkey_validate_private_ecdsa(key->pk, 1);
	if (r != 0) goto err;

	/* success */
	SSHKEY_DUMP(key);
	*keyp = key;
	return 0;

err:
	key->pk = NULL; /* transfer failed */
	sshkey_free(key);
	return r;
}


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

	/* do not call ..complete.. as nid is set from curve read and
	 * does not need to be preserved
	 */
	r = ssh_EC_KEY_validate_public(ec);
	if (r != 0) goto err;

	/* success */
	SSHKEY_DUMP(key);

err:
	EC_KEY_free(ec);
	return r;
}

static int
sshbuf_put_ec(struct sshbuf *buf, const EC_POINT *v, const EC_GROUP *g)
{
	u_char d[SSHBUF_MAX_ECPOINT];
	size_t len;
	int ret;

	if ((len = EC_POINT_point2oct(g, v, POINT_CONVERSION_UNCOMPRESSED,
	    NULL, 0, NULL)) > SSHBUF_MAX_ECPOINT) {
		return SSH_ERR_INVALID_ARGUMENT;
	}
	if (EC_POINT_point2oct(g, v, POINT_CONVERSION_UNCOMPRESSED,
	    d, len, NULL) != len) {
		return SSH_ERR_INTERNAL_ERROR; /* Shouldn't happen */
	}
	ret = sshbuf_put_string(buf, d, len);
	explicit_bzero(d, len);
	return ret;
}

#ifdef HAVE_EVP_KEYMGMT_GET0_PROVIDER
static int
sshbuf_write_prov_ecpub(struct sshbuf *buf, EVP_PKEY *pk) {
	unsigned char *data = NULL;
	size_t len;
	int r = SSH_ERR_LIBCRYPTO_ERROR;

	len = ssh_EVP_PKEY_get1_encoded_public_key(pk, &data);
	if (len == 0) goto err;

	r = sshbuf_put_string(buf, data, len);

err:
	OPENSSL_free(data);
	return r;
}
#endif /*def HAVE_EVP_KEYMGMT_GET0_PROVIDER*/

static inline int
sshbuf_put_eckey(struct sshbuf *buf, const EC_KEY *ec)
{
	return sshbuf_put_ec(buf,
	    EC_KEY_get0_public_key(ec),
	    EC_KEY_get0_group(ec));
}

int
sshbuf_write_pkey_ecpub(struct sshbuf *buf, EVP_PKEY *pk) {
#ifdef HAVE_EVP_KEYMGMT_GET0_PROVIDER
	if (EVP_PKEY_get0_provider(pk) != NULL)
		return sshbuf_write_prov_ecpub(buf, pk);
#endif
{	int r;
	EC_KEY *ec = EVP_PKEY_get1_EC_KEY(pk);
	if (ec == NULL)
		return SSH_ERR_INVALID_ARGUMENT;

	r = sshbuf_put_eckey(buf, ec);

	EC_KEY_free(ec);
	return r;
}
}

static int
sshbuf_write_pub_ecdsa(struct sshbuf *buf, const struct sshkey *key) {
	if (key->pk == NULL) return SSH_ERR_INVALID_ARGUMENT;
	return sshbuf_write_pkey_ecpub(buf, key->pk);
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

	r = ssh_EC_KEY_validate_private(ec, 0);
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
#endif /* def WITH_OPENSSL_4_0_API */


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

#ifdef USE_EVP_PKEY_KEYGEN
extern int /* see kexecdh.c */
ssh_pkey_keygen_ec(int nid, EVP_PKEY **ret);

int
ssh_pkey_keygen_ec(int nid, EVP_PKEY **ret) {
	EVP_PKEY *pk = NULL;
	EVP_PKEY_CTX *ctx = NULL;
	int r;

	ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
	if (ctx == NULL) return SSH_ERR_ALLOC_FAIL;

	if (EVP_PKEY_keygen_init(ctx) <= 0) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		goto err;
	}

	if (EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx, nid) <= 0) {
		r = SSH_ERR_EC_CURVE_INVALID;
		goto err;
	}

	/* for compatibility reason between OpenSSL releases */
	if (EVP_PKEY_CTX_set_ec_param_enc(ctx, OPENSSL_EC_NAMED_CURVE) <= 0) {
		r = SSH_ERR_EC_CURVE_MISMATCH;
		goto err;
	}

	if (EVP_PKEY_keygen(ctx, &pk) <= 0) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		goto err;
	}

	/* success */
	*ret = pk;
	r = 0;

err:
	EVP_PKEY_CTX_free(ctx);
	return r;
}
#else /*ndef USE_EVP_PKEY_KEYGEN*/
static int
ssh_pkey_ec_generate(int nid, EVP_PKEY **ret) {
	EVP_PKEY *pk;
	EC_KEY *private = NULL;
	int r = 0;

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

	/* success */
	*ret = pk;
	pk = NULL;

err:
	EVP_PKEY_free(pk);
	EC_KEY_free(private);
	return r;
}
#endif /*ndef USE_EVP_PKEY_KEYGEN*/

static int
ssh_ecdsa_generate(struct sshkey *key, int bits) {
	EVP_PKEY *pk;
	int r = 0, nid;

	nid = sshkey_ecdsa_bits_to_nid(bits);
	if (nid == -1) return SSH_ERR_KEY_LENGTH;

#ifdef USE_EVP_PKEY_KEYGEN
	r = ssh_pkey_keygen_ec(nid, &pk);
#else
	r = ssh_pkey_ec_generate(nid, &pk);
#endif
	if (r == 0) {
		key->pk = pk;
		key->ecdsa_nid = nid;
	}

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

	if (key == NULL) return SSH_ERR_INVALID_ARGUMENT;

	dgst = ssh_ecdsa_dgst(key);
	if (dgst == NULL) return SSH_ERR_INTERNAL_ERROR;

	ret = ssh_pkey_validate_public_ecdsa(key->pk);
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
	struct sshbuf *b = NULL;
	char *ktype = NULL;
	const u_char *sigblob;
	size_t len;
	int ret;

	if (sig == NULL || siglen == 0)
		return SSH_ERR_INVALID_ARGUMENT;

	if (key == NULL) return SSH_ERR_INVALID_ARGUMENT;

	dgst = ssh_ecdsa_dgst(key);
	if (dgst == NULL) return SSH_ERR_INTERNAL_ERROR;

	ret = ssh_pkey_validate_public_ecdsa(key->pk);
	if (ret != 0) return ret;

	/* fetch signature */
	if ((b = sshbuf_from(sig, siglen)) == NULL)
		return SSH_ERR_ALLOC_FAIL;
	if (sshbuf_get_cstring(b, &ktype, NULL) != 0 ||
	    sshbuf_get_string_direct(b, &sigblob, &len) != 0) {
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

	ret = ssh_pkey_verify_r(dgst, key->pk,
	    sigblob, len, data, datalen);

 out:
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
