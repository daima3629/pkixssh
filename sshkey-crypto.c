/*
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

#ifdef WITH_OPENSSL
#include "evp-compat.h"
#include <openssl/pem.h>

#include "ssh-x509.h"
#include "compat.h"
#include "ssherr.h"
#include "crypto_api.h" /*for some Ed25519 defines */
#include "xmalloc.h"
#include "log.h"

#ifdef DEBUG_PK
static void
ssh_EVP_PKEY_print_fp(FILE *fp, const EVP_PKEY *pkey) {
#ifdef HAVE_EVP_PKEY_PRINT_PARAMS /* OpenSSL 1.0.0+ */
{	/* OpenSSL lacks print to file stream */
	BIO *bio = BIO_new_fp(fp, BIO_NOCLOSE);
#ifdef VMS
	{	BIO *tmpbio = BIO_new(BIO_f_linebuffer());
		bio = BIO_push(tmpbio, bio);
	}
#endif

	EVP_PKEY_print_private(bio, pkey, 0, NULL);
	BIO_free_all(bio);
}
#else
{
	int evp_id = EVP_PKEY_base_id(pkey);

	switch (evp_id) {
	case EVP_PKEY_RSA: {
		RSA *rsa = EVP_PKEY_get1_RSA(pkey);
		RSA_print_fp(fp, rsa, 0);
		RSA_free(rsa);
		} break;
#ifdef OPENSSL_HAS_ECC
	case EVP_PKEY_EC: {
		EC_KEY *ec = EVP_PKEY_get1_EC_KEY(pkey);
		EC_KEY_print_fp(fp, ec, 0);
		EC_KEY_free(ec);
		} break;
#endif /* OPENSSL_HAS_ECC */
	case EVP_PKEY_DSA: {
		DSA *dsa = EVP_PKEY_get1_DSA(pkey);
		DSA_print_fp(fp, dsa, 0);
		DSA_free(dsa);
		} break;
	}
}
#endif /*ndef HAVE_EVP_PKEY_PRINT_PARAMS*/
}

static void
sshkey_dump(const char *func, const struct sshkey *key) {
	fprintf(stderr, "dump key %s():\n", func);
	ssh_EVP_PKEY_print_fp(stderr, key->pk);
}
#endif /* DEBUG_PK */

#define SSHKEY_DUMP(...)	sshkey_dump(__func__, __VA_ARGS__)


#ifdef OPENSSL_HAS_ECC
extern int /* TODO move to ssh-ecdsa.c */
sshkey_validate_ec_priv(const EC_KEY *ec);

int
sshkey_validate_ec_priv(const EC_KEY *ec) {
	int r;
	const BIGNUM *exponent;
	BIGNUM *order = NULL, *tmp = NULL;

	exponent = EC_KEY_get0_private_key(ec);
	if (exponent == NULL) {
		r = SSH_ERR_INVALID_ARGUMENT;
		goto err;
	}

	order = BN_new();
	if (order == NULL)  {
		r = SSH_ERR_ALLOC_FAIL;
		goto err;
	}

	if (EC_GROUP_get_order(EC_KEY_get0_group(ec), order, NULL) != 1) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		goto err;
	}

	/* log2(private) > log2(order)/2 */
	if (BN_num_bits(exponent) <= BN_num_bits(order) / 2) {
		r = SSH_ERR_KEY_INVALID_EC_VALUE;
		goto err;
	}

	tmp = BN_new();
	if (tmp == NULL) {
		r = SSH_ERR_ALLOC_FAIL;
		goto err;
	}

	/* private < order - 1 */
	if (!BN_sub(tmp, order, BN_value_one())) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		goto err;
	}
	if (BN_cmp(exponent, tmp) >= 0) {
		r = SSH_ERR_KEY_INVALID_EC_VALUE;
		goto err;
	}

	/* other checks ? */

	r = 0;

err:
	BN_clear_free(order);
	BN_clear_free(tmp);
	return r;
}
#endif


#ifdef OPENSSL_HAS_ECC
int
ssh_EC_KEY_preserve_nid(EC_KEY *ec)
{
	static int nids[] = {
		NID_X9_62_prime256v1,
		NID_secp384r1,
#  ifdef OPENSSL_HAS_NISTP521
		NID_secp521r1,
#  endif /* OPENSSL_HAS_NISTP521 */
		-1
	};
	int k;
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
	if (nid > 0) {
		for (k = 0; nids[k] != -1; k++) {
			if (nid == nids[k])
				return nid;
		}
		return -1;
	}
}
{	EC_GROUP *eg;
	for (k = 0; nids[k] != -1; k++) {
		eg = EC_GROUP_new_by_curve_name(nids[k]);
		if (eg == NULL) return -1;
		if (EC_GROUP_cmp(g, eg, NULL) == 0)
			break;
		EC_GROUP_free(eg);
	}
	if (nids[k] == -1) return -1;
	/* Use the group with the NID attached */
	EC_GROUP_set_asn1_flag(eg, OPENSSL_EC_NAMED_CURVE);
	if (EC_KEY_set_group(ec, eg) != 1) {
		EC_GROUP_free(eg);
		return -1;
	}
	EC_GROUP_free(eg);
}
	return nids[k];
}
#endif /*def OPENSSL_HAS_ECC*/


extern int
ssh_EVP_PKEY_complete_pub_rsa(EVP_PKEY *pk);

static int
sshkey_from_pkey_rsa(EVP_PKEY *pk, struct sshkey **keyp) {
	int r;
	struct sshkey* key;

	r = ssh_EVP_PKEY_complete_pub_rsa(pk);
	if (r != 0) return r;

	key = sshkey_new(KEY_UNSPEC);
	if (key == NULL)
		return SSH_ERR_ALLOC_FAIL;

	key->type = KEY_RSA;
	key->pk = pk;

	/* success */
	SSHKEY_DUMP(key);
	*keyp = key;
	return 0;
}

extern int
ssh_EVP_PKEY_complete_pub_dsa(EVP_PKEY *pk);

static int
sshkey_from_pkey_dsa(EVP_PKEY *pk, struct sshkey **keyp) {
	int r;
	struct sshkey* key;

	r = ssh_EVP_PKEY_complete_pub_dsa(pk);
	if (r != 0) return r;

	key = sshkey_new(KEY_UNSPEC);
	if (key == NULL)
		return SSH_ERR_ALLOC_FAIL;

	/* success */
	key->type = KEY_DSA;
	key->pk = pk;

	SSHKEY_DUMP(key);
	*keyp = key;
	return 0;
}

#ifdef OPENSSL_HAS_ECC
extern int
ssh_EVP_PKEY_complete_pub_ecdsa(EVP_PKEY *pk);

static int
sshkey_from_pkey_ecdsa(EVP_PKEY *pk, struct sshkey **keyp) {
	int r;
	struct sshkey* key;
	EC_KEY *ec;

	r = ssh_EVP_PKEY_complete_pub_ecdsa(pk);
	if (r != 0) return r;

	key = sshkey_new(KEY_UNSPEC);
	if (key == NULL)
		return SSH_ERR_ALLOC_FAIL;

	key->type = KEY_ECDSA;
	key->pk = pk;

	ec = EVP_PKEY_get1_EC_KEY(key->pk);
	if (ec == NULL) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		goto err;
	}

{	/* indirectly set in sshkey_ecdsa_key_to_nid(if needed)
	   when pkey is completed */
	const EC_GROUP *g = EC_KEY_get0_group(ec);
	key->ecdsa_nid = EC_GROUP_get_curve_name(g);
}

{	/* private part is not required */
	const BIGNUM *exponent = EC_KEY_get0_private_key(ec);
	if (exponent == NULL) goto skip_private;

	r = sshkey_validate_ec_priv(ec);
	if (r != 0) goto err;
}
skip_private:

	/* success */
	SSHKEY_DUMP(key);
	*keyp = key;
	EC_KEY_free(ec);
	return 0;

err:
	EC_KEY_free(ec);
	sshkey_free(key);
	return r;
}
#endif /* OPENSSL_HAS_ECC */

#ifdef OPENSSL_HAS_ED25519
static int
sshkey_from_pkey_ed25519(EVP_PKEY *pk, struct sshkey **keyp) {
	int r;
	struct sshkey* key;
	char *raw_pk = NULL, *raw_sk = NULL;
	size_t len;

	key = sshkey_new(KEY_UNSPEC);
	if (key == NULL)
		return SSH_ERR_ALLOC_FAIL;

	if ((raw_pk = calloc(1, ED25519_PK_SZ)) == NULL ||
	    (raw_sk = calloc(1, ED25519_SK_SZ)) == NULL
	) {
		r = SSH_ERR_ALLOC_FAIL;
		goto err;
	}

	len = ED25519_PK_SZ;
	if (!EVP_PKEY_get_raw_public_key(pk, raw_pk, &len)) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		goto err;
	}
	if (len != ED25519_PK_SZ) {
		r = SSH_ERR_INVALID_FORMAT;
		goto err;
	}

	/* private part is not required */
	len = ED25519_SK_SZ - ED25519_PK_SZ;
	if (!EVP_PKEY_get_raw_private_key(pk, raw_sk, &len))
		goto skip_private;
	if (len != (ED25519_SK_SZ - ED25519_PK_SZ)) {
		r = SSH_ERR_INVALID_FORMAT;
		goto err;
	}
	/* append the public key to private to match internal format */
	memcpy(raw_sk + len, raw_pk, ED25519_PK_SZ);
skip_private:

	key->type = KEY_ED25519;
	key->pk = pk;

	/* success */
	SSHKEY_DUMP(key);
	*keyp = key;
	/* free raw values; TODO */
	key->ed25519_pk = raw_pk;
	key->ed25519_sk = raw_sk;
	return 0;

err:
	free(raw_pk);
	free(raw_sk);
	sshkey_free(key);
	return r;
}
#endif /*def OPENSSL_HAS_ED25519*/

int
sshkey_from_pkey(EVP_PKEY *pk, struct sshkey **keyp) {
	int r, evp_id;

	/* NOTE do not set flags |= SSHKEY_FLAG_EXT !!! */
	evp_id = EVP_PKEY_base_id(pk);
	switch (evp_id) {
	case EVP_PKEY_RSA:
		r = sshkey_from_pkey_rsa(pk, keyp);
		break;
	case EVP_PKEY_DSA:
		r = sshkey_from_pkey_dsa(pk, keyp);
		break;
#ifdef OPENSSL_HAS_ECC
	case EVP_PKEY_EC:
		r = sshkey_from_pkey_ecdsa(pk, keyp);
		break;
#endif /*def OPENSSL_HAS_ECC*/
#ifdef OPENSSL_HAS_ED25519
	case EVP_PKEY_ED25519:
		r = sshkey_from_pkey_ed25519(pk, keyp);
		break;
#endif /*def OPENSSL_HAS_ED25519*/
	default:
		error_f("unsupported pkey type %d", evp_id);
		r = SSH_ERR_KEY_TYPE_UNKNOWN;
	}

	return r;
}


void
sshkey_clear_pkey(struct sshkey *key) {
	EVP_PKEY_free(key->pk);
	key->pk = NULL;
}


void
sshkey_move_pk(struct sshkey *from, struct sshkey *to) {
	EVP_PKEY_free(to->pk);
	to->pk = from->pk;
	from->pk = NULL;
	SSHKEY_DUMP(to);
}


int
sshkey_validate_public(const struct sshkey *key) {
	int evp_id = EVP_PKEY_base_id(key->pk);

	switch (evp_id) {
	case EVP_PKEY_RSA:	return sshkey_validate_public_rsa(key);
	case EVP_PKEY_DSA:	return sshkey_validate_public_dsa(key);
#ifdef OPENSSL_HAS_ECC
	case EVP_PKEY_EC:	return sshkey_validate_public_ecdsa(key);
#endif
	}
	return SSH_ERR_KEY_TYPE_UNKNOWN;
}


#ifndef HAVE_EVP_PKEY_CMP	/* OpenSSL < 0.9.8 */
extern int ssh_EVP_PKEY_cmp_rsa(const EVP_PKEY *a, const EVP_PKEY *b);
extern int ssh_EVP_PKEY_cmp_dsa(const EVP_PKEY *a, const EVP_PKEY *b);

static int
EVP_PKEY_cmp(const EVP_PKEY *a, const EVP_PKEY *b) {
	int evp_id = EVP_PKEY_base_id(a);

	switch (evp_id) {
	case EVP_PKEY_RSA:	return ssh_EVP_PKEY_cmp_rsa(a, b);
	case EVP_PKEY_DSA:	return ssh_EVP_PKEY_cmp_dsa(a, b);
	}
	return -2;
}
#endif /*ndef HAVE_EVP_PKEY_CMP*/

int
ssh_EVP_PKEY_eq(const EVP_PKEY *a, const EVP_PKEY *b) {
#ifdef HAVE_EVP_PKEY_EQ			/* OpenSSL >= 3.0 */
	return EVP_PKEY_eq(a, b);
#else
	return EVP_PKEY_cmp(a, b);
#endif
}

int/*bool*/
sshkey_equal_public_pkey(const struct sshkey *ka, const struct sshkey *kb) {
	const EVP_PKEY *a, *b;

	if (ka == NULL) return 0;
	if (kb == NULL) return 0;

	a = ka->pk;
	if (a == NULL) return 0;

	b = kb->pk;
	if (b == NULL) return 0;

	return ssh_EVP_PKEY_eq(a, b) == 1;
}


/* write identity in PEM formats - PKCS#8 or Traditional */
int
sshkey_private_to_bio(struct sshkey *key, BIO *bio,
    const char *passphrase, int format)
{
	int res;
	int len = strlen(passphrase);
	const EVP_CIPHER *cipher = (len > 0) ? EVP_aes_256_cbc() : NULL;
	u_char *_passphrase = (len > 0) ? (u_char*)passphrase : NULL;

	if (key->pk == NULL)
		return SSH_ERR_INVALID_ARGUMENT;
	if (len > 0 && len <= 4)
		return SSH_ERR_PASSPHRASE_TOO_SHORT;
	if (len > INT_MAX)
		return SSH_ERR_INVALID_ARGUMENT;

	if (format == SSHKEY_PRIVATE_PEM) {
		switch (key->type) {
		case KEY_RSA: {
			RSA *rsa = EVP_PKEY_get1_RSA(key->pk);
			res = PEM_write_bio_RSAPrivateKey(bio, rsa,
			    cipher, _passphrase, len, NULL, NULL);
			RSA_free(rsa);
			} break;
#ifdef OPENSSL_HAS_ECC
		case KEY_ECDSA: {
			EC_KEY *ec = EVP_PKEY_get1_EC_KEY(key->pk);
			res = PEM_write_bio_ECPrivateKey(bio, ec,
			    cipher, _passphrase, len, NULL, NULL);
			EC_KEY_free(ec);
			} break;
#endif
		case KEY_DSA: {
			DSA *dsa = EVP_PKEY_get1_DSA(key->pk);
			res = PEM_write_bio_DSAPrivateKey(bio, dsa,
			    cipher, _passphrase, len, NULL, NULL);
			DSA_free(dsa);
			} break;
		default:
			return SSH_ERR_INVALID_ARGUMENT;
		}
	} else
		res = PEM_write_bio_PKCS8PrivateKey(bio, key->pk, cipher,
		    _passphrase, len, NULL, NULL);

	if (res && sshkey_is_x509(key))
		res = x509key_write_identity_bio_pem(bio, key);

	return res ? 0 : SSH_ERR_LIBCRYPTO_ERROR;
}


/* methods used localy only in ssh-keygen.c */
extern int
sshkey_public_to_fp(struct sshkey *key, FILE *fp, int format);

extern int
sshkey_public_from_fp(FILE *fp, int format, struct sshkey **key);


int
sshkey_public_to_fp(struct sshkey *key, FILE *fp, int format) {
	int res;

	if ((format != SSHKEY_PRIVATE_PEM) &&
	    (format != SSHKEY_PRIVATE_PKCS8))
		return SSH_ERR_INVALID_ARGUMENT;

	if (key->pk == NULL)
		return SSH_ERR_INVALID_ARGUMENT;

	if ((format == SSHKEY_PRIVATE_PEM) &&
	    /* Traditional PEM is available only for RSA */
	    (key->type == KEY_RSA)
	) {
		RSA *rsa = EVP_PKEY_get1_RSA(key->pk);
		res = PEM_write_RSAPublicKey(fp, rsa);
		RSA_free(rsa);
	} else
		res = PEM_write_PUBKEY(fp, key->pk);

	return res ? 0 : SSH_ERR_LIBCRYPTO_ERROR;
}

int
sshkey_public_from_fp(FILE *fp, int format, struct sshkey **key) {
	int r;

	if (format == SSHKEY_PRIVATE_PKCS8) {
		EVP_PKEY *pk = PEM_read_PUBKEY(fp, NULL, NULL, NULL);
		if (pk != NULL) {
			r = sshkey_from_pkey(pk, key);
			if (r == 0)
				pk = NULL; /* transferred */
		} else
		    r = SSH_ERR_INVALID_FORMAT;
		EVP_PKEY_free(pk);
		return r;
	}

	if (format != SSHKEY_PRIVATE_PEM)
		return SSH_ERR_INVALID_ARGUMENT;

{	/* Traditional PEM is available only for RSA */
	RSA *rsa;
	EVP_PKEY *pk = NULL;
	struct sshkey *k = NULL;

	rsa = PEM_read_RSAPublicKey(fp, NULL, NULL, NULL);
	if (rsa == NULL) return SSH_ERR_INVALID_FORMAT;

	pk = EVP_PKEY_new();
	if (pk == NULL) {
		r = SSH_ERR_ALLOC_FAIL;
		goto err;
	}
	if (!EVP_PKEY_set1_RSA(pk, rsa)) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		goto err;
	}

	k = sshkey_new(KEY_UNSPEC);
	if (k == NULL) {
		r = SSH_ERR_ALLOC_FAIL;
		goto err;
	}

	k->type = KEY_RSA;
	k->pk = pk;
	RSA_free(rsa);

	*key = k;
	return 0;

err:
	EVP_PKEY_free(pk);
	RSA_free(rsa);
	sshkey_free(k);
	return r;
}
}


/* digest compatibility */
#if defined(OPENSSL_VERSION_NUMBER) && (OPENSSL_VERSION_NUMBER < 0x10000000L)
/* work-arounds for limited EVP digests in OpenSSL 0.9.8* ...
 * (missing ecdsa support)
 */

#if defined(OPENSSL_HAS_NISTP256) || defined(OPENSSL_HAS_NISTP384) || defined(OPENSSL_HAS_NISTP521)
static inline void
ssh_EVP_MD_ecdsa_init(EVP_MD *t, const EVP_MD *s) {
    memcpy(t, s, sizeof(*t));
    t->sign = (evp_sign_method*)ECDSA_sign;
    t->verify = (evp_verify_method*)ECDSA_verify;
    t->required_pkey_type[0] = EVP_PKEY_EC;
    t->required_pkey_type[1] = 0;
}
#endif


#ifdef OPENSSL_HAS_NISTP256
/* Test for NID_X9_62_prime256v1(nistp256) includes test for EVP_sha256 */
static EVP_MD ecdsa_sha256_md = { NID_undef };

const EVP_MD*
ssh_ecdsa_EVP_sha256(void) {
    if (ecdsa_sha256_md.type == NID_undef)
	ssh_EVP_MD_ecdsa_init(&ecdsa_sha256_md, EVP_sha256());
    return &ecdsa_sha256_md;
}
#endif

#ifdef OPENSSL_HAS_NISTP384
/* Test for NID_secp384r1(nistp384) includes test for EVP_sha384 */
static EVP_MD ecdsa_sha384_md = { NID_undef };

const EVP_MD*
ssh_ecdsa_EVP_sha384(void) {
    if (ecdsa_sha384_md.type == NID_undef)
	ssh_EVP_MD_ecdsa_init(&ecdsa_sha384_md, EVP_sha384());
    return &ecdsa_sha384_md;
}
#endif

#ifdef OPENSSL_HAS_NISTP521
/* Test for NID_secp521r1(nistp521) includes test for EVP_sha512 */
static EVP_MD ecdsa_sha512_md = { NID_undef };

const EVP_MD*
ssh_ecdsa_EVP_sha512(void) {
    if (ecdsa_sha512_md.type == NID_undef)
	ssh_EVP_MD_ecdsa_init(&ecdsa_sha512_md, EVP_sha512());
    return &ecdsa_sha512_md;
}
#endif

#endif /*defined(OPENSSL_VERSION_NUMBER) && (OPENSSL_VERSION_NUMBER < 0x10000000L)*/


#define SHARAW_DIGEST_LENGTH (2*SHA_DIGEST_LENGTH)

static int
DSS1RAW_SignFinal(EVP_MD_CTX *ctx, unsigned char *sigret, unsigned int *siglen, EVP_PKEY *pkey) {
	int ret;
	unsigned char buf[20+2*(SHA_DIGEST_LENGTH)];
	unsigned int  len;

	ret = EVP_SignFinal(ctx, buf, &len, pkey);
	if (ret <= 0) goto done;

	ret = -1;
{
	DSA_SIG *sig;

{	/* decode DSA signature */
	const unsigned char *psig = buf;
	sig = d2i_DSA_SIG(NULL, &psig, (long)len);
}

	*siglen = SHARAW_DIGEST_LENGTH;
	if (sig != NULL) {
		const BIGNUM *ps, *pr;
		u_int rlen, slen;

		DSA_SIG_get0(sig, &pr, &ps);

		rlen = BN_num_bytes(pr);
		slen = BN_num_bytes(ps);

		if (rlen > SHA_DIGEST_LENGTH || slen > SHA_DIGEST_LENGTH) {
			error_f("bad sig size %u %u", rlen, slen);
			goto done;
		}

		explicit_bzero(sigret, SHARAW_DIGEST_LENGTH);
		BN_bn2bin(pr, sigret + SHARAW_DIGEST_LENGTH - SHA_DIGEST_LENGTH - rlen);
		BN_bn2bin(ps, sigret + SHARAW_DIGEST_LENGTH - slen);

		ret = 1;
	}
	DSA_SIG_free(sig);
}
done:
	return(ret);
}


static int
DSS1RAW_VerifyFinal(EVP_MD_CTX *ctx, const unsigned char *sigbuf, unsigned int siglen, EVP_PKEY *pkey) {
	DSA_SIG *sig;

	if (siglen != SHARAW_DIGEST_LENGTH) return -1;

/* decode DSA r&s from SecSH signature blob */
{	BIGNUM *ps, *pr;

	pr = BN_bin2bn(sigbuf                  , SHA_DIGEST_LENGTH, NULL);
	ps = BN_bin2bn(sigbuf+SHA_DIGEST_LENGTH, SHA_DIGEST_LENGTH, NULL);
	if ((pr == NULL) || (ps == NULL)) goto parse_err;

	sig = DSA_SIG_new();
	if (sig == NULL) goto parse_err;

	if (DSA_SIG_set0(sig, pr, ps))
		goto process;

	DSA_SIG_free(sig);

parse_err:
	BN_free(pr);
	BN_free(ps);
	return -1;
}

process:
{	int len, slen;
	unsigned char *buf;
	int ret;

	len = i2d_DSA_SIG(sig, NULL);
	if (len <= 0) {
		DSA_SIG_free(sig);
		return -1;
	}

	buf = xmalloc(len);  /*fatal on error*/

{	/* encode DSA signature */
	unsigned char *pbuf = buf;
	slen = i2d_DSA_SIG(sig, &pbuf);
}

	ret = (len == slen)
		? EVP_VerifyFinal(ctx, buf, len, pkey)
		: -1;

	freezero(buf, len);
	DSA_SIG_free(sig);

	return ret;
}
}


#ifdef OPENSSL_HAS_ECC
static int
SSH_ECDSA_SignFinal(EVP_MD_CTX *ctx, unsigned char *sigret, unsigned int *siglen, EVP_PKEY *pkey) {
	ECDSA_SIG *sig;
	unsigned int len;

{	int ret;
	unsigned char buf[20+2*(SHA512_DIGEST_LENGTH)];

	ret = EVP_SignFinal(ctx, buf, &len, pkey);
	if (ret <= 0) return ret;

{	/* decode ECDSA signature */
	const unsigned char *psig = buf;
	sig = d2i_ECDSA_SIG(NULL, &psig, (long)len);
}

	if (sig == NULL) return -1;
}

/* encode ECDSA r&s into SecSH signature blob */
{	int r;
	struct sshbuf *buf = NULL;
	const BIGNUM *pr, *ps;

	buf = sshbuf_new();
	if (buf == NULL) goto encode_err;

	ECDSA_SIG_get0(sig, &pr, &ps);

	r = sshbuf_put_bignum2(buf, pr);
	if (r != 0) goto encode_err;

	r = sshbuf_put_bignum2(buf, ps);
	if (r != 0) goto encode_err;

	len = sshbuf_len(buf);
	if ((size_t)len != sshbuf_len(buf)) goto encode_err;

	memcpy(sigret, sshbuf_ptr(buf), len);
	*siglen = len;

	sshbuf_free(buf);
	ECDSA_SIG_free(sig);
	return 1;

encode_err:
	sshbuf_free(buf);
	ECDSA_SIG_free(sig);
	return -1;
}
}
#endif /*def OPENSSL_HAS_ECC*/


#ifdef OPENSSL_HAS_ECC
static int
SSH_ECDSA_VerifyFinal(EVP_MD_CTX *ctx, const unsigned char *sigblob, unsigned int siglen, EVP_PKEY *pkey) {
	ECDSA_SIG *sig;

/* decode ECDSA r&s from SecSH signature blob */
{	int r;
	struct sshbuf *buf;
	BIGNUM *pr = NULL, *ps = NULL;

	buf = sshbuf_from(sigblob, (size_t) siglen);
	if (buf == NULL) return -1;

	/* extract mpint r */
	r = sshbuf_get_bignum2(buf, &pr);
	if (r != 0) goto parse_err;

	/* extract mpint s */
	r = sshbuf_get_bignum2(buf, &ps);
	if (r != 0) goto parse_err;

	/* unexpected trailing data */
	if (sshbuf_len(buf) != 0) goto parse_err;

	sig = ECDSA_SIG_new();
	if (sig == NULL) goto parse_err;

	if (ECDSA_SIG_set0(sig, pr, ps)) {
		sshbuf_free(buf);
		goto process;
	}

	ECDSA_SIG_free(sig);

parse_err:
	BN_free(ps);
	BN_free(pr);
	sshbuf_free(buf);
	return -1;
}

process:
{	int len, slen;
	unsigned char *buf;
	int ret;

	len = i2d_ECDSA_SIG(sig, NULL);
	if (len <= 0) {
		ECDSA_SIG_free(sig);
		return -1;
	}

	buf = xmalloc(len);  /*fatal on error*/

{	/* encode ECDSA signature */
	unsigned char *pbuf = buf;
	slen = i2d_ECDSA_SIG(sig, &pbuf);
}

	ret = (len == slen)
		? EVP_VerifyFinal(ctx, buf, slen, pkey)
		: -1;

	freezero(buf, len);
	ECDSA_SIG_free(sig);

	return ret;
}
}
#endif /*def OPENSSL_HAS_ECC*/


/* order by usability */
static ssh_evp_md dgsts[] = {
#ifdef HAVE_EVP_SHA256
	{ SSH_MD_RSA_SHA256, EVP_sha256, EVP_SignFinal, EVP_VerifyFinal },
	{ SSH_MD_RSA_SHA512, EVP_sha512, EVP_SignFinal, EVP_VerifyFinal },
#endif /* def HAVE_EVP_SHA256 */
#ifdef OPENSSL_HAS_ECC	/* ECC imply SHA-256 */
	{ SSH_MD_EC_SHA256_SSH, ssh_ecdsa_EVP_sha256, SSH_ECDSA_SignFinal, SSH_ECDSA_VerifyFinal },
	{ SSH_MD_EC_SHA384_SSH, ssh_ecdsa_EVP_sha384, SSH_ECDSA_SignFinal, SSH_ECDSA_VerifyFinal },
# ifdef HAVE_EVP_SHA512
	{ SSH_MD_EC_SHA512_SSH, ssh_ecdsa_EVP_sha512, SSH_ECDSA_SignFinal, SSH_ECDSA_VerifyFinal },
# endif /* def HAVE_EVP_SHA512 */
#endif /* def OPENSSL_HAS_ECC */

	{ SSH_MD_RSA_SHA1, EVP_sha1, EVP_SignFinal, EVP_VerifyFinal },
	{ SSH_MD_RSA_MD5, EVP_md5, EVP_SignFinal, EVP_VerifyFinal },

	{ SSH_MD_DSA_SHA1, EVP_dss1, EVP_SignFinal, EVP_VerifyFinal },
	{ SSH_MD_DSA_RAW, EVP_dss1, DSS1RAW_SignFinal, DSS1RAW_VerifyFinal },

#ifdef OPENSSL_HAS_ECC
	/* PKIX-SSH pre 10.0 does not implement properly rfc6187 */
	{ SSH_MD_EC_SHA256, ssh_ecdsa_EVP_sha256, EVP_SignFinal, EVP_VerifyFinal },
	{ SSH_MD_EC_SHA384, ssh_ecdsa_EVP_sha384, EVP_SignFinal, EVP_VerifyFinal },
# ifdef HAVE_EVP_SHA512
	{ SSH_MD_EC_SHA512, ssh_ecdsa_EVP_sha512, EVP_SignFinal, EVP_VerifyFinal },
# endif /* def HAVE_EVP_SHA512 */
#endif /* def OPENSSL_HAS_ECC */
	{ -1, NULL, NULL , NULL }
};


ssh_evp_md*
ssh_evp_md_find(int id) {
	ssh_evp_md *p;

	for (p = dgsts; p->id != -1; p++) {
		if (p->id == id)
			return p;
	}
	return NULL;
}


void
ssh_xkalg_dgst_compat(ssh_evp_md *dest, const ssh_evp_md *src, ssh_compat *compat) {
	dest->id = src->id;
	dest->md = src->md;

#ifdef OPENSSL_HAS_ECC
	if (check_compat_extra(compat, SSHX_RFC6187_ASN1_OPAQUE_ECDSA_SIGNATURE)) {
		if (src->SignFinal == SSH_ECDSA_SignFinal) {
			dest->SignFinal = EVP_SignFinal;
			dest->VerifyFinal = EVP_VerifyFinal;
			return;
		}
	}
#else
	UNUSED(compat);
#endif /*ndef OPENSSL_HAS_ECC*/

	dest->SignFinal = src->SignFinal;
	dest->VerifyFinal = src->VerifyFinal;
}


int
ssh_pkey_sign(
	const ssh_evp_md *dgst, EVP_PKEY *privkey,
	u_char *sig, u_int *siglen, const u_char *data, u_int datalen
) {
	int ret;
	EVP_MD_CTX *ctx;

	ctx = EVP_MD_CTX_new();
	if (ctx == NULL) {
		error_f("out of memory");
		return -1;
	}

	ret = EVP_SignInit_ex(ctx, dgst->md(), NULL);
	if (ret <= 0) {
		error_f("init fail");
#ifdef TRACE_EVP_ERROR
		error_crypto("EVP_SignInit_ex");
#endif
		goto done;
	}

	ret = EVP_SignUpdate(ctx, data, datalen);
	if (ret <= 0) {
		error_f("update fail");
#ifdef TRACE_EVP_ERROR
		error_crypto("EVP_SignUpdate");
#endif
		goto done;
	}

	ret = dgst->SignFinal(ctx, sig, siglen, privkey);
	if (ret <= 0) {
		error_f("final fail");
#ifdef TRACE_EVP_ERROR
		error_crypto("EVP_SignFinal");
#endif
		goto done;
	}

done:
	EVP_MD_CTX_free(ctx);
	return ret;
}


int
ssh_pkey_verify(
	const ssh_evp_md *dgst, EVP_PKEY *pubkey,
	const u_char *sig, u_int siglen, const u_char *data, u_int datalen
) {
	int ret;
	EVP_MD_CTX *ctx;

	ctx = EVP_MD_CTX_new();
	if (ctx == NULL) {
		error_f("out of memory");
		return -1;
	}

	ret = EVP_VerifyInit_ex(ctx, dgst->md(), NULL);
	if (ret <= 0) {
		error_f("init fail");
#ifdef TRACE_EVP_ERROR
		error_crypto("EVP_VerifyInit");
#endif
		goto done;
	}

	ret = EVP_VerifyUpdate(ctx, data, datalen);
	if (ret <= 0) {
		error_f("update fail");
#ifdef TRACE_EVP_ERROR
		error_crypto("EVP_VerifyUpdate");
#endif
		goto done;
	}

	ret = dgst->VerifyFinal(ctx, sig, siglen, pubkey);
	if (ret <= 0) {
#ifdef TRACE_EVP_ERROR
		error_crypto("EVP_VerifyFinal");
#endif
		goto done;
	}

done:
	EVP_MD_CTX_free(ctx);
	return ret;
}

#else

typedef int sshkey_crypto_empty_translation_unit;

#endif /* WITH_OPENSSL */
