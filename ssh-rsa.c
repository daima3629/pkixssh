/* $OpenBSD: ssh-rsa.c,v 1.67 2018/07/03 11:39:54 djm Exp $ */
/*
 * Copyright (c) 2000, 2003 Markus Friedl <markus@openbsd.org>
 * Copyright (c) 2011 Dr. Stephen Henson.  All rights reserved.
 * Copyright (c) 2011-2022 Roumen Petrov.  All rights reserved.
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
#include "xmalloc.h"
#include "log.h"


#ifndef HAVE_RSA_GENERATE_KEY_EX	/* OpenSSL < 0.9.8 */
static int
RSA_generate_key_ex(RSA *rsa, int bits, BIGNUM *bn_e, void *cb)
{
	RSA *new_rsa, tmp_rsa;
	unsigned long e;

	if (cb != NULL)
		fatal_f("callback args not supported");
	e = BN_get_word(bn_e);
	if (e == 0xffffffffL)
		fatal_f("value of e too large");
	new_rsa = RSA_generate_key(bits, e, NULL, NULL);
	if (new_rsa == NULL)
		return 0;
	/* swap rsa/new_rsa then free new_rsa */
	tmp_rsa = *rsa;
	*rsa = *new_rsa;
	*new_rsa = tmp_rsa;
	RSA_free(new_rsa);
	return 1;
}
#endif

#ifndef HAVE_RSA_GET0_KEY
/* opaque RSA key structure */
static inline void
RSA_get0_key(const RSA *rsa, const BIGNUM **n, const BIGNUM **e, const BIGNUM **d) {
	if (n != NULL) *n = rsa->n;
	if (e != NULL) *e = rsa->e;
	if (d != NULL) *d = rsa->d;
}

static inline int
RSA_set0_key(RSA *rsa, BIGNUM *n, BIGNUM *e, BIGNUM *d) {
/* If the fields in r are NULL, the corresponding input parameters MUST
 * be non-NULL for n and e.  d may be left NULL (in case only the
 * public key is used).
 *
 * It is an error to give the results from get0 on r as input
 * parameters.
 */
	if (n == rsa->n || e == rsa->e
	|| (rsa->d != NULL && d == rsa->d))
		return 0;

	if (n != NULL) { BN_free(rsa->n); rsa->n = n; }
	if (e != NULL) { BN_free(rsa->e); rsa->e = e; }
	if (d != NULL) { BN_free(rsa->d); rsa->d = d; }

	return 1;
}
#endif /* ndef HAVE_RSA_GET0_KEY */


struct ssh_rsa_alg_st {
	const char *name;
	const int nid;
	const char *signame;
};

static struct ssh_rsa_alg_st
ssh_rsa_algs[] = {
#ifdef HAVE_EVP_SHA256
	{ "rsa-sha2-256", NID_sha256, "rsa-sha2-256" },
	{ "rsa-sha2-512", NID_sha512, "rsa-sha2-512" },
#endif
	{ "ssh-rsa", NID_sha1, "ssh-rsa" },
#ifdef HAVE_EVP_SHA256
	{ "rsa-sha2-256-cert-v01@openssh.com", NID_sha256, "rsa-sha2-256" },
	{ "rsa-sha2-512-cert-v01@openssh.com", NID_sha512, "rsa-sha2-512" },
#endif
	{ "ssh-rsa-cert-v01@openssh.com", NID_sha1, "ssh-rsa" },
	{ NULL, NID_undef, NULL }
};

static struct ssh_rsa_alg_st* ssh_rsa_alg_info(const char *alg);

struct ssh_rsa_alg_st*
ssh_rsa_alg_info(const char *alg) {
	struct ssh_rsa_alg_st* p;

	if (alg == NULL || *alg == '\0')
		return ssh_rsa_alg_info("ssh-rsa");

	for (p = ssh_rsa_algs; p->name != NULL; p++)
		if (strcmp(alg, p->name) == 0)
			return p;

	return NULL;
}

/* global option overridable by configuration */
int required_rsa_size = SSH_RSA_MINIMUM_MODULUS_SIZE;

int
sshrsa_verify_length(int bits) {
	return bits < required_rsa_size
	    ? SSH_ERR_KEY_LENGTH : 0;
}

extern int /*TODO static - see sshkey-crypto.c */
sshkey_init_rsa_key(struct sshkey *key, BIGNUM *n, BIGNUM *e, BIGNUM *d);

int
sshkey_init_rsa_key(struct sshkey *key, BIGNUM *n, BIGNUM *e, BIGNUM *d) {
	int r;
	EVP_PKEY *pk = NULL;
	RSA *rsa = NULL;

	pk = EVP_PKEY_new();
	if (pk == NULL) {
		r = SSH_ERR_ALLOC_FAIL;
		goto err;
	}
	rsa = RSA_new();
	if (rsa == NULL) {
		r = SSH_ERR_ALLOC_FAIL;
		goto err;
	}

	if (!EVP_PKEY_set1_RSA(pk, rsa)) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		goto err;
	}

	/* transfer to key must be last operation -
	   if fail then caller could free arguments */
	if (!RSA_set0_key(rsa, n, e, d)) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		goto err;
	}

	/* success */
	key->pk = pk;
	pk = NULL;
	r = 0;

err:
	RSA_free(rsa);
	EVP_PKEY_free(pk);
	return r;
}

extern int /*TODO static - see sshkey-crypto.c */
ssh_EVP_PKEY_complete_pub_rsa(EVP_PKEY *pk);

static int
sshbuf_read_pub_rsa_priv(struct sshbuf *buf, struct sshkey *key) {
	int r;
	BIGNUM *n = NULL, *e = NULL;

	if ((r = sshbuf_get_bignum2(buf, &n)) != 0 ||
	    (r = sshbuf_get_bignum2(buf, &e)) != 0)
		goto err;

	/* key attribute allocation */
	r = sshkey_init_rsa_key(key, n, e, NULL);
	if (r != 0) goto err;
	n = e = NULL; /* transferred */

	r = ssh_EVP_PKEY_complete_pub_rsa(key->pk);
	if (r != 0) goto err;

	/* success */
	SSHKEY_DUMP(key);
	return 0;

err:
	BN_clear_free(n);
	BN_clear_free(e);
	sshkey_clear_pkey(key);
	return r;
}

extern int /* TODO static - see sshkey-crypto.c */
sshrsa_complete_crt_parameters(RSA *rsa, const BIGNUM *rsa_iqmp);


static int
sshbuf_write_pub_rsa_priv(struct sshbuf *buf, const struct sshkey *key) {
	int r;
	const BIGNUM *n = NULL, *e = NULL;

{	RSA *rsa = EVP_PKEY_get1_RSA(key->pk);
	if (rsa == NULL)
		return SSH_ERR_INVALID_ARGUMENT;
	RSA_get0_key(rsa, &n, &e, NULL);
	RSA_free(rsa);
}
	if ((r = sshbuf_put_bignum2(buf, n)) != 0 ||
	    (r = sshbuf_put_bignum2(buf, e)) != 0)
		return r;

	return 0;
}


static int
sshbuf_read_priv_rsa(struct sshbuf *buf, struct sshkey *key) {
	int r;
	RSA *rsa = NULL;
	BIGNUM *d = NULL, *iqmp = NULL, *p = NULL, *q = NULL;

	if ((r = sshbuf_get_bignum2(buf, &d)) != 0 ||
	    (r = sshbuf_get_bignum2(buf, &iqmp)) != 0 ||
	    (r = sshbuf_get_bignum2(buf, &p)) != 0 ||
	    (r = sshbuf_get_bignum2(buf, &q)) != 0)
		goto err;

	rsa = EVP_PKEY_get1_RSA(key->pk);
	if (rsa == NULL) {
		r = SSH_ERR_INVALID_ARGUMENT;
		goto err;
	}

	if (!RSA_set0_key(rsa, NULL, NULL, d)) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		goto err;
	}
	d = NULL; /* transferred */

	if (!RSA_set0_factors(rsa, p, q)) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		goto err;
	}
	p = q = NULL; /* transferred */

	r = sshrsa_complete_crt_parameters(rsa, iqmp);
	if (r != 0) goto err;

	/* success */
	SSHKEY_DUMP(key);
	BN_clear_free(iqmp);
	RSA_free(rsa);
	return 0;

err:
	BN_clear_free(d);
	BN_clear_free(p);
	BN_clear_free(q);
	BN_clear_free(iqmp);
	RSA_free(rsa);
	return r;
}

static int
sshbuf_write_priv_rsa(struct sshbuf *buf, const struct sshkey *key) {
	int r;
	const BIGNUM *d = NULL, *iqmp = NULL, *p = NULL, *q = NULL;

{	RSA *rsa = EVP_PKEY_get1_RSA(key->pk);
	if (rsa == NULL)
		return SSH_ERR_INVALID_ARGUMENT;
	RSA_get0_key(rsa, NULL, NULL, &d);
	RSA_get0_crt_params(rsa, NULL, NULL, &iqmp);
	RSA_get0_factors(rsa, &p, &q);
	RSA_free(rsa);
}
	if ((r = sshbuf_put_bignum2(buf, d)) != 0 ||
	    (r = sshbuf_put_bignum2(buf, iqmp)) != 0 ||
	    (r = sshbuf_put_bignum2(buf, p)) != 0 ||
	    (r = sshbuf_put_bignum2(buf, q)) != 0)
		return r;

	return 0;
}


/* key implementation */

static u_int
ssh_rsa_size(const struct sshkey *key)
{
	return (key->pk != NULL) ? EVP_PKEY_bits(key->pk) : 0;
}

static void
ssh_rsa_cleanup(struct sshkey *k)
{
	sshkey_clear_pkey(k);
}

static int
ssh_rsa_equal(const struct sshkey *a, const struct sshkey *b)
{
	return sshkey_equal_public_pkey(a, b);
}

static int
ssh_rsa_serialize_private(const struct sshkey *key, struct sshbuf *buf,
    enum sshkey_serialize_rep opts)
{
	int r;

	UNUSED(opts);
	if (!sshkey_is_cert(key)) {
		if ((r = sshbuf_write_pub_rsa_priv(buf, key)) != 0)
			return r;
	}
	return sshbuf_write_priv_rsa(buf, key);
}

static int
ssh_rsa_generate(struct sshkey *key, int bits) {
	EVP_PKEY *pk;
	RSA *private = NULL;
	BIGNUM *f4 = NULL;
	int r;

	r = sshrsa_verify_length(bits);
	if (r != 0) return r;

	if (bits > SSHBUF_MAX_BIGNUM * 8)
		return SSH_ERR_KEY_LENGTH;

	;
	if ((pk = EVP_PKEY_new()) == NULL ||
	    (private = RSA_new()) == NULL ||
	    (f4 = BN_new()) == NULL
	) {
		r = SSH_ERR_ALLOC_FAIL;
		goto err;
	}
	if (!BN_set_word(f4, RSA_F4) ||
	    !RSA_generate_key_ex(private, bits, f4, NULL)) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		goto err;
	}

	if (!EVP_PKEY_set1_RSA(pk, private)) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		goto err;
	}

	key->pk = pk;
	pk = NULL;

err:
	EVP_PKEY_free(pk);
	RSA_free(private);
	BN_free(f4);
	return r;
}

static void
ssh_rsa_move_public(struct sshkey *from, struct sshkey *to) {
	sshkey_move_pk(from, to);
}

static int
ssh_rsa_copy_public(const struct sshkey *from, struct sshkey *to) {
	int r;
	BIGNUM *n = NULL, *e = NULL;

{	RSA *rsa = EVP_PKEY_get1_RSA(from->pk);
	const BIGNUM *k_n, *k_e;

	if (rsa == NULL)
		return SSH_ERR_INVALID_ARGUMENT;
	RSA_get0_key(rsa, &k_n, &k_e, NULL);
	RSA_free(rsa);

	if ((n = BN_dup(k_n)) == NULL ||
	    (e = BN_dup(k_e)) == NULL) {
		r = SSH_ERR_ALLOC_FAIL;
		goto err;
	}
}

	r = sshkey_init_rsa_key(to, n, e, NULL);
	if (r != 0) goto err;
	/* n = e = NULL; transferred */

	/* success */
	return 0;

err:
	BN_clear_free(n);
	BN_clear_free(e);
	sshkey_clear_pkey(to);
	return r;
}

static int
ssh_rsa_deserialize_private(const char *pkalg, struct sshbuf *buf,
    struct sshkey *key)
{
	int r;

	UNUSED(pkalg);
	if (!sshkey_is_cert(key)) {
		if ((r = sshbuf_read_pub_rsa_priv(buf, key)) != 0)
			return r;
	}
	return sshbuf_read_priv_rsa(buf, key);
}

static int
ssh_rsa_sign(const ssh_sign_ctx *ctx, u_char **sigp, size_t *lenp,
    const u_char *data, size_t datalen)
{
	const struct sshkey *key = ctx->key;
	u_char *sig = NULL;
	size_t slen = 0;
	u_int len;
	struct ssh_rsa_alg_st *alg_info;
	int ret;
	struct sshbuf *b = NULL;

	if (lenp != NULL)
		*lenp = 0;
	if (sigp != NULL)
		*sigp = NULL;

	alg_info = ssh_rsa_alg_info(ctx->alg);
	if (alg_info == NULL)
		return SSH_ERR_INVALID_ARGUMENT;
	debug3_f("alg=%s/%s", (ctx->alg != NULL ? ctx->alg : "(nil)"), alg_info->name);

	ret = sshkey_validate_public_rsa(key);
	if (ret != 0) return ret;

{	/* EVP_Sign... */
	const EVP_MD *evp_md;
	int ok = -1;

	if ((evp_md = EVP_get_digestbynid(alg_info->nid)) == NULL) {
		error_f("EVP_get_digestbynid %d failed", alg_info->nid);
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
	if ((ret = sshbuf_put_cstring(b, alg_info->signame)) != 0 ||
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

static int
ssh_rsa_verify(const ssh_verify_ctx *ctx,
    const u_char *sig, size_t siglen,
    const u_char *data, size_t dlen)
{
	const struct sshkey *key = ctx->key;
	const char *alg = ctx->alg;
	char *sigtype = NULL;
	struct ssh_rsa_alg_st *alg_info;
	int ret;
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
	/* algorithm for plain keys */
	alg_info = ssh_rsa_alg_info(sigtype);
	if (alg_info == NULL) {
		ret = SSH_ERR_INVALID_ARGUMENT;
		goto out;
	}
	debug3_f("alg=%s/%s", (alg != NULL ? alg : "(nil)"), alg_info->name);
	/*
	 * For legacy reasons allow ssh-rsa-cert-v01 certs to accept SHA2 signatures
	 * but otherwise the signature algorithm should match.
	 */
	if (alg != NULL && strcmp(alg, "ssh-rsa-cert-v01@openssh.com") != 0) {
		struct ssh_rsa_alg_st *want_info;
		want_info = ssh_rsa_alg_info(alg);
		if (want_info == NULL) {
			ret = SSH_ERR_INVALID_ARGUMENT;
			goto out;
		}
		if (alg_info->nid != want_info->nid) {
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
	int ok;
	const EVP_MD *evp_md;

	if ((evp_md = EVP_get_digestbynid(alg_info->nid)) == NULL) {
		error_f("EVP_get_digestbynid %d failed", alg_info->nid);
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

	ok = EVP_VerifyUpdate(md, data, dlen);
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

static const struct sshkey_impl_funcs sshkey_rsa_funcs = {
	/* .size = */		ssh_rsa_size,
	/* .alloc =		NULL, */
	/* .cleanup = */	ssh_rsa_cleanup,
	/* .equal = */		ssh_rsa_equal,
	/* .serialize_private = */	ssh_rsa_serialize_private,
	/* .deserialize_private = */	ssh_rsa_deserialize_private,
	/* .generate = */	ssh_rsa_generate,
	/* .move_public = */	ssh_rsa_move_public,
	/* .copy_public = */	ssh_rsa_copy_public,
	/* .sign = */		ssh_rsa_sign,
	/* .verify = */		ssh_rsa_verify
};

const struct sshkey_impl sshkey_rsa_impl = {
	/* .name = */		"ssh-rsa",
	/* .shortname = */	"RSA",
	/* .sigalg = */		NULL,
	/* .type = */		KEY_RSA,
	/* .nid = */		0,
	/* .cert = */		0,
	/* .sigonly = */	0,
	/* .keybits = */	0,
	/* .funcs = */		&sshkey_rsa_funcs
};

const struct sshkey_impl sshkey_rsa_cert_impl = {
	/* .name = */		"ssh-rsa-cert-v01@openssh.com",
	/* .shortname = */	"RSA-CERT",
	/* .sigalg = */		NULL,
	/* .type = */		KEY_RSA_CERT,
	/* .nid = */		0,
	/* .cert = */		1,
	/* .sigonly = */	0,
	/* .keybits = */	0,
	/* .funcs = */		&sshkey_rsa_funcs
};

#ifdef HAVE_EVP_SHA256
const struct sshkey_impl sshkey_rsa_sha256_impl = {
	/* .name = */		"rsa-sha2-256",
	/* .shortname = */	"RSA",
	/* .sigalg = */		NULL,
	/* .type = */		KEY_RSA,
	/* .nid = */		0,
	/* .cert = */		0,
	/* .sigonly = */	1,
	/* .keybits = */	0,
	/* .funcs = */		&sshkey_rsa_funcs
};

const struct sshkey_impl sshkey_rsa_sha512_impl = {
	/* .name = */		"rsa-sha2-512",
	/* .shortname = */	"RSA",
	/* .sigalg = */		NULL,
	/* .type = */		KEY_RSA,
	/* .nid = */		0,
	/* .cert = */		0,
	/* .sigonly = */	1,
	/* .keybits = */	0,
	/* .funcs = */		&sshkey_rsa_funcs
};

const struct sshkey_impl sshkey_rsa_sha256_cert_impl = {
	/* .name = */		"rsa-sha2-256-cert-v01@openssh.com",
	/* .shortname = */	"RSA-CERT",
	/* .sigalg = */		"rsa-sha2-256",
	/* .type = */		KEY_RSA_CERT,
	/* .nid = */		0,
	/* .cert = */		1,
	/* .sigonly = */	1,
	/* .keybits = */	0,
	/* .funcs = */		&sshkey_rsa_funcs
};

const struct sshkey_impl sshkey_rsa_sha512_cert_impl = {
	/* .name = */		"rsa-sha2-512-cert-v01@openssh.com",
	/* .shortname = */	"RSA-CERT",
	/* .sigalg = */		"rsa-sha2-512",
	/* .type = */		KEY_RSA_CERT,
	/* .nid = */		0,
	/* .cert = */		1,
	/* .sigonly = */	1,
	/* .keybits = */	0,
	/* .funcs = */		&sshkey_rsa_funcs
};
#endif /*def HAVE_EVP_SHA256*/
#else

typedef int ssh_rsa_empty_translation_unit;

#endif /* WITH_OPENSSL */
