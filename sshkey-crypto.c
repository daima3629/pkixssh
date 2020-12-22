/*
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

#define SSHKEY_INTERNAL
#include "includes.h"

#ifdef WITH_OPENSSL
#include "evp-compat.h"

#include "sshkey.h"
#include "sshbuf.h"


struct sshkey*
sshkey_new_rsa(struct sshkey *key) {
	RSA *rsa = RSA_new();
	if (rsa == NULL) {
		free(key);
		return NULL;
	}
	key->rsa = rsa;
 	return key;
}

struct sshkey*
sshkey_new_dsa(struct sshkey *key) {
	DSA *dsa = DSA_new();
	if (dsa == NULL) {
		free(key);
		return NULL;
	}
	key->dsa = dsa;
 	return key;
}


void
sshkey_free_rsa(struct sshkey *key) {
	RSA_free(key->rsa);
	key->rsa = NULL;
}

void
sshkey_free_dsa(struct sshkey *key) {
	DSA_free(key->dsa);
	key->dsa = NULL;
}

#ifdef OPENSSL_HAS_ECC
void
sshkey_free_ecdsa(struct sshkey *key) {
	EC_KEY_free(key->ecdsa);
	key->ecdsa = NULL;
}
#endif /* OPENSSL_HAS_ECC */


int
sshbuf_write_pub_rsa(struct sshbuf *buf, const struct sshkey *key) {
	int r;
	const BIGNUM *n = NULL, *e = NULL;

	RSA_get0_key(key->rsa, &n, &e, NULL);
	if ((r = sshbuf_put_bignum2(buf, n)) != 0 ||
	    (r = sshbuf_put_bignum2(buf, e)) != 0)
		return r;

	return 0;
}

int
sshbuf_write_pub_rsa_inv(struct sshbuf *buf, const struct sshkey *key) {
	int r;
	const BIGNUM *n = NULL, *e = NULL;

	RSA_get0_key(key->rsa, &n, &e, NULL);
	if ((r = sshbuf_put_bignum2(buf, e)) != 0 ||
	    (r = sshbuf_put_bignum2(buf, n)) != 0)
		return r;

	return 0;
}

int
sshbuf_write_priv_rsa(struct sshbuf *buf, const struct sshkey *key) {
	int r;
	const BIGNUM *d = NULL, *iqmp = NULL, *p = NULL, *q = NULL;

	RSA_get0_key(key->rsa, NULL, NULL, &d);
	RSA_get0_crt_params(key->rsa, NULL, NULL, &iqmp);
	RSA_get0_factors(key->rsa, &p, &q);

	if ((r = sshbuf_put_bignum2(buf, d)) != 0 ||
	    (r = sshbuf_put_bignum2(buf, iqmp)) != 0 ||
	    (r = sshbuf_put_bignum2(buf, p)) != 0 ||
	    (r = sshbuf_put_bignum2(buf, q)) != 0)
		return r;

	return 0;
}

int
sshbuf_write_pub_dsa(struct sshbuf *buf, const struct sshkey *key) {
	int r;
	const BIGNUM *p = NULL, *q = NULL, *g = NULL;
	const BIGNUM *pub_key = NULL;

	DSA_get0_pqg(key->dsa, &p, &q, &g);
	DSA_get0_key(key->dsa, &pub_key, NULL);

	if ((r = sshbuf_put_bignum2(buf, p)) != 0 ||
	    (r = sshbuf_put_bignum2(buf, q)) != 0 ||
	    (r = sshbuf_put_bignum2(buf, g)) != 0 ||
	    (r = sshbuf_put_bignum2(buf, pub_key)) != 0)
		return r;

	return 0;
}

int
sshbuf_write_priv_dsa(struct sshbuf *buf, const struct sshkey *key) {
	const BIGNUM *priv_key = NULL;

	DSA_get0_key(key->dsa, NULL, &priv_key);
	return sshbuf_put_bignum2(buf, priv_key);
}

#ifdef OPENSSL_HAS_ECC
int
sshbuf_write_pub_ecdsa(struct sshbuf *buf, const struct sshkey *key) {
	int r;
	const char *curve_name = sshkey_curve_nid_to_name(key->ecdsa_nid);

	if ((r = sshbuf_put_cstring(buf, curve_name)) != 0 ||
	    (r = sshbuf_put_eckey(buf, key->ecdsa)) != 0)
		return r;

	return 0;
}

int
sshbuf_write_priv_ecdsa(struct sshbuf *buf, const struct sshkey *key) {
	return sshbuf_put_bignum2(buf, EC_KEY_get0_private_key(key->ecdsa));
}
#endif /* OPENSSL_HAS_ECC */

#else

typedef int sshkey_crypto_empty_translation_unit;

#endif /* WITH_OPENSSL */
