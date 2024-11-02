/*
 * Copyright (c) 2021-2024 Roumen Petrov.  All rights reserved.
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

#ifdef WITH_OPENSSL
#include "evp-compat.h"

#include "kex.h"
#include "dh.h"
#include "ssherr.h"
#include "misc.h"
#include "log.h"

#ifndef HAVE_BN_IS_NEGATIVE	/*macro before OpenSSL 1.1*/
# ifndef BN_is_negative		/*not defined before OpenSSL 0.9.8*/
#  define BN_is_negative(a) ((a)->neg != 0)
# endif
#endif

#ifndef HAVE_DH_GET0_KEY	/* OpenSSL < 1.1 */
/* Partial backport of opaque DH from OpenSSL >= 1.1, commits
 * "Make DH opaque", "RSA, DSA, DH: Allow some given input to be NULL
 * on already initialised keys" and etc.
 */
static inline void
DH_get0_key(const DH *dh, const BIGNUM **pub_key, const BIGNUM **priv_key) {
	if (pub_key  != NULL) *pub_key  = dh->pub_key;
	if (priv_key != NULL) *priv_key = dh->priv_key;
}

static inline int
DH_set0_key(DH *dh, BIGNUM *pub_key, BIGNUM *priv_key) {
	if (pub_key != NULL) {
		BN_clear_free(dh->pub_key);
		dh->pub_key = pub_key;
	}
	if (priv_key != NULL) {
		BN_clear_free(dh->priv_key);
		dh->priv_key = priv_key;
	}
	return 1;
}

static inline int
DH_set_length(DH *dh, long length) {
	dh->length = length;
	return 1;
}

static inline void
DH_get0_pqg(const DH *dh, const BIGNUM **p, const BIGNUM **q, const BIGNUM **g) {
	if (p != NULL) *p = dh->p;
	if (q != NULL) *q = dh->q;
	if (g != NULL) *g = dh->g;
}

static inline int
DH_set0_pqg(DH *dh, BIGNUM *p, BIGNUM *q, BIGNUM *g) {
/* If the fields p and g in d are NULL, the corresponding input
 * parameters MUST be non-NULL.  q may remain NULL.
 *
 * It is an error to give the results from get0 on d as input
 * parameters.
 */
	if (p == dh->p || (dh->q != NULL && q == dh->q) || g == dh->g)
		return 0;

	if (p != NULL) { BN_free(dh->p); dh->p = p; }
	if (q != NULL) { BN_free(dh->q); dh->q = q; }
	if (g != NULL) { BN_free(dh->g); dh->g = g; }

	if (q != NULL)
	        (void)DH_set_length(dh, BN_num_bits(q));

	return 1;
}
#endif /*ndef HAVE_DH_GET0_KEY*/

extern DH* _dh_new_group(BIGNUM *, BIGNUM *);
extern DH* _dh_new_group_asc(const char *, const char *);
extern DH* _dh_new_group_num(int);


/*
 * This just returns the group, we still need to generate the exchange
 * value.
 */
DH*
_dh_new_group(BIGNUM *modulus, BIGNUM *gen)
{
	DH *dh;

	dh = DH_new();
	if (dh == NULL) return NULL;

	if (!DH_set0_pqg(dh, modulus, NULL, gen)) {
		DH_free(dh);
		return NULL;
	}

	return dh;
}

DH*
_dh_new_group_asc(const char *gen, const char *modulus)
{
	BIGNUM *p = NULL, *g = NULL;

	if (BN_hex2bn(&p, modulus) == 0 ||
	    BN_hex2bn(&g, gen) == 0)
		goto err;

	return _dh_new_group(p, g);

err:
	BN_clear_free(p);
	BN_clear_free(g);
	return NULL;
}


static int/*boolean*/
dh_pub_is_valid(const DH *dh, const BIGNUM *dh_pub)
{
	int i;
	int n = BN_num_bits(dh_pub);
	int bits_set = 0;
	BIGNUM *tmp;
	const BIGNUM *dh_p;

	DH_get0_pqg(dh, &dh_p, NULL, NULL);

	if (BN_is_negative(dh_pub)) {
		error("invalid public DH value: negative");
		return 0;
	}
	if (BN_cmp(dh_pub, BN_value_one()) != 1) {	/* pub_exp <= 1 */
		error("invalid public DH value: <= 1");
		return 0;
	}

	if ((tmp = BN_new()) == NULL) {
		error_f("BN_new failed");
		return 0;
	}
	if (!BN_sub(tmp, dh_p, BN_value_one()) ||
	    BN_cmp(dh_pub, tmp) != -1) {		/* pub_exp > p-2 */
		BN_clear_free(tmp);
		error("invalid public DH value: >= p-1");
		return 0;
	}
	BN_clear_free(tmp);

	for (i = 0; i <= n; i++)
		if (BN_is_bit_set(dh_pub, i))
			bits_set++;

	/* used in dhgex regression test */
	debug2("bits set: %d/%d", bits_set, BN_num_bits(dh_p));

	/*
	 * if g==2 and bits_set==1 then computing log_g(dh_pub) is trivial
	 */
	if (bits_set < 4) {
		error("invalid public DH value (%d/%d)",
		    bits_set, BN_num_bits(dh_p));
		return 0;
	}
	return 1;
}


static int
dh_calc_length(struct kex *kex, DH *dh)
{
	int need, pbits;

	need = kex->we_need * 8; /*may overflow*/
	if (need < 0)
		return 0;

{	const BIGNUM *dh_p;
	DH_get0_pqg(dh, &dh_p, NULL, NULL);
	if (dh_p == NULL)
		return 0;
	pbits = BN_num_bits(dh_p);
}

	if (pbits <= 0 || need > INT_MAX / 2 || (2 * need) > pbits)
		return 0;

	if (need < 256) need = 256;

	/*
	 * Pollard Rho, Big step/Little Step attacks are O(sqrt(n)),
	 * so double requested need here.
	 */
	return MINIMUM(need * 2, pbits - 1);
}


int
kex_dh_key_gen(struct kex *kex)
{
	int r;
	DH *dh;

	if (kex->pk == NULL)
		return SSH_ERR_INVALID_ARGUMENT;

	dh = EVP_PKEY_get1_DH(kex->pk);
	if (dh == NULL)
		return SSH_ERR_INVALID_ARGUMENT;

{	int len = dh_calc_length(kex, dh);
	if (len <= 0) {
		r = SSH_ERR_INVALID_ARGUMENT;
		goto done;
	}
	if (!DH_set_length(dh, len)) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		goto done;
	}
}

	if (DH_generate_key(dh) == 0) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		goto done;
	}

{	const BIGNUM *pub_key;
	DH_get0_key(dh, &pub_key, NULL);
	if (!dh_pub_is_valid(dh, pub_key)) {
		r = SSH_ERR_INVALID_FORMAT;
		goto done;
	}
}

	/* success */
	r = 0;

done:
	DH_free(dh);
	return r;
}


static inline int
kex_new_dh_pkey(EVP_PKEY **pkp, DH *dh) {
	EVP_PKEY *pk = EVP_PKEY_new();

	if (pk == NULL)
		return SSH_ERR_ALLOC_FAIL;

	if (!EVP_PKEY_set1_DH(pk, dh)) {
		EVP_PKEY_free(pk);
		return SSH_ERR_LIBCRYPTO_ERROR;
	}

	*pkp = pk;
	return 0;
}


static int
kex_dh_key_init(struct kex *kex) {
	DH *dh;

	switch (kex->kex_type) {
	case KEX_DH_GRP1_SHA1:
		dh = _dh_new_group_num(1);
		break;
	case KEX_DH_GRP14_SHA1:
	case KEX_DH_GRP14_SHA256:
		dh = _dh_new_group_num(14);
		break;
	case KEX_DH_GRP16_SHA512:
		dh = _dh_new_group_num(16);
		break;
	case KEX_DH_GRP18_SHA512:
		dh = _dh_new_group_num(18);
		break;
	default:
		return SSH_ERR_INVALID_ARGUMENT;
	}
	if (dh == NULL) return SSH_ERR_ALLOC_FAIL;

{	int r = kex_new_dh_pkey(&kex->pk, dh);
	DH_free(dh);
	return r;
}
}


int
kex_dh_pkey_keygen(struct kex *kex) {
	int r = kex_dh_key_init(kex);
	if (r != 0) return r;
	return kex_dh_key_gen(kex);
}


void
kex_reset_crypto_keys(struct kex *kex) {
	EVP_PKEY_free(kex->pk);
	kex->pk = NULL;
}


/* TODO: internal */
extern DH* _choose_dh(int, int, int);

EVP_PKEY*
kex_new_dh_group_bits(int min, int wantbits, int max) {
	EVP_PKEY *pk = NULL;
	DH *dh = NULL;

	dh = _choose_dh(min, wantbits, max);
	if (dh == NULL) return NULL;

	(void)kex_new_dh_pkey(&pk, dh);

	DH_free(dh);
	return pk;
}

EVP_PKEY*
kex_new_dh_group(BIGNUM *modulus, BIGNUM *gen) {
	EVP_PKEY *pk = NULL;
	DH *dh = NULL;

	dh = _dh_new_group(modulus, gen);
	if (dh == NULL) return NULL;

	(void)kex_new_dh_pkey(&pk, dh);

	DH_free(dh);
	return pk;
}


static inline int
shared_secret_bn_to_sshbuf(const BIGNUM *shared_secret, struct sshbuf **bufp) {
	struct sshbuf *buf;
	int r;

	if ((buf = sshbuf_new()) == NULL)
		return SSH_ERR_ALLOC_FAIL;

	r = sshbuf_put_bignum2(buf, shared_secret);
	if (r == 0)
		*bufp = buf;
	else
		sshbuf_free(buf);
	return r;
}

int
kex_dh_shared_secret_to_sshbuf(u_char *kbuf, size_t klen, struct sshbuf **bufp) {
	BIGNUM *shared_secret;
	int r;

	shared_secret = BN_bin2bn(kbuf, klen, NULL);
	if (shared_secret == NULL)
		return SSH_ERR_LIBCRYPTO_ERROR;

	r = shared_secret_bn_to_sshbuf(shared_secret, bufp);

	BN_clear_free(shared_secret);
	return r;
}


#ifdef USE_EVP_PKEY_KEYGEN
int
kex_pkey_derive_shared_secret(struct kex *kex, EVP_PKEY *peerkey, struct sshbuf **bufp) {
	EVP_PKEY_CTX *ctx;
	u_char *kbuf = NULL;
	size_t klen = 0;
	int r = SSH_ERR_LIBCRYPTO_ERROR;

	ctx = EVP_PKEY_CTX_new(kex->pk, NULL);
	if (ctx == NULL) return SSH_ERR_INTERNAL_ERROR;

	if (EVP_PKEY_derive_init(ctx) != 1)
		goto out;

	if (EVP_PKEY_derive_set_peer(ctx, peerkey) != 1)
		goto out;

	if (EVP_PKEY_derive(ctx, NULL, &klen) != 1)
		goto out;
	kbuf = OPENSSL_malloc(klen);
	if (kbuf == NULL) {
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	if (EVP_PKEY_derive(ctx, kbuf, &klen) != 1)
		goto out;
#if defined(DEBUG_KEX) || defined(DEBUG_KEXDH) || defined(DEBUG_KEXECDH)
	dump_digest("shared secret", kbuf, klen);
#endif

	r = kex_dh_shared_secret_to_sshbuf(kbuf, klen, bufp);

 out:
	OPENSSL_clear_free(kbuf, klen);
	EVP_PKEY_CTX_free(ctx);
	return r;
}
#endif /*def USE_EVP_PKEY_KEYGEN*/


#ifdef USE_EVP_PKEY_KEYGEN
static DH*
_dh_new_group_pkey(EVP_PKEY *pk) {
	BIGNUM *dh_p, *dh_g;
	DH *dh;

{	const BIGNUM *modulus, *gen;

	dh = EVP_PKEY_get1_DH(pk);
	if (dh == NULL) return NULL;

	DH_get0_pqg(dh, &modulus, NULL, &gen);
	DH_free(dh);

	dh_p = BN_dup(modulus);
	dh_g = BN_dup(gen);
}

	if (dh_p == NULL || dh_g == NULL)
		goto err;

	dh = _dh_new_group(dh_p, dh_g);
	if (dh == NULL) goto err;

	return dh;

err:
	BN_free(dh_p);
	BN_free(dh_g);

	return NULL;
}


static int
create_peer_pkey(struct kex *kex, BIGNUM *dh_pub, EVP_PKEY **peerkeyp) {
	DH *peerdh;
	int r;

	peerdh = _dh_new_group_pkey(kex->pk);
	if (peerdh == NULL) return SSH_ERR_ALLOC_FAIL;

{	BIGNUM *pub_key = BN_dup(dh_pub);
	if (pub_key == NULL) {
		r = SSH_ERR_ALLOC_FAIL;
		goto done;
	}

	(void)DH_set0_key(peerdh, pub_key, NULL);
}

	r = kex_new_dh_pkey(peerkeyp, peerdh);

done:
	DH_free(peerdh);
	return r;
}
#endif /*def USE_EVP_PKEY_KEYGEN*/


#ifdef DEBUG_KEXDH
static void
DEBUG_DH_COMPUTE_KEY(struct kex *kex, BIGNUM *pub_key) {
	fprintf(stderr, "dh pub: ");
	BN_print_fp(stderr, pub_key);
	fprintf(stderr, "\n");
	fprintf(stderr, "bits %d\n", BN_num_bits(pub_key));
{	BIO *err = BIO_new_fp(stderr, BIO_NOCLOSE);
	EVP_PKEY_print_params(err, kex->pk, 0, NULL);
	BIO_free_all(err);
}
}
#else
static inline void
DEBUG_DH_COMPUTE_KEY(struct kex *kex, BIGNUM *pub_key) {
	UNUSED(kex); UNUSED(pub_key);
}
#endif


int
kex_dh_compute_key(struct kex *kex, BIGNUM *pub_key, struct sshbuf **shared_secretp)
{
#ifndef USE_EVP_PKEY_KEYGEN
	DH *dh;
	int klen;
	u_char *kbuf = NULL;
	int r;

	DEBUG_DH_COMPUTE_KEY(kex, pub_key);

	dh = EVP_PKEY_get1_DH(kex->pk);
	if (dh == NULL)
		return SSH_ERR_INVALID_ARGUMENT;

	if (!dh_pub_is_valid(dh, pub_key))
		return SSH_ERR_MESSAGE_INCOMPLETE;

	/* NOTE EVP_PKEY_size fail for DH key if OpenSSL < 1.0.0 */
	klen = DH_size(dh);

	kbuf = malloc(klen);
	if (kbuf == NULL) {
		r = SSH_ERR_ALLOC_FAIL;
		goto done;
	}

{	int kout = DH_compute_key(kbuf, pub_key, dh);
	if (kout < 0) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		goto done;
	}
#ifdef DEBUG_KEXDH
	dump_digest("shared secret", kbuf, kout);
#endif

	r = kex_dh_shared_secret_to_sshbuf(kbuf, kout, shared_secretp);
}

done:
	freezero(kbuf, klen);
	DH_free(dh);
#else /*def USE_EVP_PKEY_KEYGEN*/
	EVP_PKEY *peerkey = NULL;
	int r;

	DEBUG_DH_COMPUTE_KEY(kex, pub_key);

	r = create_peer_pkey(kex, pub_key, &peerkey);
	if (r != 0) return r;

	r = kex_pkey_derive_shared_secret(kex, peerkey, shared_secretp);

	EVP_PKEY_free(peerkey);
#endif /*def USE_EVP_PKEY_KEYGEN*/
	return r;
}


int
sshbuf_kex_write_dh_group(struct sshbuf *buf, EVP_PKEY *pk) {
	int r;
	DH *dh;

	dh = EVP_PKEY_get1_DH(pk);
	if (dh == NULL)
		return SSH_ERR_INVALID_ARGUMENT;

{	const BIGNUM *p = NULL, *g = NULL;
	DH_get0_pqg(dh, &p, NULL, &g);

	if ((r = sshbuf_put_bignum2(buf, p)) != 0)
		goto done;
	r = sshbuf_put_bignum2(buf, g);
}

done:
	DH_free(dh);
	return r;
}

int
sshbuf_kex_write_dh_pub(struct sshbuf *buf, EVP_PKEY *pk) {
	int r;
	DH *dh;

	dh = EVP_PKEY_get1_DH(pk);
	if (dh == NULL)
		return SSH_ERR_INVALID_ARGUMENT;

{	const BIGNUM *pub_key;
	DH_get0_key(dh, &pub_key, NULL);
#ifdef DEBUG_KEXDH
	fprintf(stderr, "dh pub: ");
	BN_print_fp(stderr, pub_key);
	fprintf(stderr, "\n");
	fprintf(stderr, "bits %d\n", BN_num_bits(pub_key));
{	BIO *err = BIO_new_fp(stderr, BIO_NOCLOSE);
	EVP_PKEY_print_params(err, pk, 0, NULL);
	BIO_free_all(err);
}
#endif

	r = sshbuf_put_bignum2(buf, pub_key);
}
	DH_free(dh);
	return r;
}


int
kexgex_hash_client(const struct kex *kex,
    const struct sshbuf *key_blob, const BIGNUM *peer_pub,
    const struct sshbuf *shared_secret,
    u_char *hash, size_t *hashlen
) {
	int r;
	DH *dh;
	const BIGNUM *my_pub, *dh_p, *dh_g;

	dh = EVP_PKEY_get1_DH(kex->pk);
	if (dh == NULL)
		return SSH_ERR_INVALID_ARGUMENT;

	DH_get0_key(dh, &my_pub, NULL);
	DH_get0_pqg(dh, &dh_p, NULL, &dh_g);

	r = kexgex_hash(kex->hash_alg,
	    kex->client_version, kex->server_version,
	    kex->my, kex->peer, key_blob,
	    kex->min, kex->nbits, kex->max,
	    dh_p, dh_g, my_pub, peer_pub,
	    sshbuf_ptr(shared_secret), sshbuf_len(shared_secret),
	    hash, hashlen);

	DH_free(dh);
	return r;
}

int
kexgex_hash_server(const struct kex *kex,
    const struct sshbuf *key_blob, const BIGNUM *peer_pub,
    const struct sshbuf *shared_secret,
    u_char *hash, size_t *hashlen
) {
	int r;
	DH *dh;
	const BIGNUM *my_pub, *dh_p, *dh_g;

	dh = EVP_PKEY_get1_DH(kex->pk);
	if (dh == NULL)
		return SSH_ERR_INVALID_ARGUMENT;

	DH_get0_key(dh, &my_pub, NULL);
	DH_get0_pqg(dh, &dh_p, NULL, &dh_g);

	r = kexgex_hash(kex->hash_alg,
	    kex->client_version, kex->server_version,
	    kex->peer, kex->my, key_blob,
	    kex->min, kex->nbits, kex->max,
	    dh_p, dh_g, peer_pub, my_pub,
	    sshbuf_ptr(shared_secret), sshbuf_len(shared_secret),
	    hash, hashlen);

	DH_free(dh);
	return r;
}
#else

typedef int kex_crypto_empty_translation_unit;

#endif /* WITH_OPENSSL */
