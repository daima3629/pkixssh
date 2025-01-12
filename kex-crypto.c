/*
 * Copyright (c) 2021-2025 Roumen Petrov.  All rights reserved.
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
#include "dh-crypto.h"
#include "ssherr.h"
#include "misc.h"
#include "log.h"

extern DH* dh_new_group(BIGNUM *, BIGNUM *);


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


extern void/*internal*/
kex_reset_crypto_keys(struct kex *kex);

void
kex_reset_crypto_keys(struct kex *kex) {
	EVP_PKEY_free(kex->pk);
	kex->pk = NULL;
}


#ifdef USE_EVP_PKEY_KEYGEN
int
kex_pkey_derive_shared_secret_raw(struct kex *kex, EVP_PKEY *peerkey,
    u_char **kbufp, size_t *klenp
) {
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
	if (EVP_PKEY_derive(ctx, kbuf, &klen) != 1) {
		OPENSSL_free(kbuf);
		goto out;
	}
#if defined(DEBUG_KEX) || defined(DEBUG_KEXDH) || defined(DEBUG_KEXECDH) || \
    defined(DEBUG_KEXECX) || defined(DEBUG_KEXKEM)
	dump_digest("shared secret", kbuf, klen);
#endif

	*klenp = klen;
	*kbufp = kbuf;
	r = 0;

 out:
	EVP_PKEY_CTX_free(ctx);
	return r;
}
#endif /*def USE_EVP_PKEY_KEYGEN*/


#ifdef USE_EVP_PKEY_KEYGEN
int
kex_pkey_derive_shared_secret(struct kex *kex, EVP_PKEY *peerkey,
    int raw, struct sshbuf **bufp
) {
	u_char *kbuf = NULL;
	size_t klen = 0;
	int r = SSH_ERR_LIBCRYPTO_ERROR;

	r =  kex_pkey_derive_shared_secret_raw(kex, peerkey,
	    &kbuf, &klen);
	if (r != 0) goto out;

	r = kex_shared_secret_to_sshbuf(kbuf, klen, raw, bufp);

 out:
	OPENSSL_clear_free(kbuf, klen);
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

	dh = dh_new_group(dh_p, dh_g);
	if (dh == NULL) goto err;

	return dh;

err:
	BN_free(dh_p);
	BN_free(dh_g);

	return NULL;
}


extern int/*internal*/
kex_new_dh_pkey(EVP_PKEY **pkp, DH *dh);

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
DUMP_DH_KEY(const EVP_PKEY *pk, const BIGNUM *pub_key) {
	fprintf(stderr, "dh pub: ");
	BN_print_fp(stderr, pub_key);
	fprintf(stderr, "\n");
	fprintf(stderr, "bits %d\n", BN_num_bits(pub_key));
{	BIO *err = BIO_new_fp(stderr, BIO_NOCLOSE);
	EVP_PKEY_print_params(err, pk, 0, NULL);
	BIO_free_all(err);
}
}
#else
static inline void
DUMP_DH_KEY(const EVP_PKEY *pk, const BIGNUM *pub_key) {
	UNUSED(pk); UNUSED(pub_key);
}
#endif


int
kex_dh_compute_key(struct kex *kex, BIGNUM *pub_key, struct sshbuf **shared_secretp)
{
#ifdef USE_EVP_PKEY_KEYGEN
	EVP_PKEY *peerkey = NULL;
	int r;

	DUMP_DH_KEY(kex->pk, pub_key);

	r = create_peer_pkey(kex, pub_key, &peerkey);
	if (r != 0) return r;

	r = kex_pkey_derive_shared_secret(kex, peerkey, 0, shared_secretp);

	EVP_PKEY_free(peerkey);
#else /*ndef USE_EVP_PKEY_KEYGEN*/
	DH *dh;
	int klen;
	u_char *kbuf = NULL;
	int r;

	DUMP_DH_KEY(kex->pk, pub_key);

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

	r = kex_shared_secret_to_sshbuf(kbuf, kout, 0, shared_secretp);
}

done:
	freezero(kbuf, klen);
	DH_free(dh);
#endif /*ndef USE_EVP_PKEY_KEYGEN*/
	return r;
}
#else

typedef int kex_crypto_empty_translation_unit;

#endif /* WITH_OPENSSL */
