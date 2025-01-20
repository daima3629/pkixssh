/* $OpenBSD: kexdh.c,v 1.34 2020/12/04 02:29:25 djm Exp $ */
/*
 * Copyright (c) 2019 Markus Friedl.  All rights reserved.
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

#include "includes.h"

#include "kex.h"
#include "digest.h"
#ifdef ENABLE_KEX_DH
#include "dh-crypto.h"
#include "ssherr.h"
#include "log.h"

extern DH* _choose_dh(int, int, int);
extern DH* dh_new_group(BIGNUM *, BIGNUM *);
extern DH* _dh_new_group_num(int);


struct kex_dh_spec {
	int	dh_group;
};


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
	DUMP_DH_KEY(pk, pub_key);

	r = sshbuf_put_bignum2(buf, pub_key);
}
	DH_free(dh);
	return r;
}

static int
kex_dh_to_sshbuf(struct kex *kex, struct sshbuf **bufp) {
	struct sshbuf *buf;
	int r;

	if ((buf = sshbuf_new()) == NULL)
		return SSH_ERR_ALLOC_FAIL;
	if ((r = sshbuf_kex_write_dh_pub(buf, kex->pk)) != 0 ||
	    (r = sshbuf_get_u32(buf, NULL)) != 0)
		goto out;

	*bufp = buf;
	buf = NULL;

 out:
	sshbuf_free(buf);
	return r;
}


static int
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

	dh = dh_new_group(modulus, gen);
	if (dh == NULL) return NULL;

	(void)kex_new_dh_pkey(&pk, dh);

	DH_free(dh);
	return pk;
}


static int
kex_dh_key_init(struct kex *kex) {
	DH *dh;

{	struct kex_dh_spec *spec = kex->impl->spec;
	dh = _dh_new_group_num(spec->dh_group);
}
	if (dh == NULL) return SSH_ERR_ALLOC_FAIL;

{	int r = kex_new_dh_pkey(&kex->pk, dh);
	DH_free(dh);
	return r;
}
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
kex_dh_pkey_keygen(struct kex *kex) {
	int r = kex_dh_key_init(kex);
	if (r != 0) return r;
	return kex_dh_key_gen(kex);
}


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


/* diffie-hellman key exchange implementation */

static int
kex_dh_dec(struct kex *kex, const struct sshbuf *dh_blob,
    struct sshbuf **shared_secretp);


static int
kex_dh_keypair(struct kex *kex)
{
	int r;

	r = kex_dh_pkey_keygen(kex);
	if (r != 0) return r;

	r = kex_dh_to_sshbuf(kex, &kex->client_pub);
#ifdef DEBUG_KEXDH
	dump_digestb("client public keypair dh:", kex->client_pub);
#endif

	if (r != 0)
		kex_reset_keys(kex);
	return r;
}

static int
kex_dh_enc(struct kex *kex, const struct sshbuf *client_blob,
    struct sshbuf **server_blobp, struct sshbuf **shared_secretp)
{
	int r;

	*server_blobp = NULL;
	*shared_secretp = NULL;

#ifdef DEBUG_KEXDH
	dump_digestb("client public key dh:", client_blob);
#endif
	r = kex_dh_pkey_keygen(kex);
	if (r != 0) return r;

	r = kex_dh_to_sshbuf(kex, server_blobp);
	if (r != 0) goto out;

	r = kex_dh_dec(kex, client_blob, shared_secretp);

 out:
	kex_reset_keys(kex);
	if (r != 0) {
		sshbuf_free(*server_blobp);
		*server_blobp = NULL;
	}
	return r;
}

static int
kex_dh_dec(struct kex *kex, const struct sshbuf *dh_blob,
    struct sshbuf **shared_secretp)
{
	BIGNUM *dh_pub = NULL;
	int r;

	*shared_secretp = NULL;
#ifdef DEBUG_KEXDH
	dump_digestb("server public key dh:", dh_blob);
#endif

	r = sshbuf_to_dhpub(dh_blob, &dh_pub);
	if (r != 0) return r;

	r = kex_dh_compute_key(kex, dh_pub, shared_secretp);
#ifdef DEBUG_KEXDH
	if (r == 0)
		dump_digestb("encoded shared secret:", *shared_secretp);
#endif

	kex_reset_keys(kex);
	BN_free(dh_pub);
	return r;
}

static int kex_dh_sha1_enabled(void) { return 1; }
# ifdef HAVE_EVP_SHA256
static int kex_dh_sha2_enabled(void) { return 1; }
# else
static int kex_dh_sha2_enabled(void) { return 0; }
# endif
# ifdef USE_BN_GET_RFC_PRIME
static int kex_dh_gr3k_enabled(void) { return 1; }
# else
static int kex_dh_gr3k_enabled(void) { return 0; }
# endif

static const struct kex_impl_funcs kex_dh_funcs = {
	kex_init_gen,
	kex_dh_keypair,
	kex_dh_enc,
	kex_dh_dec
};

static struct kex_dh_spec kex_dh_grp1_spec = {
	1
};
const struct kex_impl kex_dh_grp1_sha1_impl = {
	"diffie-hellman-group1-sha1",
	SSH_DIGEST_SHA1,
	kex_dh_sha1_enabled,
	&kex_dh_funcs,
	&kex_dh_grp1_spec
};

static struct kex_dh_spec kex_dh_grp14_spec = {
	14
};
const struct kex_impl kex_dh_grp14_sha1_impl = {
	"diffie-hellman-group14-sha1",
	SSH_DIGEST_SHA1,
	kex_dh_sha1_enabled,
	&kex_dh_funcs,
	&kex_dh_grp14_spec
};

const struct kex_impl kex_dh_grp14_sha256_impl = {
	"diffie-hellman-group14-sha256",
	SSH_DIGEST_SHA256,
	kex_dh_sha2_enabled,
	&kex_dh_funcs,
	&kex_dh_grp14_spec
};

static struct kex_dh_spec kex_dh_grp16_spec = {
	16
};
const struct kex_impl kex_dh_grp16_sha512_impl = {
	"diffie-hellman-group16-sha512",
	SSH_DIGEST_SHA512,
	kex_dh_sha2_enabled,
	&kex_dh_funcs,
	&kex_dh_grp16_spec
};

static struct kex_dh_spec kex_dh_grp18_spec = {
	18
};
const struct kex_impl kex_dh_grp18_sha512_impl = {
	"diffie-hellman-group18-sha512",
	SSH_DIGEST_SHA512,
	kex_dh_sha2_enabled,
	&kex_dh_funcs,
	&kex_dh_grp18_spec
};

static struct kex_dh_spec kex_dh_grp15_spec = {
	15
};
const struct kex_impl kex_dh_grp15_sha512_impl = {
	"diffie-hellman-group15-sha512",
	SSH_DIGEST_SHA512,
	kex_dh_gr3k_enabled,
	&kex_dh_funcs,
	&kex_dh_grp15_spec
};

static struct kex_dh_spec kex_dh_grp17_spec = {
	17
};
const struct kex_impl kex_dh_grp17_sha512_impl = {
	"diffie-hellman-group17-sha512",
	SSH_DIGEST_SHA512,
	kex_dh_gr3k_enabled,
	&kex_dh_funcs,
	&kex_dh_grp17_spec
};
#else /*ndef ENABLE_KEX_DH*/

static int kex_dh_enabled(void) { return 0; }

const struct kex_impl kex_dh_grp1_sha1_impl = {
	"diffie-hellman-group1-sha1", SSH_DIGEST_SHA1,
	kex_dh_enabled, NULL, NULL,
};
const struct kex_impl kex_dh_grp14_sha1_impl = {
	"diffie-hellman-group14-sha1", SSH_DIGEST_SHA1,
	kex_dh_enabled, NULL, NULL,
};
const struct kex_impl kex_dh_grp14_sha256_impl = {
	"diffie-hellman-group14-sha256", SSH_DIGEST_SHA256,
	kex_dh_enabled, NULL, NULL,
};
const struct kex_impl kex_dh_grp16_sha512_impl = {
	"diffie-hellman-group16-sha512", SSH_DIGEST_SHA512,
	kex_dh_enabled, NULL, NULL,
};
const struct kex_impl kex_dh_grp18_sha512_impl = {
	"diffie-hellman-group18-sha512", SSH_DIGEST_SHA512,
	kex_dh_enabled, NULL, NULL,
};
const struct kex_impl kex_dh_grp15_sha512_impl = {
	"diffie-hellman-group15-sha512", SSH_DIGEST_SHA512,
	kex_dh_enabled, NULL, NULL,
};
const struct kex_impl kex_dh_grp17_sha512_impl = {
	"diffie-hellman-group17-sha512", SSH_DIGEST_SHA512,
	kex_dh_enabled, NULL, NULL,
};

#endif /*ndef ENABLE_KEX_DH*/
