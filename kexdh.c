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

#ifdef WITH_OPENSSL

#ifndef USE_OPENSSL_PROVIDER
/* TODO: implement OpenSSL 4.0 API, as OpenSSL 3.* is quite nonfunctional */
# define OPENSSL_SUPPRESS_DEPRECATED
#endif

#include "includes.h"

#include "kex.h"
#include "digest.h"
#include "ssherr.h"
#include "misc.h"

extern DH* _choose_dh(int, int, int);
extern DH* _dh_new_group(BIGNUM *, BIGNUM *);
extern DH* _dh_new_group_num(int);


struct kex_dh_spec {
	int	dh_group;
};


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


extern int/*internal*/
kex_new_dh_pkey(EVP_PKEY **pkp, DH *dh);

int
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

	dh = _dh_new_group(modulus, gen);
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


static inline int
kex_dh_pkey_keygen(struct kex *kex) {
	int r = kex_dh_key_init(kex);
	if (r != 0) return r;
	return kex_dh_key_gen(kex);
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
#endif /* WITH_OPENSSL */
