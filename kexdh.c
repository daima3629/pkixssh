/* $OpenBSD: kexdh.c,v 1.34 2020/12/04 02:29:25 djm Exp $ */
/*
 * Copyright (c) 2019 Markus Friedl.  All rights reserved.
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

#include "includes.h"

#ifdef WITH_OPENSSL

#include "kex.h"
#include "digest.h"
#include "ssherr.h"
#include "misc.h"

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


/* diffie-hellman key exchange implementation */

static int
kex_dh_dec(struct kex *kex, const struct sshbuf *dh_blob,
    struct sshbuf **shared_secretp);


static int
kex_dh_keypair(struct kex *kex)
{
	struct sshbuf *buf = NULL;
	int r;

	if ((r = kex_dh_pkey_keygen(kex)) != 0)
		goto out;

	r = kex_dh_to_sshbuf(kex, &kex->client_pub);
#ifdef DEBUG_KEXDH
	dump_digestb("client public keypair dh:", kex->client_pub);
#endif

 out:
	if (r != 0)
		kex_reset_crypto_keys(kex);
	sshbuf_free(buf);
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
	if ((r = kex_dh_pkey_keygen(kex)) != 0 ||
	    (r = kex_dh_to_sshbuf(kex, server_blobp)) != 0)
		goto out;

	r = kex_dh_dec(kex, client_blob, shared_secretp);

 out:
	if (r != 0) {
		sshbuf_free(*server_blobp);
		*server_blobp = NULL;
	}
	kex_reset_crypto_keys(kex);
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

	BN_free(dh_pub);
	kex_reset_crypto_keys(kex);
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

const struct kex_impl kex_dh_grp1_sha1_impl = {
	KEX_DH_GRP1_SHA1,
	"diffie-hellman-group1-sha1",
	SSH_DIGEST_SHA1,
	kex_dh_sha1_enabled,
	&kex_dh_funcs,
	NULL
};

const struct kex_impl kex_dh_grp14_sha1_impl = {
	KEX_DH_GRP14_SHA1,
	"diffie-hellman-group14-sha1",
	SSH_DIGEST_SHA1,
	kex_dh_sha1_enabled,
	&kex_dh_funcs,
	NULL
};

const struct kex_impl kex_dh_grp14_sha256_impl = {
	KEX_DH_GRP14_SHA256,
	"diffie-hellman-group14-sha256",
	SSH_DIGEST_SHA256,
	kex_dh_sha2_enabled,
	&kex_dh_funcs,
	NULL
};

const struct kex_impl kex_dh_grp16_sha512_impl = {
	KEX_DH_GRP16_SHA512,
	"diffie-hellman-group16-sha512",
	SSH_DIGEST_SHA512,
	kex_dh_sha2_enabled,
	&kex_dh_funcs,
	NULL
};

const struct kex_impl kex_dh_grp18_sha512_impl = {
	KEX_DH_GRP18_SHA512,
	"diffie-hellman-group18-sha512",
	SSH_DIGEST_SHA512,
	kex_dh_sha2_enabled,
	&kex_dh_funcs,
	NULL
};
#endif /* WITH_OPENSSL */
