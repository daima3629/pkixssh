/* $OpenBSD: kexdh.c,v 1.33 2020/05/08 05:13:14 djm Exp $ */
/*
 * Copyright (c) 2019 Markus Friedl.  All rights reserved.
 * Copyright (c) 2021 Roumen Petrov.  All rights reserved.
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

#include <signal.h>
#include <stdio.h>
#include <string.h>

#include "dh.h"
#include "kex.h"
#include "ssherr.h"
#include "misc.h"


int
kex_dh_compute_key(struct kex *kex, BIGNUM *dh_pub, struct sshbuf *out)
{
	BIGNUM *shared_secret = NULL;
	u_char *kbuf = NULL;
	size_t klen = 0;
	int kout, r;

#ifdef DEBUG_KEXDH
	fprintf(stderr, "dh pub: ");
	BN_print_fp(stderr, dh_pub);
	fprintf(stderr, "\n");
	fprintf(stderr, "bits %d\n", BN_num_bits(dh_pub));
{	BIO *err = BIO_new_fp(stderr, BIO_NOCLOSE);
	EVP_PKEY_print_params(err, kex->pk, 0, NULL);
	BIO_free_all(err);
}
#endif

	if (!dh_pub_is_valid(kex->dh, dh_pub)) {
		r = SSH_ERR_MESSAGE_INCOMPLETE;
		goto out;
	}
	klen = DH_size(kex->dh);
	if ((kbuf = malloc(klen)) == NULL ||
	    (shared_secret = BN_new()) == NULL) {
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	if ((kout = DH_compute_key(kbuf, dh_pub, kex->dh)) < 0 ||
	    BN_bin2bn(kbuf, kout, shared_secret) == NULL) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		goto out;
	}
#ifdef DEBUG_KEXDH
	dump_digest("shared secret", kbuf, kout);
#endif
	r = sshbuf_put_bignum2(out, shared_secret);
 out:
	freezero(kbuf, klen);
	BN_clear_free(shared_secret);
	return r;
}

int
kex_dh_keypair(struct kex *kex)
{
	struct sshbuf *buf = NULL;
	int r;

	if ((r = kex_key_init_dh(kex)) != 0 ||
	    (r = kex_key_gen_dh(kex)) != 0)
		return r;
	if ((buf = sshbuf_new()) == NULL)
		return SSH_ERR_ALLOC_FAIL;
	if ((r = sshbuf_kex_write_dh_pub(buf, kex->pk)) != 0 ||
	    (r = sshbuf_get_u32(buf, NULL)) != 0)
		goto out;
	kex->client_pub = buf;
	buf = NULL;
 out:
	sshbuf_free(buf);
	return r;
}

int
kex_dh_enc(struct kex *kex, const struct sshbuf *client_blob,
    struct sshbuf **server_blobp, struct sshbuf **shared_secretp)
{
	struct sshbuf *server_blob = NULL;
	int r;

	*server_blobp = NULL;
	*shared_secretp = NULL;

	if ((r = kex_key_init_dh(kex)) != 0 ||
	    (r = kex_key_gen_dh(kex)) != 0)
		goto out;
	if ((server_blob = sshbuf_new()) == NULL) {
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	if ((r = sshbuf_kex_write_dh_pub(server_blob, kex->pk)) != 0 ||
	    (r = sshbuf_get_u32(server_blob, NULL)) != 0)
		goto out;
	if ((r = kex_dh_dec(kex, client_blob, shared_secretp)) != 0)
		goto out;
	*server_blobp = server_blob;
	server_blob = NULL;
 out:
	kex_reset_crypto_keys(kex);
	sshbuf_free(server_blob);
	return r;
}

int
kex_dh_dec(struct kex *kex, const struct sshbuf *dh_blob,
    struct sshbuf **shared_secretp)
{
	struct sshbuf *buf = NULL;
	BIGNUM *dh_pub = NULL;
	int r;

	*shared_secretp = NULL;

	if ((buf = sshbuf_new()) == NULL) {
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	if ((r = sshbuf_put_stringb(buf, dh_blob)) != 0 ||
	    (r = sshbuf_get_bignum2(buf, &dh_pub)) != 0)
		goto out;
	sshbuf_reset(buf);
	if ((r = kex_dh_compute_key(kex, dh_pub, buf)) != 0)
		goto out;
	*shared_secretp = buf;
	buf = NULL;
 out:
	BN_free(dh_pub);
	kex_reset_crypto_keys(kex);
	sshbuf_free(buf);
	return r;
}
#endif /* WITH_OPENSSL */
