/* $OpenBSD: kexsntrup761x25519.c,v 1.3 2024/09/15 02:20:51 djm Exp $ */
/*
 * Copyright (c) 2019 Markus Friedl.  All rights reserved.
 * Copyright (c) 2024-2025 Roumen Petrov.  All rights reserved.
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

#include <sys/types.h>

#include <stdio.h>
#include <string.h>

#include "kex.h"
#include "digest.h"
#ifdef ENABLE_KEX_SNTRUP761X25519
#include "sshkey.h"
#include "sshbuf.h"
#include "ssherr.h"

volatile crypto_int16 crypto_int16_optblocker = 0;
volatile crypto_int32 crypto_int32_optblocker = 0;
volatile crypto_int64 crypto_int64_optblocker = 0;

/* NTRU Prime post-quantum key exchange implementation */

static int
kex_kem_sntrup761x25519_keypair(struct kex *kex)
{
	struct sshbuf *buf = NULL;
	u_char *cp = NULL;
	size_t need;
	int r;

	if ((buf = sshbuf_new()) == NULL)
		return SSH_ERR_ALLOC_FAIL;
	need = crypto_kem_sntrup761_PUBLICKEYBYTES;
	if ((r = sshbuf_reserve(buf, need, &cp)) != 0)
		goto out;
	crypto_kem_sntrup761_keypair(cp, kex->sntrup761_client_key);
#ifdef DEBUG_KEXKEM
	dump_digest("client public keypair sntrup761:", cp,
	    crypto_kem_sntrup761_PUBLICKEYBYTES);
#endif

	r = kex_c25519_keygen_to_sshbuf(kex, &buf);
	if (r != 0) goto out;

	/* success */
	kex->client_pub = buf;
	buf = NULL;
 out:
	sshbuf_free(buf);
	return r;
}

static int
kex_kem_sntrup761x25519_enc(struct kex *kex,
   const struct sshbuf *client_blob, struct sshbuf **server_blobp,
   struct sshbuf **shared_secretp)
{
	struct sshbuf *server_blob = NULL;
	struct sshbuf *buf = NULL;
	const u_char *client_pub;
	u_char *ciphertext;
	int r;

	*server_blobp = NULL;
	*shared_secretp = NULL;

	/* client_blob contains both KEM and ECDH client pubkeys */
{	size_t need = crypto_kem_sntrup761_PUBLICKEYBYTES + CURVE25519_SIZE;
	if (sshbuf_len(client_blob) != need) {
		r = SSH_ERR_SIGNATURE_INVALID;
		goto out;
	}
}
	client_pub = sshbuf_ptr(client_blob);
#ifdef DEBUG_KEXKEM
	dump_digest("client public key sntrup761:", client_pub,
	    crypto_kem_sntrup761_PUBLICKEYBYTES);
	dump_digest("client public key c25519:",
	    client_pub + crypto_kem_sntrup761_PUBLICKEYBYTES,
	    CURVE25519_SIZE);
#endif
	/* allocate buffer for concatenation of KEM key and ECDH shared key */
	/* the buffer will be hashed and the result is the shared secret */
	if ((buf = sshbuf_new()) == NULL) {
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	/* allocate space for encrypted KEM key and ECDH pub key */
	if ((server_blob = sshbuf_new()) == NULL) {
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
{	size_t need = crypto_kem_sntrup761_CIPHERTEXTBYTES;
	if ((r = sshbuf_reserve(server_blob, need, &ciphertext)) != 0)
		goto out;
}
	/* generate and encrypt KEM key with client key */
{	u_char *kem_key;
	if ((r = sshbuf_reserve(buf, crypto_kem_sntrup761_BYTES,
	    &kem_key)) != 0)
		goto out;
	crypto_kem_sntrup761_enc(ciphertext, kem_key, client_pub);
#ifdef DEBUG_KEXKEM
	dump_digest("server kem key:", kem_key, crypto_kem_sntrup761_BYTES);
#endif
}
	/* generate ECDH key pair, store server pubkey after ciphertext */
	r = kex_c25519_keygen_to_sshbuf(kex, &server_blob);
	if (r != 0) goto out;

	/* append ECDH shared key */
	client_pub += crypto_kem_sntrup761_PUBLICKEYBYTES;
	r = kex_c25519_shared_secret_to_sshbuf(kex, client_pub, 1, &buf);
	if (r != 0) goto out;

#ifdef DEBUG_KEXKEM
	dump_digest("server cipher text:", ciphertext,
	    crypto_kem_sntrup761_CIPHERTEXTBYTES);
	dump_digestb("concatenation of KEM and ECDH public part:", server_blob);
	dump_digestb("concatenation of KEM and ECDH shared key:", buf);
#endif
	/* string-encoded hash is resulting shared secret */
	r = kex_digest_buffer(kex->impl->hash_alg, buf, shared_secretp);
#ifdef DEBUG_KEXKEM
	if (r == 0)
		dump_digestb("encoded shared secret:", *shared_secretp);
	else
		fprintf(stderr, "shared secret error: %s\n", ssh_err(r));
#endif
	if (r == 0) {
		*server_blobp = server_blob;
		server_blob = NULL;
	}
 out:
	kex_reset_keys(kex);
	sshbuf_free(server_blob);
	sshbuf_free(buf);
	return r;
}

static int
kex_kem_sntrup761x25519_dec(struct kex *kex,
    const struct sshbuf *server_blob, struct sshbuf **shared_secretp)
{
	struct sshbuf *buf = NULL;
	const u_char *ciphertext, *server_pub;
	int r, decoded;

	*shared_secretp = NULL;

{	size_t need = crypto_kem_sntrup761_CIPHERTEXTBYTES + CURVE25519_SIZE;
	if (sshbuf_len(server_blob) != need) {
		r = SSH_ERR_SIGNATURE_INVALID;
		goto out;
	}
}
	ciphertext = sshbuf_ptr(server_blob);
	server_pub = ciphertext + crypto_kem_sntrup761_CIPHERTEXTBYTES;
#ifdef DEBUG_KEXKEM
	dump_digest("server cipher text:", ciphertext,
	    crypto_kem_sntrup761_CIPHERTEXTBYTES);
	dump_digest("server public key c25519:", server_pub, CURVE25519_SIZE);
#endif
	/* hash concatenation of KEM key and ECDH shared key */
	if ((buf = sshbuf_new()) == NULL) {
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}

{	u_char *kem_key = NULL;
	if ((r = sshbuf_reserve(buf, crypto_kem_sntrup761_BYTES,
	    &kem_key)) != 0)
		goto out;
	decoded = crypto_kem_sntrup761_dec(kem_key, ciphertext,
	    kex->sntrup761_client_key);
#ifdef DEBUG_KEXKEM
	/* TODO: if decapsulation fail? */
	dump_digest("client kem key:", kem_key, crypto_kem_sntrup761_BYTES);
#endif
}

	r = kex_c25519_shared_secret_to_sshbuf(kex, server_pub, 1, &buf);
	if (r != 0) goto out;
#ifdef DEBUG_KEXKEM
	dump_digestb("concatenation of KEM key and ECDH shared key:", buf);
#endif
	r = kex_digest_buffer(kex->impl->hash_alg, buf, shared_secretp);
#ifdef DEBUG_KEXKEM
	if (r == 0)
		dump_digestb("encoded shared secret:", *shared_secretp);
	else
		fprintf(stderr, "shared secret error: %s\n", ssh_err(r));
#endif
	if (decoded != 0) {
		if (r != 0) {
			sshbuf_free(*shared_secretp);
			*shared_secretp = NULL;
		}
		r = SSH_ERR_SIGNATURE_INVALID;
	}
 out:
	kex_reset_keys(kex);
	sshbuf_free(buf);
	return r;
}

static int kex_kem_sntrup761x25519_enabled(void) { return 1; }

static const struct kex_impl_funcs kex_kem_sntrup761x25519_funcs = {
	kex_init_gen,
	kex_kem_sntrup761x25519_keypair,
	kex_kem_sntrup761x25519_enc,
	kex_kem_sntrup761x25519_dec
};

const struct kex_impl kex_kem_sntrup761x25519_sha512_impl = {
	"sntrup761x25519-sha512",
	SSH_DIGEST_SHA512,
	kex_kem_sntrup761x25519_enabled,
	&kex_kem_sntrup761x25519_funcs,
	NULL
};

const struct kex_impl kex_kem_sntrup761x25519_sha512_impl_ext = {
	"sntrup761x25519-sha512@openssh.com",
	SSH_DIGEST_SHA512,
	kex_kem_sntrup761x25519_enabled,
	&kex_kem_sntrup761x25519_funcs,
	NULL
};
#else /* ENABLE_KEX_SNTRUP761X25519 */

static int kex_kem_sntrup761x25519_enabled(void) { return 0; }
const struct kex_impl kex_kem_sntrup761x25519_sha512_impl = {
	"sntrup761x25519-sha512", SSH_DIGEST_SHA512,
	kex_kem_sntrup761x25519_enabled, NULL, NULL
};
const struct kex_impl kex_kem_sntrup761x25519_sha512_impl_ext = {
	"sntrup761x25519-sha512@openssh.com", SSH_DIGEST_SHA512,
	kex_kem_sntrup761x25519_enabled, NULL, NULL
};

#endif /* ENABLE_KEX_SNTRUP761X25519 */
