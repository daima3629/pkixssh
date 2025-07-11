/* $OpenBSD: kexmlkem768x25519.c,v 1.2 2024/10/27 02:06:59 djm Exp $ */
/*
 * Copyright (c) 2023 Markus Friedl.  All rights reserved.
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
#ifdef HAVE_STDINT_H
# include <stdint.h>
#endif
#include <stdbool.h>
#include <string.h>
#ifdef HAVE_ENDIAN_H
# include <endian.h>
#endif

#include "kex.h"
#include "digest.h"
#ifdef ENABLE_KEX_MLKEM768X25519
#include "sshkey.h"
#include "sshbuf.h"
#include "ssherr.h"
#include "log.h"

#if HAVE_DECL_LE32TOH == 0 || \
    HAVE_DECL_LE64TOH == 0 || \
    HAVE_DECL_HTOLE64 == 0
# define compat_swap32(v)					\
	(uint32_t)(((uint32_t)(v) & 0xff) << 24 |		\
	((uint32_t)(v) & 0xff00) << 8 |				\
	((uint32_t)(v) & 0xff0000) >> 8 |			\
	((uint32_t)(v) & 0xff000000) >> 24)
# define compat_swap64(v)					\
	(uint64_t)((((uint64_t)(v) & 0xff) << 56) |		\
	((uint64_t)(v) & 0xff00ULL) << 40 |			\
	((uint64_t)(v) & 0xff0000ULL) << 24 |			\
	((uint64_t)(v) & 0xff000000ULL) << 8 |		\
	((uint64_t)(v) & 0xff00000000ULL) >> 8 |		\
	((uint64_t)(v) & 0xff0000000000ULL) >> 24 |		\
	((uint64_t)(v) & 0xff000000000000ULL) >> 40 |		\
	((uint64_t)(v) & 0xff00000000000000ULL) >> 56)
# ifdef WORDS_BIGENDIAN
#  if HAVE_DECL_LE32TOH == 0
#   define le32toh(v) (compat_swap32(v))
#  endif
#  if HAVE_DECL_LE64TOH == 0
#   define le64toh(v) (compat_swap64(v))
#  endif
#  if HAVE_DECL_HTOLE64 == 0
#   define htole64(v) (compat_swap64(v))
#  endif
# else
#  if HAVE_DECL_LE32TOH == 0
#   define le32toh(v) ((uint32_t)v)
#  endif
#  if HAVE_DECL_LE64TOH == 0
#   define le64toh(v) ((uint64_t)v)
#  endif
#  if HAVE_DECL_HTOLE64 == 0
#   define htole64(v) ((uint64_t)v)
#  endif
# endif
#endif

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunknown-pragmas"
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wunused-parameter"
#pragma clang diagnostic ignored "-Wunused-parameter"
#pragma GCC diagnostic ignored "-Waggregate-return"
#pragma GCC diagnostic ignored "-Winline"
#include "libcrux_mlkem768_sha3.h"
#pragma clang diagnostic pop
#pragma GCC diagnostic pop

/* Post-Quantum Traditional hybrid key exchange implementation */

static int
kex_kem_mlkem768x25519_keypair(struct kex *kex)
{
	struct sshbuf *buf = NULL;
	u_char rnd[LIBCRUX_ML_KEM_KEY_PAIR_PRNG_LEN], *cp = NULL;
	size_t need;
	int r = SSH_ERR_INTERNAL_ERROR;
	struct libcrux_mlkem768_keypair keypair;

	if ((buf = sshbuf_new()) == NULL)
		return SSH_ERR_ALLOC_FAIL;
	need = crypto_kem_mlkem768_PUBLICKEYBYTES;
	if ((r = sshbuf_reserve(buf, need, &cp)) != 0)
		goto out;
	arc4random_buf(rnd, sizeof(rnd));
	keypair = libcrux_ml_kem_mlkem768_portable_generate_key_pair(rnd);
	memcpy(cp, keypair.pk.value, crypto_kem_mlkem768_PUBLICKEYBYTES);
	memcpy(kex->mlkem768_client_key, keypair.sk.value,
	    sizeof(kex->mlkem768_client_key));
#ifdef DEBUG_KEXKEM
	dump_digest("client public keypair mlkem768:", cp,
	    crypto_kem_mlkem768_PUBLICKEYBYTES);
#endif

	r = kex_c25519_keygen_to_sshbuf(kex, &buf);
	if (r != 0) goto out;

	/* success */
	kex->client_pub = buf;
	buf = NULL;
 out:
	explicit_bzero(&keypair, sizeof(keypair));
	explicit_bzero(rnd, sizeof(rnd));
	sshbuf_free(buf);
	return r;
}

static inline struct libcrux_mlkem768_enc_result
ssh_libcrux_ml_kem_mlkem768_portable_encapsulate(struct libcrux_mlkem768_pk *pub) {
	u_char rnd[LIBCRUX_ML_KEM_ENC_PRNG_LEN];
	struct libcrux_mlkem768_enc_result ret;

	arc4random_buf(rnd, sizeof(rnd));
	ret = libcrux_ml_kem_mlkem768_portable_encapsulate(pub, rnd);
	explicit_bzero(rnd, sizeof(rnd));

	return ret;
}

static int
kex_kem_mlkem768x25519_enc(struct kex *kex,
   const struct sshbuf *client_blob, struct sshbuf **server_blobp,
   struct sshbuf **shared_secretp)
{
	struct sshbuf *server_blob = NULL;
	struct sshbuf *buf = NULL;
	const u_char *client_pub;
	int r = SSH_ERR_INTERNAL_ERROR;
	struct libcrux_mlkem768_enc_result enc;

	*server_blobp = NULL;
	*shared_secretp = NULL;

	/* client_blob contains both KEM and ECDH client pubkeys */
{	size_t need = crypto_kem_mlkem768_PUBLICKEYBYTES + CURVE25519_SIZE;
	if (sshbuf_len(client_blob) != need) {
		r = SSH_ERR_SIGNATURE_INVALID;
		goto out;
	}
}
	client_pub = sshbuf_ptr(client_blob);
#ifdef DEBUG_KEXKEM
	dump_digest("client public key mlkem768:", client_pub,
	    crypto_kem_mlkem768_PUBLICKEYBYTES);
	dump_digest("client public key c25519:",
	    client_pub + crypto_kem_mlkem768_PUBLICKEYBYTES,
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
	/* generate and encrypt KEM key with client key */
{	struct libcrux_mlkem768_pk mlkem_pub;
	memset(&mlkem_pub, 0, sizeof(mlkem_pub));

	/* check public key validity */
	memcpy(mlkem_pub.value, client_pub, crypto_kem_mlkem768_PUBLICKEYBYTES);
	if (!libcrux_ml_kem_mlkem768_portable_validate_public_key(&mlkem_pub)) {
		r = SSH_ERR_SIGNATURE_INVALID;
		goto out;
	}

	enc = ssh_libcrux_ml_kem_mlkem768_portable_encapsulate(&mlkem_pub);
}
	/* generate ECDH key pair, store server pubkey after ciphertext */
	if ((r = sshbuf_put(buf, enc.snd, sizeof(enc.snd))) != 0 ||
	    (r = sshbuf_put(server_blob, enc.fst.value, sizeof(enc.fst.value))) != 0)
		goto out;
	r = kex_c25519_keygen_to_sshbuf(kex, &server_blob);
	if (r != 0) goto out;

	/* append ECDH shared key */
	client_pub += crypto_kem_mlkem768_PUBLICKEYBYTES;
	r = kex_c25519_shared_secret_to_sshbuf(kex, client_pub, 1, &buf);
	if (r != 0) goto out;
#ifdef DEBUG_KEXKEM
	dump_digest("server cipher text:",
	    enc.fst.value, sizeof(enc.fst.value));
	dump_digestb("concatenation of KEM and ECDH public part:", server_blob);
	dump_digest("server kem key:", enc.snd, sizeof(enc.snd));
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
	explicit_bzero(&enc, sizeof(enc));
	sshbuf_free(server_blob);
	sshbuf_free(buf);
	return r;
}

static int
kex_kem_mlkem768x25519_dec(struct kex *kex,
    const struct sshbuf *server_blob, struct sshbuf **shared_secretp)
{
	struct sshbuf *buf = NULL;
	const u_char *ciphertext, *server_pub;
	int r;
	struct libcrux_mlkem768_sk mlkem_priv;
	struct libcrux_mlkem768_ciphertext mlkem_ciphertext;

	*shared_secretp = NULL;
	memset(&mlkem_priv, 0, sizeof(mlkem_priv));
	memset(&mlkem_ciphertext, 0, sizeof(mlkem_ciphertext));

{	size_t need = crypto_kem_mlkem768_CIPHERTEXTBYTES + CURVE25519_SIZE;
	if (sshbuf_len(server_blob) != need) {
		r = SSH_ERR_SIGNATURE_INVALID;
		goto out;
	}
}
	ciphertext = sshbuf_ptr(server_blob);
	server_pub = ciphertext + crypto_kem_mlkem768_CIPHERTEXTBYTES;
	/* hash concatenation of KEM key and ECDH shared key */
	if ((buf = sshbuf_new()) == NULL) {
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	memcpy(mlkem_priv.value, kex->mlkem768_client_key,
	    sizeof(kex->mlkem768_client_key));
	memcpy(mlkem_ciphertext.value, ciphertext,
	    sizeof(mlkem_ciphertext.value));
#ifdef DEBUG_KEXKEM
	dump_digest("server cipher text:", mlkem_ciphertext.value,
	    sizeof(mlkem_ciphertext.value));
	dump_digest("server public key c25519:", server_pub, CURVE25519_SIZE);
#endif

{	u_char mlkem_key[crypto_kem_mlkem768_BYTES];
	libcrux_ml_kem_mlkem768_portable_decapsulate(&mlkem_priv,
	    &mlkem_ciphertext, mlkem_key);
	if ((r = sshbuf_put(buf, mlkem_key, sizeof(mlkem_key))) != 0) {
		explicit_bzero(mlkem_key, sizeof(mlkem_key));
		goto out;
	}
#ifdef DEBUG_KEXKEM
	dump_digest("client kem key:", mlkem_key, sizeof(mlkem_key));
#endif
	explicit_bzero(mlkem_key, sizeof(mlkem_key));
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
 out:
	kex_reset_keys(kex);
	explicit_bzero(&mlkem_priv, sizeof(mlkem_priv));
	explicit_bzero(&mlkem_ciphertext, sizeof(mlkem_ciphertext));
	sshbuf_free(buf);
	return r;
}

static int kex_kem_mlkem768x25519_enabled(void) { return 1; }

static const struct kex_impl_funcs kex_kem_mlkem768x25519_funcs = {
	kex_init_gen,
	kex_kem_mlkem768x25519_keypair,
	kex_kem_mlkem768x25519_enc,
	kex_kem_mlkem768x25519_dec
};

const struct kex_impl kex_kem_mlkem768x25519_sha256_impl = {
	"mlkem768x25519-sha256",
	SSH_DIGEST_SHA256,
	kex_kem_mlkem768x25519_enabled,
	&kex_kem_mlkem768x25519_funcs,
	NULL
};
#else /* ENABLE_KEX_MLKEM768X25519 */

static int kex_kem_mlkem768x25519_enabled(void) { return 0; }
const struct kex_impl kex_kem_mlkem768x25519_sha256_impl = {
	"mlkem768x25519-sha256", SSH_DIGEST_SHA256,
	kex_kem_mlkem768x25519_enabled, NULL, NULL
};

#endif /* ENABLE_KEX_MLKEM768X25519 */
