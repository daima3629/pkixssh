/*
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

#include "kex.h"
#include "digest.h"
#ifdef ENABLE_KEM_PROVIDERS
#include "ssherr.h"
#include "log.h"

/* see sshkey-crypto.c */
extern OSSL_LIB_CTX *pkixssh_libctx;
extern char *pkixssh_propq;

struct kex_pkem_spec {
	struct kex_kem_spec kem_spec;
	struct kex_ecdh_spec ecdh_spec;
	struct kex_ecx_spec ecx_spec;
	size_t ec_pub_len;
	size_t ec_cipher_len;
	size_t ec_secret_len;
};


extern int /* see kexkem.c */
kexkey_kem_keypair(struct kexkey *key, struct sshbuf **client_pubp);

extern int /* see kexecx.c */
kexkey_ecx_keypair(struct kexkey *key, struct sshbuf **client_pubp);

extern int /* see kexecdh.c */
kexkey_ecdh_keypair(struct kexkey *key, struct sshbuf **client_pubp);

static int
kex_pkem_keypair_kem(struct kex *kex, struct sshbuf **client_pubp) {
	struct kex_pkem_spec *spec = kex->impl->spec;
	struct kexkey key = { &kex->pkem, &spec->kem_spec };

	return kexkey_kem_keypair(&key, client_pubp);
}

static int
kex_pkem_keypair_trad(struct kex *kex, struct sshbuf **client_pubp) {
	struct kex_pkem_spec *spec = kex->impl->spec;
	struct kexkey key = { &kex->pk, NULL };
	int r;

	if (spec->ecx_spec.key_id != -1) {
		key.spec = &spec->ecx_spec;
		r = kexkey_ecx_keypair(&key, client_pubp);
	} else
	if (spec->ecdh_spec.ec_nid != -1) {
		key.spec = &spec->ecdh_spec;
		r = kexkey_ecdh_keypair(&key, client_pubp);
	} else
		return 0;

	if (r != 0) {
		do_log_crypto_errors(SYSLOG_LEVEL_ERROR);
		return r;
	}

	return r;
}

static int
kex_pkem_keypair(struct kex *kex) {
	int r;


	r = kex_pkem_keypair_kem(kex, &kex->client_pub);
	if (r != 0) return r;

	r = kex_pkem_keypair_trad(kex, &kex->client_pub);
	if (r != 0) return r;

#ifdef DEBUG_KEXKEM
	dump_digestb("public keypair kem:", kex->client_pub);
#endif
	return r;
}


extern int
kexkey_kem_enc(struct kexkey *key, const struct sshbuf *client_blob,
    struct sshbuf **server_blobp, struct sshbuf **secret_blobp);

extern int
kexkey_ecdh_enc(struct kexkey *key, const struct sshbuf *client_blob,
    struct sshbuf **server_blobp, struct sshbuf **shared_secretp);

extern int
kexkey_ecx_enc(struct kexkey *key, const struct sshbuf *client_blob,
   struct sshbuf **server_blobp, struct sshbuf **shared_secretp);

static int
kex_pkem_enc_kem(struct kex *kex, const struct sshbuf *client_blob,
    struct sshbuf **server_blobp, struct sshbuf **secret_blobp
) {
	struct kex_pkem_spec *spec = kex->impl->spec;
	struct kex_kem_spec *kem_spec = &spec->kem_spec;
	struct sshbuf *client_pub;
	int r;

	client_pub = sshbuf_from(sshbuf_ptr(client_blob), kem_spec->pub_len);
	if (client_pub == NULL)
		return SSH_ERR_ALLOC_FAIL;

{	struct kexkey key = { &kex->pkem, kem_spec };
	r = kexkey_kem_enc(&key, client_pub, server_blobp, secret_blobp);
}

	sshbuf_free(client_pub);
	return r;
}
static int
kex_pkem_enc_trad(struct kex *kex, const struct sshbuf *client_blob,
    struct sshbuf **server_blobp, struct sshbuf **secret_blobp
) {
	struct kex_pkem_spec *spec = kex->impl->spec;
	struct kexkey key = { &kex->pk, NULL };
	struct sshbuf *client_pub;
	int r;

	*server_blobp = NULL;
	*secret_blobp = NULL;

	client_pub = sshbuf_from(sshbuf_ptr(client_blob)
	    + spec->kem_spec.pub_len, spec->ec_pub_len);
	if (client_pub == NULL)
		return SSH_ERR_ALLOC_FAIL;

	if (spec->ecx_spec.key_id != -1) {
		key.spec = &spec->ecx_spec;
		r = kexkey_ecx_enc(&key, client_pub,
		    server_blobp, secret_blobp);
	} else
	if (spec->ecdh_spec.ec_nid != -1) {
		key.spec = &spec->ecdh_spec;
		r = kexkey_ecdh_enc(&key, client_pub,
		    server_blobp, secret_blobp);
	} else
		r = 0;

	sshbuf_free(client_pub);
	return r;
}

static int
kex_pkem_enc(struct kex *kex, const struct sshbuf *client_blob,
    struct sshbuf **server_blobp, struct sshbuf **shared_secretp
) {
	struct kex_pkem_spec *spec = kex->impl->spec;
	struct sshbuf *server_blob = NULL, *secret_blob = NULL;
	struct sshbuf *server_blob_trad = NULL, *secret_blob_trad = NULL;
	int r;

	*server_blobp = NULL;
	*shared_secretp = NULL;

{	/* client_blob contains both KEM and ECDH client pubkeys */
	size_t need = spec->kem_spec.pub_len + spec->ec_pub_len;
	if (need != sshbuf_len(client_blob)) {
		r = SSH_ERR_SIGNATURE_INVALID;
		goto out;
	}
}
#ifdef DEBUG_KEXKEM
	dump_digestb("client public key:", client_blob);
#endif

	r = kex_pkem_enc_kem(kex, client_blob,
	    &server_blob, &secret_blob);
	if (r != 0) goto out;

	r = kex_pkem_enc_trad(kex, client_blob,
	    &server_blob_trad, &secret_blob_trad);
	if (r != 0) goto out;

	r = sshbuf_putb(server_blob, server_blob_trad);
	if (r != 0) goto out;
	r = sshbuf_putb(secret_blob, secret_blob_trad);
	if (r != 0) goto out;

#ifdef DEBUG_KEXKEM
	dump_digestb("concatenation of KEM and ECDH public part:", server_blob);
	dump_digestb("concatenation of KEM and ECDH shared key:", secret_blob);
#endif

	/* string-encoded hash is resulting shared secret */
	r = kex_digest_buffer(kex->impl->hash_alg, secret_blob, shared_secretp);
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
	sshbuf_free(server_blob);
	sshbuf_free(secret_blob);
	sshbuf_free(server_blob_trad);
	sshbuf_free(secret_blob_trad);
	return r;
}


extern int
kexkey_kem_dec(struct kexkey *key, const struct sshbuf *server_blob,
    struct sshbuf **shared_secretp);

extern int
kexkey_ecx_dec(struct kexkey *key, const struct sshbuf *server_blob,
    struct sshbuf **shared_secretp);

extern int
kexkey_ecdh_dec(struct kexkey *key, const struct sshbuf *server_blob,
    struct sshbuf **shared_secretp);

static int
kex_pkem_dec_kem(struct kex *kex, const struct sshbuf *server_blob,
    struct sshbuf **shared_secretp
) {
	struct kex_pkem_spec *spec = kex->impl->spec;
	struct kex_kem_spec *kem_spec = &spec->kem_spec;
	struct sshbuf *server_buf;
	int r;

	server_buf = sshbuf_from(sshbuf_ptr(server_blob), kem_spec->cipher_len);
	if (server_buf == NULL)
		return SSH_ERR_ALLOC_FAIL;

{	struct kexkey key = { &kex->pkem, kem_spec } ;
	r = kexkey_kem_dec(&key, server_buf, shared_secretp);
}

	sshbuf_free(server_buf);
	return r;
}

static int
kex_pkem_dec_trad(struct kex *kex, const struct sshbuf *server_blob,
    struct sshbuf **shared_secretp
) {
	struct kex_pkem_spec *spec = kex->impl->spec;
	struct kexkey key = { &kex->pk, NULL };
	struct kex_kem_spec *kem_spec = &spec->kem_spec;
	struct sshbuf *server_buf;
	int r;

	*shared_secretp = NULL;

	server_buf = sshbuf_from(sshbuf_ptr(server_blob)
	    + kem_spec->cipher_len, spec->ec_cipher_len);
	if (server_buf == NULL)
		return SSH_ERR_ALLOC_FAIL;

	if (spec->ecx_spec.key_id != -1) {
		key.spec = &spec->ecx_spec;
		r = kexkey_ecx_dec(&key, server_buf,
		    shared_secretp);
	} else
	if (spec->ecdh_spec.ec_nid != -1) {
		key.spec = &spec->ecdh_spec;
		r = kexkey_ecdh_dec(&key, server_buf,
		    shared_secretp);
	} else
		r = 0;

	sshbuf_free(server_buf);
	return r;
}

static int
kex_pkem_dec(struct kex *kex, const struct sshbuf *server_blob,
    struct sshbuf **shared_secretp) {
	struct kex_pkem_spec *spec = kex->impl->spec;
	struct sshbuf *secret_buf = NULL;
	struct sshbuf *secret_buf_trad = NULL;
	int r;

	*shared_secretp = NULL;

{	size_t need = spec->kem_spec.cipher_len + spec->ec_cipher_len;
	if (need != sshbuf_len(server_blob)) {
		r = SSH_ERR_SIGNATURE_INVALID;
		goto out;
	}
}
#ifdef DEBUG_KEXKEM
	dump_digestb("server KEM and ECDH public part:", server_blob);
#endif

	r = kex_pkem_dec_kem(kex, server_blob, &secret_buf);
	if (r != 0) goto out;

	r = kex_pkem_dec_trad(kex, server_blob, &secret_buf_trad);
	if (r != 0) goto out;

	r = sshbuf_putb(secret_buf, secret_buf_trad);
	if (r != 0) goto out;

#ifdef DEBUG_KEXKEM
	dump_digestb("concatenation of KEM and ECDH shared key:", secret_buf);
#endif
	r = kex_digest_buffer(kex->impl->hash_alg, secret_buf, shared_secretp);
#ifdef DEBUG_KEXKEM
	if (r == 0)
		dump_digestb("encoded shared secret:", *shared_secretp);
	else
		fprintf(stderr, "shared secret error: %s\n", ssh_err(r));
#endif

out:
	sshbuf_free(secret_buf);
	sshbuf_free(secret_buf_trad);
	return 0;
}


static inline int
kex_pkem_enabled(const char *algorithm, int *flag) {
	if (*flag >= 0) return *flag;
	*flag = ssh_kem_allowed(algorithm);
	return *flag;
}

static const char KEX_SSH_MLKEM768[] = "MLKEM768";
static int
kex_pkem_mlkem768_enabled(void) {
	static int flag_pkem_mlkem768 = -1;
	return kex_pkem_enabled(KEX_SSH_MLKEM768, &flag_pkem_mlkem768);
}

static const char KEX_SSH_MLKEM1024[] = "MLKEM1024";
static int
kex_pkem_mlkem1024_enabled(void) {
	static int flag_pkem_mlkem1024 = -1;
	return kex_pkem_enabled(KEX_SSH_MLKEM1024, &flag_pkem_mlkem1024);
}


static const struct kex_impl_funcs kex_pkem_funcs = {
	kex_init_gen,
	kex_pkem_keypair,
	kex_pkem_enc,
	kex_pkem_dec
};


static struct kex_pkem_spec kex_pkem_mlkem768nistp256_spec = {
	{ KEX_SSH_MLKEM768, 1184, 1088, 32},
	{ NID_X9_62_prime256v1, 1 },
	{ -1, 0, 0 },
	65, 65, 32
};
const struct kex_impl kex_pkem_mlkem768nistp256_sha256_impl = {
	"mlkem768nistp256-sha256",
	SSH_DIGEST_SHA256,
	kex_pkem_mlkem768_enabled,
	&kex_pkem_funcs,
	&kex_pkem_mlkem768nistp256_spec
};

static struct kex_pkem_spec kex_pkem_mlkem1024nistp384_spec = {
	{ KEX_SSH_MLKEM1024, 1568, 1568, 32},
	{ NID_secp384r1, 1 },
	{ -1, 0, 0 },
	97, 97, 48
};
const struct kex_impl kex_pkem_mlkem1024nistp384_sha384_impl = {
	"mlkem1024nistp384-sha384",
	SSH_DIGEST_SHA384,
	kex_pkem_mlkem1024_enabled,
	&kex_pkem_funcs,
	&kex_pkem_mlkem1024nistp384_spec
};

static struct kex_pkem_spec kex_pkem_mlkem768x25519_spec = {
	{ KEX_SSH_MLKEM768, 1184, 1088, 32},
	{ -1, 0 },
	{ EVP_PKEY_X25519, 32, 1 },
	32, 32, 32
};

const struct kex_impl kex_pkem_mlkem768x25519_sha256_impl = {
	"mlkem768x25519-sha256",
	SSH_DIGEST_SHA256,
	kex_pkem_mlkem768_enabled,
	&kex_pkem_funcs,
	&kex_pkem_mlkem768x25519_spec
};

#else /* ENABLE_KEM_PROVIDERS */
static int kex_pkem_enabled(void) { return 0; }

const struct kex_impl kex_pkem_mlkem768nistp256_sha256_impl = {
	"mlkem768nistp256-sha256", SSH_DIGEST_SHA256,
	kex_pkem_enabled, NULL, NULL
};

const struct kex_impl kex_pkem_mlkem1024nistp384_sha384_impl = {
	"mlkem1024nistp384-sha384", SSH_DIGEST_SHA384,
	kex_pkem_enabled, NULL, NULL
};

const struct kex_impl kex_pkem_mlkem768x25519_sha256_impl = {
	"mlkem768x25519-sha256", SSH_DIGEST_SHA256,
	kex_pkem_enabled, NULL, NULL
};
#endif /* ENABLE_KEM_PROVIDERS */
