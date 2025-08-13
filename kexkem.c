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
#include "sshbuf.h"
#include "ssherr.h"
#include "log.h"

/* TODO: move to cryptographic library initialisation */
OSSL_LIB_CTX *pkixssh_libctx = NULL;
char *pkixssh_propq = NULL;

/* generate key and store public part to buffer */

static int
sshkem_EVP_PKEY_keygen(const char *kem_name, EVP_PKEY **pkp) {
#if 0	/* OpenSSL 3+ is buggy - does not allow third party keys */
	*pkp = EVP_PKEY_Q_keygen(pkixssh_libctx, pkixssh_propq, kem_name, NULL);
	if (*pkp == NULL) {
		do_log_crypto_errors(SYSLOG_LEVEL_ERROR);
		return SSH_ERR_LIBCRYPTO_ERROR;
	}
	return 0;
#else
	EVP_PKEY_CTX *ctx = NULL;
	EVP_PKEY *pk = NULL;
	int r;

	ctx = EVP_PKEY_CTX_new_from_name(pkixssh_libctx, kem_name, pkixssh_propq);
	if (ctx == NULL) {
		r = SSH_ERR_INVALID_ARGUMENT;
		goto out;
	}
	if (EVP_PKEY_keygen_init(ctx) <= 0) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		goto out;
	}
	if (EVP_PKEY_keygen(ctx, &pk) <= 0) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		goto out;
	}

	r = 0;

out:
	if (r == 0) {
		*pkp = pk;
		pk = NULL;
	} else
		do_log_crypto_errors(SYSLOG_LEVEL_ERROR);

	EVP_PKEY_CTX_free(ctx);
	EVP_PKEY_free(pk);
	return r;
#endif
}

static int
kexkey_kem_keygen_to_sshbuf(struct kexkey *key, struct sshbuf **client_pubp) {
	struct kex_kem_spec *spec = key->spec;
	struct sshbuf *buf;
	u_char *pub = NULL;
	int r;

	if (*client_pubp == NULL) {
		buf = sshbuf_new();
		if (buf == NULL) return SSH_ERR_ALLOC_FAIL;
	} else
		buf = *client_pubp;

	r = sshkem_EVP_PKEY_keygen(spec->name, key->pk);
	if (r != 0) goto err;


	pub = malloc(spec->pub_len);
	if (pub == NULL) {
		r = SSH_ERR_ALLOC_FAIL;
		goto err;
	}

	/* extra control */
{	size_t len = spec->pub_len;
	if (EVP_PKEY_get_raw_public_key(*key->pk, pub, &len) != 1 &&
	    len != spec->pub_len) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		goto err;
	}
}

	r = sshbuf_put(buf, pub, spec->pub_len);

err:
	free(pub);
	if (*client_pubp == NULL) {
		if (r == 0)
			*client_pubp = buf;
		else
			sshbuf_free(buf);
	}
	return r;
}

static EVP_PKEY*
kexkey_kem_new_pub(const char *kem_name,
    const struct sshbuf *client_blob
) {
	EVP_PKEY *pk;

	pk = EVP_PKEY_new_raw_public_key_ex(pkixssh_libctx,
	    kem_name, pkixssh_propq,
	    sshbuf_ptr(client_blob), sshbuf_len(client_blob));
	if (pk == NULL)
		do_log_crypto_errors(SYSLOG_LEVEL_ERROR);
	return pk;
}


/* for internal use in hybrid key echange */

extern int
kexkey_kem_keypair(struct kexkey *key, struct sshbuf **client_pubp);

extern int
kexkey_kem_enc(struct kexkey *key, const struct sshbuf *client_blob,
    struct sshbuf **server_blobp, struct sshbuf **secret_blobp
);

extern int
kexkey_kem_dec(struct kexkey *key, const struct sshbuf *server_blob,
    struct sshbuf **shared_secretp
);


/* key encapsulation implementation */

int
kexkey_kem_keypair(struct kexkey *key, struct sshbuf **client_pubp)
{
	int r;

	r = kexkey_kem_keygen_to_sshbuf(key, client_pubp);
#ifdef DEBUG_KEXKEM
	if (r == 0)
		dump_digestb("kem public key:", *client_pubp);
	else
		fprintf(stderr, "kem keypair error: %s\n", ssh_err(r));
#endif

	return r;
}

int
kexkey_kem_enc(struct kexkey *key, const struct sshbuf *client_blob,
    struct sshbuf **server_blobp, struct sshbuf **secret_blobp
) {
	struct kex_kem_spec *spec = key->spec;
	EVP_PKEY_CTX *ctx = NULL;
	struct sshbuf *server_blob = NULL, *secret_blob = NULL;
	size_t secret_len, outdata_len;
	int r;

	*key->pk = kexkey_kem_new_pub(spec->name, client_blob);
	if (*key->pk == NULL)
		return SSH_ERR_LIBCRYPTO_ERROR;

	ctx = EVP_PKEY_CTX_new_from_pkey(pkixssh_libctx, *key->pk, pkixssh_propq);
	if (ctx == NULL) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		do_log_crypto_errors(SYSLOG_LEVEL_ERROR);
		goto out;
	}

	if ((EVP_PKEY_encapsulate_init(ctx, NULL) <= 0) ||
	    (EVP_PKEY_encapsulate(ctx, NULL, &outdata_len, NULL, &secret_len) <= 0)
	) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		do_log_crypto_errors(SYSLOG_LEVEL_ERROR);
		goto out;
	}
{	size_t need = spec->cipher_len;
	if (outdata_len != need) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		goto out;
	}
}
{	size_t need = spec->secret_len;
	if (secret_len != need) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		goto out;
	}
}

	if ((server_blob = sshbuf_new()) == NULL) {
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	if ((secret_blob = sshbuf_new()) == NULL) {
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}

{	unsigned char *secret, *outdata;

	r = sshbuf_reserve(secret_blob, secret_len, &secret);
	if (r != 0) goto out;
	r = sshbuf_reserve(server_blob, outdata_len, &outdata);
	if (r != 0) goto out;

	if (EVP_PKEY_encapsulate(ctx, outdata, &outdata_len,
	    secret, &secret_len) <= 0) {
		r = SSH_ERR_LIBCRYPTO_ERROR; /*TODO*/
		do_log_crypto_errors(SYSLOG_LEVEL_ERROR);
		goto out;
	}
}

	*server_blobp = server_blob; server_blob = NULL;
	*secret_blobp = secret_blob; secret_blob = NULL;
	r = 0;

out:
	sshbuf_free(server_blob);
	sshbuf_free(secret_blob);
	EVP_PKEY_CTX_free(ctx);
	return r;
}

int
kexkey_kem_dec(struct kexkey *key, const struct sshbuf *server_blob,
    struct sshbuf **shared_secretp
) {
	struct kex_kem_spec *spec = key->spec;
	EVP_PKEY_CTX *ctx = NULL;
	size_t secret_len;
	struct sshbuf *secret_buf = NULL;
	int r;

	ctx = EVP_PKEY_CTX_new_from_pkey(pkixssh_libctx, *key->pk, pkixssh_propq);
	if (ctx == NULL) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		do_log_crypto_errors(SYSLOG_LEVEL_ERROR);
		goto out;
	}

	if (EVP_PKEY_decapsulate_init(ctx, NULL) <= 0) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		do_log_crypto_errors(SYSLOG_LEVEL_ERROR);
		goto out;
	}
	if (EVP_PKEY_decapsulate(ctx, NULL, &secret_len,
	    sshbuf_ptr(server_blob), sshbuf_len(server_blob)) <= 0) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		do_log_crypto_errors(SYSLOG_LEVEL_ERROR);
		goto out;
	}
{	size_t need = spec->secret_len;
	if (secret_len != need) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		goto out;
	}
}

	if ((secret_buf = sshbuf_new()) == NULL) {
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}

{	unsigned char *secret;
	r = sshbuf_reserve(secret_buf, secret_len, &secret);
	if (r != 0) goto out;

	if (EVP_PKEY_decapsulate(ctx, secret, &secret_len,
	    sshbuf_ptr(server_blob), sshbuf_len(server_blob)) <= 0) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		do_log_crypto_errors(SYSLOG_LEVEL_ERROR);
		goto out;
	}
}

	*shared_secretp = secret_buf;
	secret_buf = NULL;
	r = 0;

out:
	sshbuf_free(secret_buf);
	EVP_PKEY_CTX_free(ctx);
	return r;
}


static int
kex_kem_keypair(struct kex *kex)
{
	struct kexkey key = { &kex->pkem, kex->impl->spec };

	return kexkey_kem_keypair(&key, &kex->client_pub);
}

static int
kex_kem_enc(struct kex *kex, const struct sshbuf *client_blob,
   struct sshbuf **server_blobp, struct sshbuf **shared_secretp)
{
	struct kexkey key = { &kex->pkem, kex->impl->spec };

	return kexkey_kem_enc(&key, client_blob, server_blobp, shared_secretp);
}

static int
kex_kem_dec(struct kex *kex, const struct sshbuf *server_blob,
    struct sshbuf **shared_secretp)
{
	struct kexkey key = { &kex->pkem, kex->impl->spec };

	return kexkey_kem_dec(&key, server_blob, shared_secretp);
}


static const struct kex_impl_funcs kex_kem_funcs = {
	kex_init_gen,
	kex_kem_keypair,
	kex_kem_enc,
	kex_kem_dec
};

/* NOTE:
Tester is responsible for providing a cryptographic
library that supports ML-KEM algorithms.
*/
#ifndef TEST_KEM_PROVIDERS
# define TEST_KEM_PROVIDERS 0
#endif
static int kex_mlkem768_enabled(void) { return TEST_KEM_PROVIDERS; }
static int kex_mlkem1024_enabled(void) { return TEST_KEM_PROVIDERS; }

static struct kex_kem_spec kex_mlkem768_spec = {
	"MLKEM768", 1184, 1088, 32
};
const struct kex_impl kex_mlkem768_sha256_testimpl = {
	"mlkem768-sha256", SSH_DIGEST_SHA256,
	kex_mlkem768_enabled,
	&kex_kem_funcs,
	&kex_mlkem768_spec
};

static struct kex_kem_spec kex_mlkem1024_spec = {
	"MLKEM1024", 1568, 1568, 32
};
const struct kex_impl kex_mlkem1024_sha384_testimpl = {
	"mlkem1024-sha384", SSH_DIGEST_SHA384,
	kex_mlkem1024_enabled,
	&kex_kem_funcs,
	&kex_mlkem1024_spec
};
#else /* ENABLE_KEM_PROVIDERS */
static int kex_mlkem_enabled(void) { return 0; }

const struct kex_impl kex_mlkem768_sha256_testimpl = {
	"mlkem768-sha256", SSH_DIGEST_SHA256,
	kex_mlkem_enabled, NULL, NULL
};

const struct kex_impl kex_mlkem1024_sha384_testimpl = {
	"mlkem1024-sha384", SSH_DIGEST_SHA384,
	kex_mlkem_enabled, NULL, NULL
};
#endif /* ENABLE_KEM_PROVIDERS */
