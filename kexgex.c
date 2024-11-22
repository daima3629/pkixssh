/* $OpenBSD: kexgex.c,v 1.32 2019/01/23 00:30:41 djm Exp $ */
/*
 * Copyright (c) 2000 Niels Provos.  All rights reserved.
 * Copyright (c) 2001 Markus Friedl.  All rights reserved.
 * Copyright (c) 2018-2024 Roumen Petrov.  All rights reserved.
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

#include <openssl/bn.h>

#include "kex.h"
#include "packet.h"
#include "ssh2.h"
#include "ssherr.h"
#include "sshbuf.h"
#include "digest.h"

int
kexgex_hash(
    int hash_alg,
    const struct sshbuf *client_version,
    const struct sshbuf *server_version,
    const struct sshbuf *client_kexinit,
    const struct sshbuf *server_kexinit,
    const struct sshbuf *server_host_key_blob,
    int min, int wantbits, int max,
    const BIGNUM *prime,
    const BIGNUM *gen,
    const BIGNUM *client_dh_pub,
    const BIGNUM *server_dh_pub,
    const u_char *shared_secret, size_t secretlen,
    u_char *hash, size_t *hashlen)
{
	struct sshbuf *b;
	int r;

	if (*hashlen < ssh_digest_bytes(SSH_DIGEST_SHA1))
		return SSH_ERR_INVALID_ARGUMENT;
	if ((b = sshbuf_new()) == NULL)
		return SSH_ERR_ALLOC_FAIL;
	if ((r = sshbuf_put_stringb(b, client_version)) != 0 ||
	    (r = sshbuf_put_stringb(b, server_version)) != 0 ||
	    /* kexinit messages: fake header: len+SSH2_MSG_KEXINIT */
	    (r = sshbuf_put_u32(b, sshbuf_len(client_kexinit) + 1)) != 0 ||
	    (r = sshbuf_put_u8(b, SSH2_MSG_KEXINIT)) != 0 ||
	    (r = sshbuf_putb(b, client_kexinit)) != 0 ||
	    (r = sshbuf_put_u32(b, sshbuf_len(server_kexinit) + 1)) != 0 ||
	    (r = sshbuf_put_u8(b, SSH2_MSG_KEXINIT)) != 0 ||
	    (r = sshbuf_putb(b, server_kexinit)) != 0 ||
	    (r = sshbuf_put_stringb(b, server_host_key_blob)) != 0 ||
	    (min != -1 && (r = sshbuf_put_u32(b, min)) != 0) ||
	    (r = sshbuf_put_u32(b, wantbits)) != 0 ||
	    (max != -1 && (r = sshbuf_put_u32(b, max)) != 0) ||
	    (r = sshbuf_put_bignum2(b, prime)) != 0 ||
	    (r = sshbuf_put_bignum2(b, gen)) != 0 ||
	    (r = sshbuf_put_bignum2(b, client_dh_pub)) != 0 ||
	    (r = sshbuf_put_bignum2(b, server_dh_pub)) != 0 ||
	    (r = sshbuf_put(b, shared_secret, secretlen)) != 0) {
		sshbuf_free(b);
		return r;
	}
#ifdef DEBUG_KEX
	dump_digestb("hash-input", b);
#endif
	if (ssh_digest_buffer(hash_alg, b, hash, *hashlen) != 0) {
		sshbuf_free(b);
		return SSH_ERR_LIBCRYPTO_ERROR;
	}
	sshbuf_free(b);
	*hashlen = ssh_digest_bytes(hash_alg);
#ifdef DEBUG_KEX
	dump_digest("hash", hash, *hashlen);
#endif
	return 0;
}


/* diffie-hellman group and key exchange implementation */
/* Note implementation uses specific message sequence implemented in callback.
 * The only difference is digest, so no need to set function pointers.
 */
static int kex_dh_gex_sha1_enabled(void) { return 1; }
# ifdef HAVE_EVP_SHA256
static int kex_dh_gex_sha2_enabled(void) { return 1; }
# else
static int kex_dh_gex_sha2_enabled(void) { return 0; }
# endif

static int
kex_init_gex(struct ssh *ssh) {
	struct kex *kex = ssh->kex;

	return kex->server
		? kexgex_server(ssh)
		: kexgex_client(ssh);
}

static const struct kex_impl_funcs kex_dh_gex_funcs = {
	kex_init_gex,
	NULL,
	NULL,
	NULL
};

const struct kex_impl kex_dh_gex_sha1_impl = {
	KEX_DH_GEX_SHA1,
	"diffie-hellman-group-exchange-sha1",
	SSH_DIGEST_SHA1,
	kex_dh_gex_sha1_enabled,
	&kex_dh_gex_funcs,
	NULL
};

const struct kex_impl kex_dh_gex_sha256_impl = {
	KEX_DH_GEX_SHA256,
	"diffie-hellman-group-exchange-sha256",
	SSH_DIGEST_SHA256,
	kex_dh_gex_sha2_enabled,
	&kex_dh_gex_funcs,
	NULL
};

#endif /* WITH_OPENSSL */
