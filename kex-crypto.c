/*
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

#define SSHKEY_INTERNAL
#include "includes.h"

#ifdef WITH_OPENSSL
#include "evp-compat.h"

#include "kex.h"
#include "dh.h"


int
kexgex_hash_client(const struct kex *kex,
    const struct sshbuf *key_blob, const BIGNUM *peer_pub,
    const struct sshbuf *shared_secret,
    u_char *hash, size_t *hashlen
) {
	const BIGNUM *my_pub, *dh_p, *dh_g;

	DH_get0_key(kex->dh, &my_pub, NULL);
	DH_get0_pqg(kex->dh, &dh_p, NULL, &dh_g);

	return kexgex_hash(kex->hash_alg,
	    kex->client_version, kex->server_version,
	    kex->my, kex->peer, key_blob,
	    kex->min, kex->nbits, kex->max,
	    dh_p, dh_g, my_pub, peer_pub,
	    sshbuf_ptr(shared_secret), sshbuf_len(shared_secret),
	    hash, hashlen);
}

int
kexgex_hash_server(const struct kex *kex,
    const struct sshbuf *key_blob, const BIGNUM *peer_pub,
    const struct sshbuf *shared_secret,
    u_char *hash, size_t *hashlen
) {
	const BIGNUM *my_pub, *dh_p, *dh_g;

	DH_get0_key(kex->dh, &my_pub, NULL);
	DH_get0_pqg(kex->dh, &dh_p, NULL, &dh_g);

	return kexgex_hash( kex->hash_alg,
	    kex->client_version, kex->server_version,
	    kex->peer, kex->my, key_blob,
	    kex->min, kex->nbits, kex->max,
	    dh_p, dh_g, peer_pub, my_pub,
	    sshbuf_ptr(shared_secret), sshbuf_len(shared_secret),
	    hash, hashlen);
}
#else

typedef int kex_crypto_empty_translation_unit;

#endif /* WITH_OPENSSL */
