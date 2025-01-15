/* $OpenBSD: kexgexs.c,v 1.46 2023/03/29 01:07:48 dtucker Exp $ */
/*
 * Copyright (c) 2000 Niels Provos.  All rights reserved.
 * Copyright (c) 2001 Markus Friedl.  All rights reserved.
 * Copyright (c) 2014-2025 Roumen Petrov.  All rights reserved.
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

#include <string.h>

#include "kex.h"
#include "dh.h"
#include "dh-crypto.h"
#include "ssh2.h"
#include "packet.h"
#include "ssherr.h"
#include "log.h"
#include "monitor_wrap.h"
#include "digest.h"


static int input_kex_dh_gex_request(int, u_int32_t, struct ssh *);
static int input_kex_dh_gex_init(int, u_int32_t, struct ssh *);

static int
kexgex_hash_server(const struct kex *kex,
    const struct sshbuf *key_blob, const BIGNUM *peer_pub,
    const struct sshbuf *shared_secret,
    u_char *hash, size_t *hashlen
) {
	int r;
	DH *dh;
	const BIGNUM *my_pub, *dh_p, *dh_g;

	dh = EVP_PKEY_get1_DH(kex->pk);
	if (dh == NULL)
		return SSH_ERR_INVALID_ARGUMENT;

	DH_get0_key(dh, &my_pub, NULL);
	DH_get0_pqg(dh, &dh_p, NULL, &dh_g);

	r = kexgex_hash(kex->impl->hash_alg,
	    kex->client_version, kex->server_version,
	    kex->peer, kex->my, key_blob,
	    kex->min, kex->nbits, kex->max,
	    dh_p, dh_g, peer_pub, my_pub,
	    sshbuf_ptr(shared_secret), sshbuf_len(shared_secret),
	    hash, hashlen);

	DH_free(dh);
	return r;
}


int
kexgex_server(struct ssh *ssh)
{
	ssh_dispatch_set(ssh, SSH2_MSG_KEX_DH_GEX_REQUEST,
	    &input_kex_dh_gex_request);
	debug("expecting SSH2_MSG_KEX_DH_GEX_REQUEST");
	return 0;
}

static int
input_kex_dh_gex_request(int type, u_int32_t seq, struct ssh *ssh)
{
	struct kex *kex = ssh->kex;
	int r;
	u_int min = 0, max = 0, nbits = 0;

	UNUSED(type);
	UNUSED(seq);
	debug("SSH2_MSG_KEX_DH_GEX_REQUEST received");
	ssh_dispatch_set(ssh, SSH2_MSG_KEX_DH_GEX_REQUEST, &kex_protocol_error);

	if ((r = sshpkt_get_u32(ssh, &min)) != 0 ||
	    (r = sshpkt_get_u32(ssh, &nbits)) != 0 ||
	    (r = sshpkt_get_u32(ssh, &max)) != 0 ||
	    (r = sshpkt_get_end(ssh)) != 0)
		goto out;
	kex->nbits = nbits;
	kex->min = min;
	kex->max = max;
	min = MAXIMUM(DH_GRP_MIN, min);
	max = MINIMUM(DH_GRP_MAX, max);
	nbits = MAXIMUM(DH_GRP_MIN, nbits);
	nbits = MINIMUM(DH_GRP_MAX, nbits);

	if (kex->max < kex->min || kex->nbits < kex->min ||
	    kex->max < kex->nbits || kex->max < DH_GRP_MIN) {
		r = SSH_ERR_DH_GEX_OUT_OF_RANGE;
		goto out;
	}

	/* Contact privileged parent */
	kex->pk = PRIVSEP(kex_new_dh_group_bits(min, nbits, max));
	if (kex->pk == NULL) {
		(void)sshpkt_disconnect(ssh, "no matching DH grp found");
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}

	if ((r = sshpkt_start(ssh, SSH2_MSG_KEX_DH_GEX_GROUP)) != 0 ||
	    (r = sshpkt_write_dh_group(ssh, kex->pk)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		goto out;
	debug("SSH2_MSG_KEX_DH_GEX_GROUP sent");

	/* Compute our exchange value in parallel with the client */
	if ((r = kex_dh_key_gen(kex)) != 0)
		goto out;

	debug("expecting SSH2_MSG_KEX_DH_GEX_INIT");
	ssh_dispatch_set(ssh, SSH2_MSG_KEX_DH_GEX_INIT, &input_kex_dh_gex_init);
	r = 0;
 out:
	return r;
}

static int
input_kex_dh_gex_init(int type, u_int32_t seq, struct ssh *ssh)
{
	struct kex *kex = ssh->kex;
	BIGNUM *dh_client_pub = NULL;
	struct sshbuf *shared_secret = NULL;
	struct sshbuf *server_host_key_blob = NULL;
	struct sshkey *server_host_public, *server_host_private;
	u_char *signature = NULL;
	u_char hash[SSH_DIGEST_MAX_LENGTH];
	size_t slen, hashlen;
	int r;

	UNUSED(type);
	UNUSED(seq);

	debug("SSH2_MSG_KEX_DH_GEX_INIT received");
	ssh_dispatch_set(ssh, SSH2_MSG_KEX_DH_GEX_INIT, &kex_protocol_error);

	r = kex_load_host_keys(ssh, &server_host_public, &server_host_private);
	if (r != SSH_ERR_SUCCESS)
		goto out;

	/* key, cert */
	if ((r = sshpkt_get_bignum2(ssh, &dh_client_pub)) != 0 ||
	    (r = sshpkt_get_end(ssh)) != 0)
		goto out;
	if ((r = kex_dh_compute_key(kex, dh_client_pub, &shared_secret)) != 0)
		goto out;

	if ((server_host_key_blob = sshbuf_new()) == NULL) {
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	r = Xkey_putb(kex->hostkey_alg, server_host_public, server_host_key_blob);
	if (r != SSH_ERR_SUCCESS) goto out;
#ifdef DEBUG_KEXDH
	dump_digestb("server public key:", server_host_key_blob);
#endif

	/* calc H */
	hashlen = sizeof(hash);
	if ((r = kexgex_hash_server(kex, server_host_key_blob, dh_client_pub,
	    shared_secret, hash, &hashlen )) != 0)
		goto out;

	/* sign H */
{	ssh_sign_ctx ctx = { kex->hostkey_alg, server_host_private, &ssh->compat, NULL, NULL };

	r = kex->xsign(ssh, &ctx, server_host_public, &signature, &slen, hash, hashlen);
	if (r != 0)
		goto out;
}

	/* send server hostkey, DH pubkey 'f' and signed H */
	if ((r = sshpkt_start(ssh, SSH2_MSG_KEX_DH_GEX_REPLY)) != 0 ||
	    (r = sshpkt_put_stringb(ssh, server_host_key_blob)) != 0 ||
	    (r = sshpkt_write_dh_pub(ssh, kex->pk)) != 0 ||
	    (r = sshpkt_put_string(ssh, signature, slen)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		goto out;

	if ((r = kex_derive_keys(ssh, hash, hashlen, shared_secret)) == 0)
		r = kex_send_newkeys(ssh);
 out:
	kex_reset_keys(kex);
	explicit_bzero(hash, sizeof(hash));
	BN_clear_free(dh_client_pub);
	sshbuf_free(shared_secret);
	sshbuf_free(server_host_key_blob);
	free(signature);
	return r;
}
#else

typedef int kexgexs_empty_translation_unit;

#endif /* WITH_OPENSSL */
