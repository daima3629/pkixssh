/* $OpenBSD: kexc25519s.c,v 1.14 2019/01/21 09:55:52 djm Exp $ */
/*
 * Copyright (c) 2001 Markus Friedl.  All rights reserved.
 * Copyright (c) 2010 Damien Miller.  All rights reserved.
 * Copyright (c) 2013 Aris Adamantiadis.  All rights reserved.
 *
 * Copyright (c) 2014-2019 Roumen Petrov.  All rights reserved.
 *
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
#include <signal.h>

#include "sshxkey.h"
#include "cipher.h"
#include "digest.h"
#include "kex.h"
#include "log.h"
#include "packet.h"
#include "ssh2.h"
#include "compat.h"
#include "sshbuf.h"
#include "ssherr.h"

static int input_kex_c25519_init(int, u_int32_t, struct ssh *);

int
kexc25519_server(struct ssh *ssh)
{
	debug("expecting SSH2_MSG_KEX_ECDH_INIT");
	ssh_dispatch_set(ssh, SSH2_MSG_KEX_ECDH_INIT, &input_kex_c25519_init);
	return 0;
}

static int
input_kex_c25519_init(int type, u_int32_t seq, struct ssh *ssh)
{
	struct kex *kex = ssh->kex;
	struct sshkey *server_host_private, *server_host_public;
	struct sshbuf *shared_secret = NULL;
	struct sshbuf *server_host_key_blob = NULL;
	u_char *signature = NULL;
	u_char server_key[CURVE25519_SIZE];
	u_char *client_pubkey = NULL;
	u_char server_pubkey[CURVE25519_SIZE];
	u_char hash[SSH_DIGEST_MAX_LENGTH];
	size_t slen, pklen, hashlen;
	int r;

	UNUSED(type);
	UNUSED(seq);
	/* generate private key */
	kexc25519_keygen(server_key, server_pubkey);
#ifdef DEBUG_KEXECDH
	dump_digest("server private key:", server_key, sizeof(server_key));
#endif

	r = kex_load_host_keys(ssh, &server_host_public, &server_host_private);
	if (r != SSH_ERR_SUCCESS)
		goto out;

	if ((r = sshpkt_get_string(ssh, &client_pubkey, &pklen)) != 0 ||
	    (r = sshpkt_get_end(ssh)) != 0)
		goto out;
	if (pklen != CURVE25519_SIZE) {
		r = SSH_ERR_SIGNATURE_INVALID;
		goto out;
	}
#ifdef DEBUG_KEXECDH
	dump_digest("client public key:", client_pubkey, CURVE25519_SIZE);
#endif

	if ((shared_secret = sshbuf_new()) == NULL) {
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	if ((r = kexc25519_shared_key(server_key, client_pubkey,
	    shared_secret)) < 0)
		goto out;

	if ((server_host_key_blob = sshbuf_new()) == NULL) {
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	r = Xkey_putb(kex->hostkey_alg, server_host_public, server_host_key_blob);
	if (r != SSH_ERR_SUCCESS) goto out;
#ifdef DEBUG_KEXECDH
	dump_digestb("server public key:", server_host_key_blob);
#endif

	/* calc H */
	hashlen = sizeof(hash);
	if ((r = kex_c25519_hash(
	    kex->hash_alg,
	    kex->client_version,
	    kex->server_version,
	    kex->peer,
	    kex->my,
	    server_host_key_blob,
	    client_pubkey,
	    server_pubkey,
	    sshbuf_ptr(shared_secret), sshbuf_len(shared_secret),
	    hash, &hashlen)) < 0)
		goto out;

	/* sign H */
{	ssh_sign_ctx ctx = { kex->hostkey_alg, server_host_private, &ssh->compat };

	r = kex->xsign(ssh, &ctx, server_host_public, &signature, &slen, hash, hashlen);
	if (r != 0)
		goto out;
}

	/* send server hostkey, ECDH pubkey 'Q_S' and signed H */
	if ((r = sshpkt_start(ssh, SSH2_MSG_KEX_ECDH_REPLY)) != 0 ||
	    (r = sshpkt_put_stringb(ssh, server_host_key_blob)) != 0 ||
	    (r = sshpkt_put_string(ssh, server_pubkey, sizeof(server_pubkey))) != 0 ||
	    (r = sshpkt_put_string(ssh, signature, slen)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		goto out;

	if ((r = kex_derive_keys(ssh, hash, hashlen, shared_secret)) == 0)
		r = kex_send_newkeys(ssh);
out:
	explicit_bzero(hash, sizeof(hash));
	explicit_bzero(server_key, sizeof(server_key));
	sshbuf_free(server_host_key_blob);
	free(signature);
	free(client_pubkey);
	sshbuf_free(shared_secret);
	return r;
}
