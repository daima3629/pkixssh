/* $OpenBSD: ssh_api.c,v 1.32 2024/10/18 05:14:51 djm Exp $ */
/*
 * Copyright (c) 2012 Markus Friedl.  All rights reserved.
 * Copyright (c) 2014-2023 Roumen Petrov.  All rights reserved.
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include "includes.h"

#include <sys/types.h>

#include <stdio.h>
#include <stdlib.h>

#include "ssh_api.h"
#include "evp-compat.h"
#include "log.h"
#include "authfile.h"
#include "sshxkey.h"
#include "misc.h"
#include "ssh2.h"
#include "version.h"
#include "myproposal.h"
#include "ssherr.h"
#include "sshbuf.h"

#include <string.h>

int	_ssh_exchange_banner(struct ssh *);
int	_ssh_send_banner(struct ssh *, struct sshbuf *);
int	_ssh_read_banner(struct ssh *, struct sshbuf *);
int	_ssh_order_hostkeyalgs(struct ssh *);
int	_ssh_verify_host_key(struct sshkey *, struct ssh *);
struct sshkey *_ssh_host_public_key(const char*, struct ssh *);
struct sshkey *_ssh_host_private_key(const char*, struct ssh *);

/*
 * stubs for the server side implementation of kex.
 * disable privsep so our stubs will never be called.
 */
int	use_privsep = 0;

#ifdef WITH_OPENSSL
/* fake implementation for client objects.
 * real for daemon is in monitor_wrap.
 */
EVP_PKEY*	mm_kex_new_dh_group_bits(int, int, int);

EVP_PKEY*
mm_kex_new_dh_group_bits(int min, int nbits, int max)
{
	UNUSED(min); UNUSED(nbits); UNUSED(max);
	return NULL;
}
#endif

static int
_ssh_host_key_sign(
    struct ssh *ssh, ssh_sign_ctx *ctx,
    struct sshkey *pub, u_char **sigp, size_t *lenp,
    const u_char *data, size_t datalen
){
	UNUSED(ssh);
	UNUSED(pub);
	return Xkey_sign(ctx, sigp, lenp, data, datalen);
}

/* API */

static int crypto_status = 0;

void
ssh_crypto_init(void) {
	if (!crypto_status) {
#ifdef WITH_OPENSSL
		ssh_OpenSSL_startup();
#endif /* WITH_OPENSSL */
		crypto_status = 1;
	}
}

void
ssh_crypto_fini(void) {
	if (crypto_status) {
#ifdef WITH_OPENSSL
		ssh_OpenSSL_shuthdown();
#endif /* WITH_OPENSSL */
		crypto_status = 0;
	}
}

int
ssh_init(struct ssh **sshp, int is_server, struct kex_params *kex_params)
{
	char *myproposal[PROPOSAL_MAX] = { KEX_CLIENT };
	struct ssh *ssh;
	char **proposal;
	int r;

	ssh_crypto_init();

	if ((ssh = ssh_packet_set_connection(NULL, -1, -1)) == NULL)
		return SSH_ERR_ALLOC_FAIL;
	if (is_server)
		ssh_packet_set_server(ssh);

	/* Initialize key exchange */
	proposal = kex_params ? kex_params->proposal : myproposal;
	if ((r = kex_ready(ssh, proposal)) != 0) {
		ssh_free(ssh);
		return r;
	}
	if (is_server) {
		ssh->kex->find_host_public_key=&_ssh_host_public_key;
		ssh->kex->find_host_private_key=&_ssh_host_private_key;
		ssh->kex->xsign=&_ssh_host_key_sign;
	} else {
		ssh->kex->verify_host_key =&_ssh_verify_host_key;
	}
	*sshp = ssh;
	return 0;
}

void
ssh_free(struct ssh *ssh)
{
	struct key_entry *k;
	int is_server;

	if (ssh == NULL) return;

	/* NOTE ssh_packet_close free ssh->kex */
	is_server = ssh->kex != NULL && ssh->kex->server;
	ssh_packet_close(ssh);
	/*
	 * we've only created the public keys variants in case we
	 * are a acting as a server.
	 */
	while ((k = TAILQ_FIRST(&ssh->public_keys)) != NULL) {
		TAILQ_REMOVE(&ssh->public_keys, k, next);
		if (is_server)
			sshkey_free(k->key);
		free(k);
	}
	while ((k = TAILQ_FIRST(&ssh->private_keys)) != NULL) {
		TAILQ_REMOVE(&ssh->private_keys, k, next);
		free(k);
	}
	free(ssh);
}

void
ssh_set_app_data(struct ssh *ssh, void *app_data)
{
	ssh->app_data = app_data;
}

void *
ssh_get_app_data(struct ssh *ssh)
{
	return ssh->app_data;
}

/* Returns < 0 on error, 0 otherwise */
int
ssh_add_hostkey(struct ssh *ssh, struct sshkey *key)
{
	struct sshkey *pubkey = NULL;
	struct key_entry *k = NULL, *k_prv = NULL;
	int r;

	if (ssh->kex->server) {
		if ((r = sshkey_from_private(key, &pubkey)) != 0)
			return r;
		if ((k = malloc(sizeof(*k))) == NULL ||
		    (k_prv = malloc(sizeof(*k_prv))) == NULL) {
			free(k);
			sshkey_free(pubkey);
			return SSH_ERR_ALLOC_FAIL;
		}
		k_prv->key = key;
		TAILQ_INSERT_TAIL(&ssh->private_keys, k_prv, next);

		/* add the public key, too */
		k->key = pubkey;
		TAILQ_INSERT_TAIL(&ssh->public_keys, k, next);
		r = 0;
	} else {
		if ((k = malloc(sizeof(*k))) == NULL)
			return SSH_ERR_ALLOC_FAIL;
		k->key = key;
		TAILQ_INSERT_TAIL(&ssh->public_keys, k, next);
		r = 0;
	}

	return r;
}

int
ssh_set_verify_host_key_callback(struct ssh *ssh,
    int (*cb)(struct sshkey *, struct ssh *))
{
	if (cb == NULL || ssh->kex == NULL)
		return SSH_ERR_INVALID_ARGUMENT;

	ssh->kex->verify_host_key = cb;

	return 0;
}

int
ssh_input_append(struct ssh *ssh, const u_char *data, size_t len)
{
	return sshbuf_put(ssh_packet_get_input(ssh), data, len);
}

int
ssh_packet_next(struct ssh *ssh, u_char *typep)
{
	int r;
	u_int32_t seqnr;
	u_char type;

	/*
	 * Try to read a packet. Return SSH_MSG_NONE if no packet or not
	 * enough data.
	 */
	*typep = SSH_MSG_NONE;
	if (sshbuf_len(ssh->kex->client_version) == 0 ||
	    sshbuf_len(ssh->kex->server_version) == 0)
		return _ssh_exchange_banner(ssh);
	/*
	 * If we enough data and a dispatch function then
	 * call the function and get the next packet.
	 * Otherwise return the packet type to the caller so it
	 * can decide how to go on.
	 *
	 * We will only call the dispatch function for:
	 *     20-29    Algorithm negotiation
	 *     30-49    Key exchange method specific (numbers can be reused for
	 *              different authentication methods)
	 */
	for (;;) {
		if ((r = ssh_packet_read_poll2(ssh, &type, &seqnr)) != 0)
			return r;
		if (type > 0 && type < DISPATCH_MAX &&
		    type >= SSH2_MSG_KEXINIT && type <= SSH2_MSG_TRANSPORT_MAX &&
		    ssh->dispatch[type] != NULL) {
			if ((r = (*ssh->dispatch[type])(type, seqnr, ssh)) != 0)
				return r;
		} else {
			*typep = type;
			return 0;
		}
	}
}

const u_char *
ssh_packet_payload(struct ssh *ssh, size_t *lenp)
{
	return sshpkt_ptr(ssh, lenp);
}

int
ssh_packet_put(struct ssh *ssh, int type, const u_char *data, size_t len)
{
	int r;

	if ((r = sshpkt_start(ssh, type)) != 0 ||
	    (r = sshpkt_put(ssh, data, len)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		return r;
	return 0;
}

const u_char *
ssh_output_ptr(struct ssh *ssh, size_t *len)
{
	struct sshbuf *output = ssh_packet_get_output(ssh);

	*len = sshbuf_len(output);
	return sshbuf_ptr(output);
}

int
ssh_output_consume(struct ssh *ssh, size_t len)
{
	return sshbuf_consume(ssh_packet_get_output(ssh), len);
}

int
ssh_output_space(struct ssh *ssh, size_t len)
{
	return (0 == sshbuf_check_reserve(ssh_packet_get_output(ssh), len));
}

int
ssh_input_space(struct ssh *ssh, size_t len)
{
	return (0 == sshbuf_check_reserve(ssh_packet_get_input(ssh), len));
}

/* Read other side's version identification. */
int
_ssh_read_banner(struct ssh *ssh, struct sshbuf *banner)
{
	struct sshbuf *input = ssh_packet_get_input(ssh);
	const char *mismatch = "Protocol mismatch.\r\n";
	const u_char *s = sshbuf_ptr(input);
	u_char c;
	char *cp = NULL, *remote_version = NULL;
	int r = 0, remote_major, remote_minor, expect_nl;
	size_t n, j;

	for (j = n = 0;;) {
		sshbuf_reset(banner);
		expect_nl = 0;
		for (;;) {
			if (j >= sshbuf_len(input))
				return 0; /* insufficient data in input buf */
			c = s[j++];
			if (c == '\r') {
				expect_nl = 1;
				continue;
			}
			if (c == '\n')
				break;
			if (expect_nl)
				goto bad;
			if ((r = sshbuf_put_u8(banner, c)) != 0)
				return r;
			if (sshbuf_len(banner) > SSH_MAX_BANNER_LEN)
				goto bad;
		}
		if (sshbuf_len(banner) >= 4 &&
		    memcmp(sshbuf_ptr(banner), "SSH-", 4) == 0)
			break;
		debug_f("%.*s", (int)sshbuf_len(banner),
		    sshbuf_ptr(banner));
		/* Accept lines before banner only on client */
		if (ssh->kex->server || ++n > SSH_MAX_PRE_BANNER_LINES) {
  bad:
			if ((r = sshbuf_put(ssh_packet_get_output(ssh),
			    mismatch, strlen(mismatch))) != 0)
				return r;
			return SSH_ERR_NO_PROTOCOL_VERSION;
		}
	}
	if ((r = sshbuf_consume(input, j)) != 0)
		return r;

	/* XXX remote version must be the same size as banner for sscanf */
	if ((cp = sshbuf_dup_string(banner)) == NULL ||
	    (remote_version = calloc(1, sshbuf_len(banner))) == NULL) {
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}

	/*
	 * Check that the versions match.  In future this might accept
	 * several versions and set appropriate flags to handle them.
	 */
	if (sscanf(cp, "SSH-%d.%d-%[^\n]\n",
	    &remote_major, &remote_minor, remote_version) != 3) {
		r = SSH_ERR_INVALID_FORMAT;
		goto out;
	}
	debug("Remote protocol version %d.%d, remote software version %.100s",
	    remote_major, remote_minor, remote_version);

	ssh_set_compatibility(ssh, remote_version);

	if  (remote_major == 1 && remote_minor == 99) {
		remote_major = 2;
		remote_minor = 0;
	}
	if (remote_major != 2) {
		r = SSH_ERR_PROTOCOL_MISMATCH;
		goto out;
	}

	debug("Remote version string %.100s", cp);
 out:
	free(cp);
	free(remote_version);
	return r;
}

/* Send our own protocol version identification. */
int
_ssh_send_banner(struct ssh *ssh, struct sshbuf *banner)
{
	char *cp;
	int r;

	if ((r = sshbuf_putf(banner, "SSH-2.0-%.100s\r\n", SSH_VERSION)) != 0)
		return r;
	if ((r = sshbuf_putb(ssh_packet_get_output(ssh), banner)) != 0)
		return r;
	/* Remove trailing \r\n */
	if ((r = sshbuf_consume_end(banner, 2)) != 0)
		return r;
	if ((cp = sshbuf_dup_string(banner)) == NULL)
		return SSH_ERR_ALLOC_FAIL;
	debug("Local version string %.100s", cp);
	free(cp);
	return 0;
}

int
_ssh_exchange_banner(struct ssh *ssh)
{
	int r;

	/*
	 * if _ssh_read_banner() cannot parse a full version string
	 * it will return NULL and we end up calling it again.
	 */

	r = 0;
	if (ssh->kex->server) {
		if (sshbuf_len(ssh->kex->server_version) == 0)
			r = _ssh_send_banner(ssh, ssh->kex->server_version);
		if (r == 0 &&
		    sshbuf_len(ssh->kex->server_version) != 0 &&
		    sshbuf_len(ssh->kex->client_version) == 0)
			r = _ssh_read_banner(ssh, ssh->kex->client_version);
	} else {
		if (sshbuf_len(ssh->kex->server_version) == 0)
			r = _ssh_read_banner(ssh, ssh->kex->server_version);
		if (r == 0 &&
		    sshbuf_len(ssh->kex->server_version) != 0 &&
		    sshbuf_len(ssh->kex->client_version) == 0)
			r = _ssh_send_banner(ssh, ssh->kex->client_version);
	}
	if (r != 0)
		return r;
	/* start initial kex as soon as we have exchanged the banners */
	if (sshbuf_len(ssh->kex->server_version) != 0 &&
	    sshbuf_len(ssh->kex->client_version) != 0) {
		if ((r = _ssh_order_hostkeyalgs(ssh)) != 0 ||
		    (r = kex_send_kexinit(ssh)) != 0)
			return r;
	}
	return 0;
}

struct sshkey *
_ssh_host_public_key(const char* pkalg, struct ssh *ssh)
{
	struct key_entry *k;

	debug3_f("need %s", pkalg);
	TAILQ_FOREACH(k, &ssh->public_keys, next) {
		debug3_f("check %s", sshkey_type(k->key));
		if (sshkey_match_pkalg(k->key, pkalg))
			return (k->key);
	}
	return (NULL);
}

struct sshkey *
_ssh_host_private_key(const char* pkalg, struct ssh *ssh)
{
	struct key_entry *k;

	debug3_f("need %s", pkalg);
	TAILQ_FOREACH(k, &ssh->private_keys, next) {
		debug3_f("check %s", sshkey_type(k->key));
		if (sshkey_match_pkalg(k->key, pkalg))
			return (k->key);
	}
	return (NULL);
}

int
_ssh_verify_host_key(struct sshkey *hostkey, struct ssh *ssh)
{
	struct key_entry *k;

	debug3_f("need %s", sshkey_type(hostkey));
	TAILQ_FOREACH(k, &ssh->public_keys, next) {
		debug3_f("check %s", sshkey_type(k->key));
		if (sshkey_equal_public(hostkey, k->key))
			return (0);	/* ok */
	}
	return (-1);	/* failed */
}

/* offer hostkey algorithms in kexinit depending on registered keys */
int
_ssh_order_hostkeyalgs(struct ssh *ssh)
{
	struct key_entry *k;
	char *orig, *avail, *oavail = NULL, *alg, *replace = NULL;
	char **proposal;
	size_t maxlen;
	int r;

	/* XXX we de-serialize ssh->kex->my, modify it, and change it */
	if ((r = kex_buf2prop(ssh->kex->my, NULL, &proposal)) != 0)
		return r;
	orig = proposal[PROPOSAL_SERVER_HOST_KEY_ALGS];
	if ((oavail = avail = strdup(orig)) == NULL) {
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	maxlen = strlen(avail) + 1;
	if ((replace = calloc(1, maxlen)) == NULL) {
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	*replace = '\0';
	while ((alg = strsep(&avail, ",")) && *alg != '\0') {
		int ktype, nid;

		ktype = sshkey_type_from_name(alg);
		if (ktype == KEY_UNSPEC) continue;
		nid = sshkey_ecdsa_nid_from_name(alg);

		TAILQ_FOREACH(k, &ssh->public_keys, next) {
			if (k->key->type != ktype &&
			    (!sshkey_is_cert(k->key) ||
			    k->key->type != sshkey_type_plain(ktype)))
				continue;
			if (sshkey_type_plain(k->key->type) == KEY_ECDSA &&
			    k->key->ecdsa_nid != nid)
				continue;

			/* candidate */
			if (*replace != '\0')
				strlcat(replace, ",", maxlen);
			strlcat(replace, alg, maxlen);
			break;
		}
	}
	if (*replace != '\0') {
		debug2_f("orig/%d    %s", ssh->kex->server, orig);
		debug2_f("replace/%d %s", ssh->kex->server, replace);
		free(orig);
		proposal[PROPOSAL_SERVER_HOST_KEY_ALGS] = replace;
		replace = NULL;	/* owned by proposal */
		r = kex_prop2buf(ssh->kex->my, proposal);
	}
 out:
	free(oavail);
	free(replace);
	kex_prop_free(proposal);
	return r;
}
