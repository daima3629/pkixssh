/* $OpenBSD: kex.c,v 1.186 2024/05/17 00:30:23 djm Exp $ */
/*
 * Copyright (c) 2000, 2001 Markus Friedl.  All rights reserved.
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

#include "includes.h"

#include <sys/types.h>
#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "xmalloc.h"
#include "ssh.h"
#include "ssh2.h"
#include "atomicio.h"
#include "packet.h"
#include "compat.h"
#include "cipher.h"
#include "sshkey.h"
#include "kex.h"
#include "log.h"
#include "mac.h"
#include "match.h"
#include "misc.h"
#include "dispatch.h"
#include "monitor.h"

#include "ssherr.h"
#include "sshbuf.h"
#include "digest.h"
#include "xmalloc.h"

const char *srv_extinfo_pkalgs = "publickey-algorithms@roumenpetrov.info";
char *server_pkalgs = NULL;

/* prototype */
static int kex_choose_conf(struct ssh *, uint32_t seq);
static int kex_input_newkeys(int, u_int32_t, struct ssh *);

static const char * const proposal_names[PROPOSAL_MAX] = {
	"KEX algorithms",
	"host key algorithms",
	"ciphers ctos",
	"ciphers stoc",
	"MACs ctos",
	"MACs stoc",
	"compression ctos",
	"compression stoc",
	"languages ctos",
	"languages stoc",
};

/*
 * Fill out a proposal array with dynamically allocated values, which may
 * be modified as required for compatibility reasons.
 * Any of the options may be NULL, in which case the default is used.
 * Array contents must be freed by calling kex_proposal_free_entries.
 */
void
kex_proposal_populate_entries(struct ssh *ssh, char *prop[PROPOSAL_MAX],
    char *kexalgos, const char *ciphers, const char *macs,
    const char *comp, const char *hkalgs)
{
	u_int i;

	if (prop == NULL)
		fatal_f("proposal missing");

	for (i = 0; i < PROPOSAL_MAX; i++) {
		switch(i) {
		case PROPOSAL_KEX_ALGS:
			prop[i] = compat_kex_proposal(ssh, kexalgos);
			break;
		case PROPOSAL_ENC_ALGS_CTOS:
		case PROPOSAL_ENC_ALGS_STOC:
			prop[i] = xstrdup(ciphers != NULL ? ciphers : prop[i]);
			break;
		case PROPOSAL_MAC_ALGS_CTOS:
		case PROPOSAL_MAC_ALGS_STOC:
			prop[i]  = xstrdup(macs != NULL ? macs : prop[i]);
			break;
		case PROPOSAL_COMP_ALGS_CTOS:
		case PROPOSAL_COMP_ALGS_STOC:
			prop[i] = xstrdup(comp != NULL ? comp : prop[i]);
			break;
		case PROPOSAL_SERVER_HOST_KEY_ALGS:
			prop[i] = xstrdup(hkalgs != NULL ? hkalgs : prop[i]);
			break;
		default:
			prop[i] = xstrdup(prop[i]);
		}
	}
}

void
kex_proposal_free_entries(char *prop[PROPOSAL_MAX])
{
	u_int i;

	for (i = 0; i < PROPOSAL_MAX; i++)
		free(prop[i]);
}

/* put algorithm proposal into buffer */
int
kex_prop2buf(struct sshbuf *b, char *proposal[PROPOSAL_MAX])
{
	u_int i;
	int r;

	sshbuf_reset(b);

	/*
	 * add a dummy cookie, the cookie will be overwritten by
	 * kex_send_kexinit(), each time a kexinit is set
	 */
	for (i = 0; i < KEX_COOKIE_LEN; i++) {
		if ((r = sshbuf_put_u8(b, 0)) != 0)
			return r;
	}
	for (i = 0; i < PROPOSAL_MAX; i++) {
		if ((r = sshbuf_put_cstring(b, proposal[i])) != 0)
			return r;
	}
	if ((r = sshbuf_put_u8(b, 0)) != 0 ||	/* first_kex_packet_follows */
	    (r = sshbuf_put_u32(b, 0)) != 0)	/* uint32 reserved */
		return r;
	return 0;
}

/* parse buffer and return algorithm proposal */
int
kex_buf2prop(struct sshbuf *raw, int *first_kex_follows, char ***propp)
{
	struct sshbuf *b = NULL;
	u_char v;
	u_int i;
	char **proposal = NULL;
	int r;

	*propp = NULL;
	if ((proposal = calloc(PROPOSAL_MAX, sizeof(char *))) == NULL)
		return SSH_ERR_ALLOC_FAIL;
	if ((b = sshbuf_fromb(raw)) == NULL) {
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	if ((r = sshbuf_consume(b, KEX_COOKIE_LEN)) != 0) { /* skip cookie */
		error_fr(r, "consume cookie");
		goto out;
	}
	/* extract kex init proposal strings */
	for (i = 0; i < PROPOSAL_MAX; i++) {
		if ((r = sshbuf_get_cstring(b, &(proposal[i]), NULL)) != 0) {
			error_fr(r, "parse proposal %u", i);
			goto out;
		}
		debug2("%s: %s", proposal_names[i], proposal[i]);
	}
	/* first kex follows / reserved */
	if ((r = sshbuf_get_u8(b, &v)) != 0 ||	/* first_kex_follows */
	    (r = sshbuf_get_u32(b, &i)) != 0) {	/* reserved */
		error_fr(r, "parse");
		goto out;
	}
	if (first_kex_follows != NULL)
		*first_kex_follows = v;
	debug2("first_kex_follows %d ", v);
	debug2("reserved %u ", i);
	r = 0;
	*propp = proposal;
 out:
	if (r != 0 && proposal != NULL)
		kex_prop_free(proposal);
	sshbuf_free(b);
	return r;
}

void
kex_prop_free(char **proposal)
{
	u_int i;

	if (proposal == NULL)
		return;
	for (i = 0; i < PROPOSAL_MAX; i++)
		free(proposal[i]);
	free(proposal);
}

int
kex_protocol_error(int type, u_int32_t seq, struct ssh *ssh)
{
	int r;

	/* If in strict mode, any unexpected message is an error */
	if ((ssh->kex->flags & KEX_INITIAL) && ssh->kex->kex_strict) {
		ssh_packet_disconnect(ssh, "strict KEX violation: "
		    "unexpected packet type %u (seqnr %u)", type, seq);
	}
	error_f("type %u seq %u", type, seq);
	if ((r = sshpkt_start(ssh, SSH2_MSG_UNIMPLEMENTED)) != 0 ||
	    (r = sshpkt_put_u32(ssh, seq)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		return r;
	return 0;
}

static void
kex_reset_dispatch(struct ssh *ssh)
{
	ssh_dispatch_range(ssh, SSH2_MSG_TRANSPORT_MIN,
	    SSH2_MSG_TRANSPORT_MAX, &kex_protocol_error);
}

static int
kex_compose_ext_info_pkalgs(struct ssh *ssh, struct sshbuf *m, int *count) {
	struct sshbuf *tmp = NULL;
	int r;

	UNUSED(ssh);
	*count = 0;
	if (server_pkalgs == NULL) return 0;

	if ((tmp = sshbuf_new()) == NULL)
		fatal_f("sshbuf_new failed");

	if (
	    (r = sshbuf_put_cstring(tmp, srv_extinfo_pkalgs)) != 0 ||
	    (r = sshbuf_put_cstring(tmp, server_pkalgs)) != 0 ||
	    (r = sshbuf_put_cstring(tmp, "server-sig-algs")) != 0 ||
	    (r = sshbuf_put_cstring(tmp, server_pkalgs)) != 0) {
		error_fr(r, "compose");
		goto out;
	}

	r = sshbuf_putb(m, tmp);
	if (r == 0) *count = 2;

out:
	sshbuf_free(tmp);
	return r;
}

static int
kex_compose_ext_info_server(struct ssh *ssh, struct sshbuf *m, int *count)
{
	int r, k;

	k = 0;
	r = kex_compose_ext_info_pkalgs(ssh, m, &k);
	if (r != 0) {
		error_fr(r, "kex_compose_ext_info_pkalgs failed");
		goto out;
	}
	*count += k;

	/* TODO: other extensions ? */

out:
	return r;
}

static int
kex_maybe_send_ext_info(struct ssh *ssh)
{
	int r, count = 0;
	struct sshbuf *m = NULL;

	if ((ssh->kex->flags & KEX_INITIAL) == 0)
		return 0;
	/* TODO: server extensions ? */
	if (!ssh->kex->ext_info_c)
		return 0;

	if ((m = sshbuf_new()) == NULL)
		fatal_f("sshbuf_new failed");

	if (ssh->kex->ext_info_c) {
		r = kex_compose_ext_info_server(ssh, m, &count);
		if (r != 0) goto out;
	}

	debug("sending(?) SSH2_MSG_EXT_INFO items: %d", count);
	if (count <= 0) goto out;

	if (
	    (r = sshpkt_start(ssh, SSH2_MSG_EXT_INFO)) != 0 ||
	    (r = sshpkt_put_u32(ssh, count)) != 0 ||
	    (r = sshpkt_putb(ssh, m)) != 0) {
		error_fr(r, "compose");
		goto out;
	}

	r = sshpkt_send(ssh);

out:
	sshbuf_free(m);
	return r;
}

int
kex_send_newkeys(struct ssh *ssh)
{
	int r;

	kex_reset_dispatch(ssh);
	if ((r = sshpkt_start(ssh, SSH2_MSG_NEWKEYS)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		return r;
	debug("SSH2_MSG_NEWKEYS sent");
	ssh_dispatch_set(ssh, SSH2_MSG_NEWKEYS, &kex_input_newkeys);

	if ((r = kex_maybe_send_ext_info(ssh)) != 0)
		return r;

	debug("expecting SSH2_MSG_NEWKEYS");
	return 0;
}

static void
preset_pkalgs(struct kex *kex, char *pkalgs) {
	size_t n = 0;

	free(kex->pkalgs);
	kex->pkalgs = NULL;

	if (pkalgs == NULL) return;

{	char *alg, *q = pkalgs, *new_pkalgs = NULL;

	for (alg = strsep(&q, ","); alg != NULL; alg = strsep(&q, ",")) {
		size_t len;
		int type = sshkey_type_from_name(alg);

		if (type == KEY_UNSPEC) {
			debug3_f("unsupported public-key algorithm: %.100s", alg);
			continue;
		}

		len = strlen(alg);
		new_pkalgs = realloc(new_pkalgs, n + len + 1);
		if (new_pkalgs == NULL) goto done;

		memmove(new_pkalgs + n, alg, len);
		n += len;
		new_pkalgs[n++] = ',';
	}
	if (new_pkalgs != NULL)
		new_pkalgs[--n] = '\0';

	kex->pkalgs = new_pkalgs;
done:
	free(pkalgs);
}
}

int
kex_input_ext_info(int type, u_int32_t seq, struct ssh *ssh)
{
	struct kex *kex = ssh->kex;
	u_int32_t i, ninfo;
	char *name;
	u_char *val;
	size_t vlen;
	char *pkalgs = NULL, *sigalgs = NULL;
	int r;

	debug("SSH2_MSG_EXT_INFO received");
	ssh_dispatch_set(ssh, SSH2_MSG_EXT_INFO, &kex_protocol_error);

	if ((r = sshpkt_get_u32(ssh, &ninfo)) != 0)
		return r;
	if (ninfo >= 1024) {
		error("SSH2_MSG_EXT_INFO with too many entries, expected "
		    "<=1024, received %u", ninfo);
		return dispatch_protocol_error(type, seq, ssh);
	}
	for (i = 0; i < ninfo; i++) {
		if ((r = sshpkt_get_cstring(ssh, &name, NULL)) != 0)
			return r;
		if ((r = sshpkt_get_string(ssh, &val, &vlen)) != 0) {
			free(name);
			return r;
		}
		if (strcmp(name, srv_extinfo_pkalgs) == 0) {
			/* Ensure no \0 lurking in value */
			if (memchr(val, '\0', vlen) != NULL) {
				error_f("nul byte in %s", name);
				return SSH_ERR_INVALID_FORMAT;
			}
			debug_f("%s=<%s>", name, val);
			pkalgs = val;
			free(name);
			continue;
		}
		if (strcmp(name, "server-sig-algs") == 0) {
			/* Ensure no \0 lurking in value */
			if (memchr(val, '\0', vlen) != NULL) {
				error_f("nul byte in %s", name);
				return SSH_ERR_INVALID_FORMAT;
			}
			debug_f("%s=<%s>", name, val);
			sigalgs = val;
			free(name);
			continue;
		}
		debug3_f("%s (unsupported)", name);
		free(name);
		free(val);
	}
	if (pkalgs != NULL) {
		free(sigalgs);
		preset_pkalgs(kex, pkalgs);
	} else {
		if (ssh_compat_extra(ssh, SSHX_OPENSSH_BROKEN_ALGO_INFO)) {
			free(sigalgs);
			/* use list as is properly announced in OpenSSH 7.5 */
			sigalgs = strdup(
				"ssh-ed25519,ssh-rsa,rsa-sha2-256,rsa-sha2-512,ssh-dss,"
				"ecdsa-sha2-nistp256,ecdsa-sha2-nistp384,ecdsa-sha2-nistp521");
		}
		preset_pkalgs(kex, sigalgs);
	}

	return sshpkt_get_end(ssh);
}

static int
kex_input_newkeys(int type, u_int32_t seq, struct ssh *ssh)
{
	struct kex *kex = ssh->kex;
	int r;

	UNUSED(type);
	UNUSED(seq);

	debug("SSH2_MSG_NEWKEYS received");
	ssh_dispatch_set(ssh, SSH2_MSG_NEWKEYS, &kex_protocol_error);
	ssh_dispatch_set(ssh, SSH2_MSG_KEXINIT, &kex_input_kexinit);

	if ((r = sshpkt_get_end(ssh)) != 0)
		return r;
	if ((r = ssh_set_newkeys(ssh, MODE_IN)) != 0)
		return r;
	kex->done = 1;
	kex->flags &= ~KEX_INITIAL;
	sshbuf_reset(kex->peer);
	/* sshbuf_reset(kex->my); */
	kex->flags &= ~KEX_INIT_SENT;

#if 0	/* keep for later use */
	free(kex->hostkey_alg);
	kex->hostkey_alg = NULL;
#endif

	free(kex->name);
	kex->name = NULL;
	return 0;
}

int
kex_send_kexinit(struct ssh *ssh)
{
	u_char *cookie;
	struct kex *kex = ssh->kex;
	int r;

	if (kex == NULL) {
		error_f("no kex");
		return SSH_ERR_INTERNAL_ERROR;
	}
	if (kex->flags & KEX_INIT_SENT)
		return 0;
	kex->done = 0;

	/* generate a random cookie */
	if (sshbuf_len(kex->my) < KEX_COOKIE_LEN) {
		error_f("bad kex length: %zu < %d",
		    sshbuf_len(kex->my), KEX_COOKIE_LEN);
		return SSH_ERR_INVALID_FORMAT;
	}
	if ((cookie = sshbuf_mutable_ptr(kex->my)) == NULL) {
		error_f("buffer error");
		return SSH_ERR_INTERNAL_ERROR;
	}
	arc4random_buf(cookie, KEX_COOKIE_LEN);

	if ((r = sshpkt_start(ssh, SSH2_MSG_KEXINIT)) != 0 ||
	    (r = sshpkt_putb(ssh, kex->my)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0) {
		error_fr(r, "compose reply");
		return r;
	}
	debug("SSH2_MSG_KEXINIT sent");
	kex->flags |= KEX_INIT_SENT;
	return 0;
}

int
kex_input_kexinit(int type, u_int32_t seq, struct ssh *ssh)
{
	struct kex *kex = ssh->kex;
	const u_char *ptr;
	u_int i;
	size_t dlen;
	int r;

	UNUSED(type);
	UNUSED(seq);

	debug("SSH2_MSG_KEXINIT received");
	if (kex == NULL) {
		error_f("no kex");
		return SSH_ERR_INTERNAL_ERROR;
	}
	ssh_dispatch_set(ssh, SSH2_MSG_KEXINIT, &kex_protocol_error);

	ptr = sshpkt_ptr(ssh, &dlen);
	if ((r = sshbuf_put(kex->peer, ptr, dlen)) != 0)
		return r;

	/* discard packet */
	for (i = 0; i < KEX_COOKIE_LEN; i++) {
		if ((r = sshpkt_get_u8(ssh, NULL)) != 0) {
			error_fr(r, "discard cookie");
			return r;
		}
	}
	for (i = 0; i < PROPOSAL_MAX; i++) {
		if ((r = sshpkt_get_string(ssh, NULL, NULL)) != 0) {
			error_fr(r, "discard proposal");
			return r;
		}
	}
	/*
	 * XXX RFC4253 sec 7: "each side MAY guess" - currently no supported
	 * KEX method has the server move first, but a server might be using
	 * a custom method or one that we otherwise don't support. We should
	 * be prepared to remember first_kex_follows here so we can eat a
	 * packet later.
	 * XXX2 - RFC4253 is kind of ambiguous on what first_kex_follows means
	 * for cases where the server *doesn't* go first. I guess we should
	 * ignore it when it is set for these cases, which is what we do now.
	 */
	if ((r = sshpkt_get_u8(ssh, NULL)) != 0 ||	/* first_kex_follows */
	    (r = sshpkt_get_u32(ssh, NULL)) != 0 ||	/* reserved */
	    (r = sshpkt_get_end(ssh)) != 0)
			return r;

	if (!(kex->flags & KEX_INIT_SENT))
		if ((r = kex_send_kexinit(ssh)) != 0)
			return r;
	if ((r = kex_choose_conf(ssh, seq)) != 0)
		return r;

	/* implementation already selected - kex_choose_conf(...)->choose_kex(...) */
	return kex->impl->funcs->init(ssh);
}

struct kex *
kex_new(void)
{
	struct kex *kex;

	if ((kex = calloc(1, sizeof(*kex))) == NULL ||
	    (kex->peer = sshbuf_new()) == NULL ||
	    (kex->my = sshbuf_new()) == NULL ||
	    (kex->client_version = sshbuf_new()) == NULL ||
	    (kex->server_version = sshbuf_new()) == NULL ||
	    (kex->session_id = sshbuf_new()) == NULL) {
		kex_free(kex);
		return NULL;
	}
	return kex;
}

void
kex_free_newkeys(struct newkeys *newkeys)
{
	if (newkeys == NULL)
		return;
	if (newkeys->enc.key) {
		freezero(newkeys->enc.key, newkeys->enc.key_len);
		newkeys->enc.key = NULL;
	}
	if (newkeys->enc.iv) {
		freezero(newkeys->enc.iv, newkeys->enc.iv_len);
		newkeys->enc.iv = NULL;
	}
	free(newkeys->enc.name);
	explicit_bzero(&newkeys->enc, sizeof(newkeys->enc));
	free(newkeys->comp.name);
	explicit_bzero(&newkeys->comp, sizeof(newkeys->comp));
	mac_clear(&newkeys->mac);
	if (newkeys->mac.key) {
		freezero(newkeys->mac.key, newkeys->mac.key_len);
		newkeys->mac.key = NULL;
	}
	free(newkeys->mac.name);
	explicit_bzero(&newkeys->mac, sizeof(newkeys->mac));
	freezero(newkeys, sizeof(*newkeys));
}

static inline void
kex_reset_crypto_keys(struct kex *kex) {
#ifdef WITH_OPENSSL
	EVP_PKEY_free(kex->pk);
	kex->pk = NULL;
#
	UNUSED(kex);
#endif
}

void
kex_reset_keys(struct kex *kex) {
	kex_reset_crypto_keys(kex);
#ifndef USE_ECDH_X25519
	explicit_bzero(kex->c25519_key, sizeof(kex->c25519_key));
#endif
}

void
kex_free(struct kex *kex)
{
	u_int mode;

	if (kex == NULL) return;

	for (mode = 0; mode < MODE_MAX; mode++) {
		kex_free_newkeys(kex->newkeys[mode]);
		kex->newkeys[mode] = NULL;
	}
	sshbuf_free(kex->peer);
	sshbuf_free(kex->my);
	sshbuf_free(kex->client_version);
	sshbuf_free(kex->server_version);
	sshbuf_free(kex->session_id);
	sshbuf_free(kex->client_pub);
	free(kex->failed_choice);
	free(kex->hostkey_alg);
	free(kex->pkalgs);
	free(kex->name);
	free(kex);
}

int
kex_ready(struct ssh *ssh, char *proposal[PROPOSAL_MAX])
{
	int r;

	if (ssh->kex == NULL) return SSH_ERR_INTERNAL_ERROR;

	if ((r = kex_prop2buf(ssh->kex->my, proposal)) != 0)
		return r;
	ssh->kex->flags = KEX_INITIAL;
	kex_reset_dispatch(ssh);
	ssh_dispatch_set(ssh, SSH2_MSG_KEXINIT, &kex_input_kexinit);
	return 0;
}

int
kex_setup(struct ssh *ssh, char *proposal[PROPOSAL_MAX])
{
	int r;

	if ((r = kex_ready(ssh, proposal)) != 0)
		return r;
	if ((r = kex_send_kexinit(ssh)) != 0) {		/* we start */
		kex_free(ssh->kex);
		ssh->kex = NULL;
		return r;
	}
	return 0;
}

/*
 * Request key re-exchange, returns 0 on success or a ssherr.h error
 * code otherwise. Must not be called if KEX is incomplete or in-progress.
 */
int
kex_start_rekex(struct ssh *ssh)
{
	if (ssh->kex == NULL) {
		error_f("no kex");
		return SSH_ERR_INTERNAL_ERROR;
	}
	if (ssh->kex->done == 0) {
		error_f("requested twice");
		return SSH_ERR_INTERNAL_ERROR;
	}
	ssh->kex->done = 0;
	return kex_send_kexinit(ssh);
}

static int
choose_enc(struct sshenc *enc, char *client, char *server)
{
	char *name = match_list(client, server, NULL);

	if (name == NULL)
		return SSH_ERR_NO_CIPHER_ALG_MATCH;
	if ((enc->cipher = cipher_by_name(name)) == NULL) {
		error_f("unsupported cipher %s", name);
		free(name);
		return SSH_ERR_INTERNAL_ERROR;
	}
	enc->name = name;
	enc->enabled = 0;
	enc->iv = NULL;
	enc->iv_len = cipher_ivlen(enc->cipher);
	enc->key = NULL;
	enc->key_len = cipher_keylen(enc->cipher);
	enc->block_size = cipher_blocksize(enc->cipher);
	return 0;
}

static int
choose_mac(struct ssh *ssh, struct sshmac *mac, char *client, char *server)
{
	char *name = match_list(client, server, NULL);

	UNUSED(ssh);
	if (name == NULL)
		return SSH_ERR_NO_MAC_ALG_MATCH;
	if (mac_setup(mac, name) < 0) {
		error_f("unsupported MAC %s", name);
		free(name);
		return SSH_ERR_INTERNAL_ERROR;
	}
	mac->name = name;
	mac->key = NULL;
	mac->enabled = 0;
	return 0;
}

static int
choose_comp(struct sshcomp *comp, char *client, char *server)
{
	char *name = match_list(client, server, NULL);

	if (name == NULL)
		return SSH_ERR_NO_COMPRESS_ALG_MATCH;
#ifdef WITH_ZLIB
	if (strcmp(name, "zlib@openssh.com") == 0) {
		comp->type = COMP_DELAYED;
	} else if (strcmp(name, "zlib") == 0) {
		comp->type = COMP_ZLIB;
	} else
#endif	/* WITH_ZLIB */
	if (strcmp(name, "none") == 0) {
		comp->type = COMP_NONE;
	} else {
		error_f("unsupported compression scheme %s", name);
		free(name);
		return SSH_ERR_INTERNAL_ERROR;
	}
	comp->name = name;
	return 0;
}

static int
choose_kex(struct kex *k, char *client, char *server)
{
	k->name = match_list(client, server, NULL);

	debug("kex: algorithm: %s", k->name ? k->name : "(no match)");
	if (k->name == NULL)
		return SSH_ERR_NO_KEX_ALG_MATCH;
	k->impl = kex_find_impl(k->name);
	if (k->impl == NULL) {
		error_f("unsupported KEX method %s", k->name);
		return SSH_ERR_INTERNAL_ERROR;
	}
	return 0;
}

static int
choose_hostkeyalg(struct kex *k, char *client, char *server)
{
	free(k->hostkey_alg);
	k->hostkey_alg = match_list(client, server, NULL);

	debug("kex: host key algorithm: %s",
	    k->hostkey_alg ? k->hostkey_alg : "(no match)");
	if (k->hostkey_alg == NULL)
		return SSH_ERR_NO_HOSTKEY_ALG_MATCH;
	if (sshkey_type_from_name(k->hostkey_alg) == KEY_UNSPEC) {
		error_f("unsupported hostkey algorithm %s", k->hostkey_alg);
		return SSH_ERR_INTERNAL_ERROR;
	}
	return 0;
}

static int
proposals_match(char *my[PROPOSAL_MAX], char *peer[PROPOSAL_MAX])
{
	static int check[] = {
		PROPOSAL_KEX_ALGS, PROPOSAL_SERVER_HOST_KEY_ALGS, -1
	};
	int *idx;
	char *p;

	for (idx = &check[0]; *idx != -1; idx++) {
		if ((p = strchr(my[*idx], ',')) != NULL)
			*p = '\0';
		if ((p = strchr(peer[*idx], ',')) != NULL)
			*p = '\0';
		if (strcmp(my[*idx], peer[*idx]) != 0) {
			debug2("proposal mismatch: my %s peer %s",
			    my[*idx], peer[*idx]);
			return (0);
		}
	}
	debug2("proposals match");
	return (1);
}

static inline int
kexalgs_contains(char **peer, const char *ext)
{
	return kex_has_any_alg(peer[PROPOSAL_KEX_ALGS], ext);
}

static int
kex_choose_conf(struct ssh *ssh, uint32_t seq)
{
	struct kex *kex = ssh->kex;
	struct newkeys *newkeys;
	char **my = NULL, **peer = NULL;
	char **cprop, **sprop;
	int nenc, nmac, ncomp;
	u_int mode, ctos, need, dh_need, authlen;
	int r, first_kex_follows = 0;

	debug2("local %s KEXINIT proposal", kex->server ? "server" : "client");
	if ((r = kex_buf2prop(kex->my, NULL, &my)) != 0)
		goto out;
	debug2("peer %s KEXINIT proposal", kex->server ? "client" : "server");
	if ((r = kex_buf2prop(kex->peer, &first_kex_follows, &peer)) != 0)
		goto out;

	if (kex->server) {
		cprop=peer;
		sprop=my;
	} else {
		cprop=my;
		sprop=peer;
	}

	/* Check whether peer supports ext_info/kex_strict */
	if ((kex->flags & KEX_INITIAL) != 0) {
		kex->ext_info_c = kex->server
		    ? kexalgs_contains(peer, "ext-info-c")
		    : 0;
	#ifndef WITHOUT_ETM_FUNCTIONALITY
		kex->kex_strict = kexalgs_contains(peer,
		    kex->server
			? "kex-strict-c-v00@openssh.com"
			: "kex-strict-s-v00@openssh.com");
	#else
		kex->kex_strict = 0;
	#endif
		if (kex->kex_strict) {
			debug3_f("will use strict KEX ordering");
			if (seq != 0)
				ssh_packet_disconnect(ssh,
				    "strict KEX violation: "
				    "KEXINIT was not the first packet");
		}
		else
			debug3_f("will use usual KEX ordering");
	}

	/* Check whether client supports rsa-sha2 algorithms */
	if (kex->server && (kex->flags & KEX_INITIAL)) {
		if (kex_has_any_alg(peer[PROPOSAL_SERVER_HOST_KEY_ALGS],
		    "rsa-sha2-256,rsa-sha2-256-cert-v01@openssh.com"))
			kex->flags |= KEX_RSA_SHA2_256_SUPPORTED;
		if (kex_has_any_alg(peer[PROPOSAL_SERVER_HOST_KEY_ALGS],
		    "rsa-sha2-512,rsa-sha2-512-cert-v01@openssh.com"))
			kex->flags |= KEX_RSA_SHA2_512_SUPPORTED;
	}

	/* Algorithm Negotiation */
	if ((r = choose_kex(kex, cprop[PROPOSAL_KEX_ALGS],
	    sprop[PROPOSAL_KEX_ALGS])) != 0) {
		kex->failed_choice = peer[PROPOSAL_KEX_ALGS];
		peer[PROPOSAL_KEX_ALGS] = NULL;
		goto out;
	}
	if ((r = choose_hostkeyalg(kex, cprop[PROPOSAL_SERVER_HOST_KEY_ALGS],
	    sprop[PROPOSAL_SERVER_HOST_KEY_ALGS])) != 0) {
		kex->failed_choice = peer[PROPOSAL_SERVER_HOST_KEY_ALGS];
		peer[PROPOSAL_SERVER_HOST_KEY_ALGS] = NULL;
		goto out;
	}
	for (mode = 0; mode < MODE_MAX; mode++) {
		if ((newkeys = calloc(1, sizeof(*newkeys))) == NULL) {
			r = SSH_ERR_ALLOC_FAIL;
			goto out;
		}
		kex->newkeys[mode] = newkeys;
		ctos = (!kex->server && mode == MODE_OUT) ||
		    (kex->server && mode == MODE_IN);
		nenc  = ctos ? PROPOSAL_ENC_ALGS_CTOS  : PROPOSAL_ENC_ALGS_STOC;
		nmac  = ctos ? PROPOSAL_MAC_ALGS_CTOS  : PROPOSAL_MAC_ALGS_STOC;
		ncomp = ctos ? PROPOSAL_COMP_ALGS_CTOS : PROPOSAL_COMP_ALGS_STOC;
		if ((r = choose_enc(&newkeys->enc, cprop[nenc],
		    sprop[nenc])) != 0) {
			kex->failed_choice = peer[nenc];
			peer[nenc] = NULL;
			goto out;
		}
		authlen = cipher_authlen(newkeys->enc.cipher);
		/* ignore mac for authenticated encryption */
		if (authlen == 0 &&
		    (r = choose_mac(ssh, &newkeys->mac, cprop[nmac],
		    sprop[nmac])) != 0) {
			kex->failed_choice = peer[nmac];
			peer[nmac] = NULL;
			goto out;
		}
		if ((r = choose_comp(&newkeys->comp, cprop[ncomp],
		    sprop[ncomp])) != 0) {
			kex->failed_choice = peer[ncomp];
			peer[ncomp] = NULL;
			goto out;
		}
		debug("kex: %s cipher: %s MAC: %s compression: %s",
		    ctos ? "client->server" : "server->client",
		    newkeys->enc.name,
		    authlen == 0 ? newkeys->mac.name : "<implicit>",
		    newkeys->comp.name);
	}
	need = dh_need = 0;
	for (mode = 0; mode < MODE_MAX; mode++) {
		newkeys = kex->newkeys[mode];
		need = MAXIMUM(need, newkeys->enc.key_len);
		need = MAXIMUM(need, newkeys->enc.block_size);
		need = MAXIMUM(need, newkeys->enc.iv_len);
		need = MAXIMUM(need, newkeys->mac.key_len);
		dh_need = MAXIMUM(dh_need, cipher_seclen(newkeys->enc.cipher));
		dh_need = MAXIMUM(dh_need, newkeys->enc.block_size);
		dh_need = MAXIMUM(dh_need, newkeys->enc.iv_len);
		dh_need = MAXIMUM(dh_need, newkeys->mac.key_len);
	}
	/* XXX need runden? */
	kex->we_need = need;
	kex->dh_need = dh_need;
	r = 0;

 out:
	/* ignore the next message if the proposals do not match */
	if (first_kex_follows && !proposals_match(my, peer))
		ssh->dispatch_skip_packets = 1;
	kex_prop_free(my);
	kex_prop_free(peer);
	return r;
}

static int
derive_key(struct ssh *ssh, int id, u_int need, u_char *hash, u_int hashlen,
    const struct sshbuf *shared_secret, u_char **keyp)
{
	struct kex *kex = ssh->kex;
	struct ssh_digest_ctx *hashctx = NULL;
	char c = id;
	u_int have;
	size_t mdsz;
	u_char *digest;
	int r;

	if ((mdsz = ssh_digest_bytes(kex->impl->hash_alg)) == 0)
		return SSH_ERR_INVALID_ARGUMENT;
	if ((digest = calloc(1, ROUNDUP(need, mdsz))) == NULL) {
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}

	/* K1 = HASH(K || H || "A" || session_id) */
	if ((hashctx = ssh_digest_start(kex->impl->hash_alg)) == NULL ||
	    ssh_digest_update_buffer(hashctx, shared_secret) != 0 ||
	    ssh_digest_update(hashctx, hash, hashlen) != 0 ||
	    ssh_digest_update(hashctx, &c, 1) != 0 ||
	    ssh_digest_update_buffer(hashctx, kex->session_id) != 0 ||
	    ssh_digest_final(hashctx, digest, mdsz) != 0) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		error_f("KEX hash failed");
		goto out;
	}
	ssh_digest_free(hashctx);
	hashctx = NULL;

	/*
	 * expand key:
	 * Kn = HASH(K || H || K1 || K2 || ... || Kn-1)
	 * Key = K1 || K2 || ... || Kn
	 */
	for (have = mdsz; need > have; have += mdsz) {
		if ((hashctx = ssh_digest_start(kex->impl->hash_alg)) == NULL ||
		    ssh_digest_update_buffer(hashctx, shared_secret) != 0 ||
		    ssh_digest_update(hashctx, hash, hashlen) != 0 ||
		    ssh_digest_update(hashctx, digest, have) != 0 ||
		    ssh_digest_final(hashctx, digest + have, mdsz) != 0) {
			error_f("KDF failed");
			r = SSH_ERR_LIBCRYPTO_ERROR;
			goto out;
		}
		ssh_digest_free(hashctx);
		hashctx = NULL;
	}
#ifdef DEBUG_KEX
	fprintf(stderr, "key '%c'== ", c);
	dump_digest("key", digest, need);
#endif
	*keyp = digest;
	digest = NULL;
	r = 0;
 out:
	free(digest);
	ssh_digest_free(hashctx);
	return r;
}

#define NKEYS	6
int
kex_derive_keys(struct ssh *ssh, u_char *hash, u_int hashlen,
    const struct sshbuf *shared_secret)
{
	struct kex *kex = ssh->kex;
	u_char *keys[NKEYS];
	u_int i, j, mode, ctos;
	int r;

	/* save initial hash as session id */
	if (sshbuf_len(kex->session_id) == 0) {
		r = sshbuf_put(kex->session_id, hash, hashlen);
		if (r != 0) return r;
	}
	for (i = 0; i < NKEYS; i++) {
		if ((r = derive_key(ssh, 'A'+i, kex->we_need, hash, hashlen,
		    shared_secret, &keys[i])) != 0) {
			for (j = 0; j < i; j++)
				free(keys[j]);
			return r;
		}
	}
	for (mode = 0; mode < MODE_MAX; mode++) {
		ctos = (!kex->server && mode == MODE_OUT) ||
		    (kex->server && mode == MODE_IN);
		kex->newkeys[mode]->enc.iv  = keys[ctos ? 0 : 1];
		kex->newkeys[mode]->enc.key = keys[ctos ? 2 : 3];
		kex->newkeys[mode]->mac.key = keys[ctos ? 4 : 5];
	}
	return 0;
}

int
kex_load_host_keys(struct ssh *ssh, struct sshkey **hostpub, struct sshkey **hostpriv) {
	struct kex *kex = ssh->kex;
	int r;

	if (hostpub == NULL || hostpriv == NULL) {
		r = SSH_ERR_INVALID_ARGUMENT;
		goto done;
	}

	if (kex->find_host_public_key == NULL ||
	    kex->find_host_private_key == NULL) {
		error_f("missing hostkey find callback");
		r = SSH_ERR_INVALID_ARGUMENT;
		goto done;
	}

	*hostpub = kex->find_host_public_key(kex->hostkey_alg, ssh);
	*hostpriv = kex->find_host_private_key(kex->hostkey_alg, ssh);

	/* Only public part is required, private is optional and
	 * caller is responsible to check private part
	 */
	r = (*hostpub != NULL)
		? SSH_ERR_SUCCESS
		: SSH_ERR_NO_HOSTKEY_LOADED;
done:
	return r;
}

int
kex_verify_host_key(struct ssh *ssh, struct sshkey *server_host_key)
{
	struct kex *kex = ssh->kex;

	if (kex->verify_host_key == NULL) {
		error_f("missing hostkey verify callback");
		return SSH_ERR_INVALID_ARGUMENT;
	}
	if (!sshkey_match_pkalg(server_host_key, kex->hostkey_alg))
		return SSH_ERR_KEY_TYPE_MISMATCH;
	if (kex->verify_host_key(server_host_key, ssh) == -1)
		return  SSH_ERR_SIGNATURE_INVALID;
	return 0;
}

void
dump_digest(const char *msg, const u_char *digest, size_t len)
{
	fprintf(stderr, "length %zu, %s\n", len, msg);
	sshbuf_dump_data(digest, len, stderr);
}

void
dump_digestb(const char *msg, const struct sshbuf *digest)
{
	if (digest == NULL) {
		fprintf(stderr, "length none, %s\n", msg);
		return;
	}
	dump_digest(msg, sshbuf_ptr(digest), sshbuf_len(digest));
}

/*
 * Send a plaintext error message to the peer, suffixed by \r\n.
 * Only used during banner exchange, and there only for the server.
 */
static void
send_error(struct ssh *ssh, char *msg)
{
	char *crnl = "\r\n";

	if (!ssh->kex->server)
		return;

	if (atomicio(vwrite, ssh_packet_get_connection_out(ssh),
	    msg, strlen(msg)) != strlen(msg) ||
	    atomicio(vwrite, ssh_packet_get_connection_out(ssh),
	    crnl, strlen(crnl)) != strlen(crnl))
		error_f("write: %.100s", strerror(errno));
}

/*
 * Sends our identification string and waits for the peer's. Will block for
 * up to timeout_ms (or indefinitely if timeout_ms <= 0).
 * Returns on 0 success or a ssherr.h code on failure.
 */
int
kex_exchange_identification(struct ssh *ssh, int timeout_ms)
{
	int is_server = ssh->kex->server;
	int remote_major, remote_minor, mismatch, oerrno = 0;
	size_t len;
	int n, found_cr;
	int r, expect_nl;
	u_char c;
	struct sshbuf *our_version;
	struct sshbuf *peer_version;
	char *our_version_string = NULL, *peer_version_string = NULL;
	char *cp, *remote_version = NULL;

	if (is_server) {
		our_version = ssh->kex->server_version;
		peer_version = ssh->kex->client_version;
	} else {
		our_version = ssh->kex->client_version;
		peer_version = ssh->kex->server_version;
	}

	/* Send our banner */
	if (atomicio(vwrite, ssh_packet_get_connection_out(ssh),
	    sshbuf_mutable_ptr(our_version),
	    sshbuf_len(our_version)) != sshbuf_len(our_version)) {
		oerrno = errno;
		debug_f("write: %.100s", strerror(errno));
		r = SSH_ERR_SYSTEM_ERROR;
		goto out;
	}
	if ((r = sshbuf_consume_end(our_version, 2)) != 0) { /* trim \r\n */
		oerrno = errno;
		error_fr(r, "sshbuf_consume_end");
		goto out;
	}
	our_version_string = sshbuf_dup_string(our_version);
	if (our_version_string == NULL) {
		error_f("sshbuf_dup_string failed");
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	debug("Local version string %.100s", our_version_string);

	/* Read other side's version identification. */
	for (n = 0; ; n++) {
		if (n >= SSH_MAX_PRE_BANNER_LINES) {
			send_error(ssh, "No SSH identification string "
			    "received.");
			error_f("No SSH version received in first %u lines "
			    "from server", SSH_MAX_PRE_BANNER_LINES);
			r = SSH_ERR_INVALID_FORMAT;
			goto out;
		}
		sshbuf_reset(peer_version);
		expect_nl = 0;
		found_cr = 0;
		while (1) {
			if (timeout_ms > 0) {
				r = waitrfd(ssh_packet_get_connection_in(ssh),
				    &timeout_ms, NULL);
				if (r == -1 && errno == ETIMEDOUT) {
					send_error(ssh, "Timed out waiting "
					    "for SSH identification string.");
					error("Connection timed out during "
					    "banner exchange");
					r = SSH_ERR_CONN_TIMEOUT;
					goto out;
				} else if (r == -1) {
					oerrno = errno;
					error_f("%s", strerror(errno));
					r = SSH_ERR_SYSTEM_ERROR;
					goto out;
				}
			}

			len = atomicio(read, ssh_packet_get_connection_in(ssh),
			    &c, 1);
			if (len != 1 && errno == EPIPE) {
				debug_f("connection closed by remote host");
				r = SSH_ERR_CONN_CLOSED;
				goto out;
			} else if (len != 1) {
				oerrno = errno;
				error_f("read: %.100s", strerror(errno));
				r = SSH_ERR_SYSTEM_ERROR;
				goto out;
			}
			if (c == '\r') {
				found_cr = 1;
				expect_nl = 1;
				continue;
			}
			if (c == '\n') {
				if (!found_cr)
					error("protocol identification string"
					    " lack carriage return");
				break;
			}
			if (c == '\0' || expect_nl) {
				debug_f("banner line contains invalid "
				    "characters");
				goto invalid;
			}
			if ((r = sshbuf_put_u8(peer_version, c)) != 0) {
				oerrno = errno;
				error_fr(r, "sshbuf_put");
				goto out;
			}
			if (sshbuf_len(peer_version) > SSH_MAX_BANNER_LEN) {
				debug_f("banner line too long");
				goto invalid;
			}
		}
		/* Is this an actual protocol banner? */
		if (sshbuf_len(peer_version) > 4 &&
		    memcmp(sshbuf_ptr(peer_version), "SSH-", 4) == 0)
			break;
		/* If not, then just log the line and continue */
		if ((cp = sshbuf_dup_string(peer_version)) == NULL) {
			error_f("sshbuf_dup_string failed");
			r = SSH_ERR_ALLOC_FAIL;
			goto out;
		}
		/* Do not accept lines before the SSH ident from a client */
		if (is_server) {
			debug_f("client sent invalid protocol identifier "
			    "\"%.256s\"", cp);
			free(cp);
			goto invalid;
		}
		debug_f("banner line %d: %.256s", n, cp);
		free(cp);
	}
	peer_version_string = sshbuf_dup_string(peer_version);
	if (peer_version_string == NULL)
		fatal_f("sshbuf_dup_string failed");
	/* XXX must be same size for sscanf */
	if ((remote_version = calloc(1, sshbuf_len(peer_version))) == NULL) {
		error_f("calloc failed");
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}

	/*
	 * Check that the versions match.  In future this might accept
	 * several versions and set appropriate flags to handle them.
	 */
	if (sscanf(peer_version_string, "SSH-%d.%d-%[^\n]\n",
	    &remote_major, &remote_minor, remote_version) != 3) {
		error("Bad remote protocol version identification: '%.100s'",
		    peer_version_string);
 invalid:
		send_error(ssh, "Invalid SSH identification string.");
		r = SSH_ERR_INVALID_FORMAT;
		goto out;
	}
	debug("Remote protocol version %d.%d, remote software version %.100s",
	    remote_major, remote_minor, remote_version);

	ssh_set_compatibility(ssh, remote_version);

	mismatch = 0;
	switch (remote_major) {
	case 2:
		break;
	case 1:
		if (remote_minor != 99)
			mismatch = 1;
		break;
	default:
		mismatch = 1;
		break;
	}
	if (mismatch) {
		error("Protocol major versions differ: %d vs. %d",
		    PROTOCOL_MAJOR_2, remote_major);
		send_error(ssh, "Protocol major versions differ.");
		r = SSH_ERR_NO_PROTOCOL_VERSION;
		goto out;
	}

	if (is_server && ssh_compat_fellows(ssh, SSH_BUG_PROBE)) {
		logit("probed from %s port %d with %s.  Don't panic.",
		    ssh_remote_ipaddr(ssh), ssh_remote_port(ssh),
		    peer_version_string);
		r = SSH_ERR_CONN_CLOSED; /* XXX */
		goto out;
	}
	if (is_server && ssh_compat_fellows(ssh, SSH_BUG_SCANNER)) {
		logit("scanned from %s port %d with %s.  Don't panic.",
		    ssh_remote_ipaddr(ssh), ssh_remote_port(ssh),
		    peer_version_string);
		r = SSH_ERR_CONN_CLOSED; /* XXX */
		goto out;
	}
	/* success */
	r = 0;
 out:
	free(our_version_string);
	free(peer_version_string);
	free(remote_version);
	if (r == SSH_ERR_SYSTEM_ERROR)
		errno = oerrno;
	return r;
}

int
kex_shared_secret_to_sshbuf(u_char *kbuf, size_t klen,
    int raw, struct sshbuf **bufp
) {
	struct sshbuf *buf;
	int r;

	if (*bufp == NULL) {
		buf = sshbuf_new();
		if (buf == NULL) return SSH_ERR_ALLOC_FAIL;
	} else
		buf = *bufp;

	if (raw)
		r = sshbuf_put(buf, kbuf, klen);
	else
		r = sshbuf_put_bignum2_bytes(buf, kbuf, klen);

	if (*bufp == NULL) {
		if (r == 0)
			*bufp = buf;
		else
			sshbuf_free(buf);
	}
	return r;
}


#ifdef USE_EVP_PKEY_KEYGEN
static int
kex_pkey_derive_shared_secret_raw(struct kex *kex, EVP_PKEY *peerkey,
    u_char **kbufp, size_t *klenp
) {
	EVP_PKEY_CTX *ctx;
	u_char *kbuf = NULL;
	size_t klen = 0;
	int r = SSH_ERR_LIBCRYPTO_ERROR;

	ctx = EVP_PKEY_CTX_new(kex->pk, NULL);
	if (ctx == NULL) return SSH_ERR_INTERNAL_ERROR;

	if (EVP_PKEY_derive_init(ctx) != 1)
		goto out;

	if (EVP_PKEY_derive_set_peer(ctx, peerkey) != 1)
		goto out;

	if (EVP_PKEY_derive(ctx, NULL, &klen) != 1)
		goto out;
	kbuf = OPENSSL_malloc(klen);
	if (kbuf == NULL) {
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	if (EVP_PKEY_derive(ctx, kbuf, &klen) != 1) {
		OPENSSL_free(kbuf);
		goto out;
	}
#if defined(DEBUG_KEX) || defined(DEBUG_KEXDH) || defined(DEBUG_KEXECDH) || \
    defined(DEBUG_KEXECX) || defined(DEBUG_KEXKEM)
	dump_digest("shared secret", kbuf, klen);
#endif

	*klenp = klen;
	*kbufp = kbuf;
	r = 0;

 out:
	EVP_PKEY_CTX_free(ctx);
	return r;
}
#endif /*def USE_EVP_PKEY_KEYGEN*/

#ifdef USE_EVP_PKEY_KEYGEN
int
kex_pkey_derive_shared_secret(struct kex *kex, EVP_PKEY *peerkey,
    int raw, struct sshbuf **bufp
) {
	u_char *kbuf = NULL;
	size_t klen = 0;
	int r = SSH_ERR_LIBCRYPTO_ERROR;

	r =  kex_pkey_derive_shared_secret_raw(kex, peerkey, &kbuf, &klen);
	if (r != 0) goto out;

	r = kex_shared_secret_to_sshbuf(kbuf, klen, raw, bufp);

 out:
	OPENSSL_clear_free(kbuf, klen);
	return r;
}
#endif /*def USE_EVP_PKEY_KEYGEN*/
