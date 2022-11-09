/* $OpenBSD: ssh-xmss.c,v 1.5 2022/04/20 15:59:18 millert Exp $*/
/*
 * Copyright (c) 2017 Stefan-Lukas Gazdag.
 * Copyright (c) 2017 Markus Friedl.
 * Copyright (c) 2022 Roumen Petrov.  All rights reserved.
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
#ifdef WITH_XMSS

#define SSHKEY_INTERNAL
#include <sys/types.h>
#include <limits.h>

#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <unistd.h>

#include "log.h"
#include "sshbuf.h"
#include "sshkey.h"
#include "sshkey-xmss.h"
#include "ssherr.h"
#include "ssh.h"

#include "xmss_fast.h"


/* key implementation */

static void
ssh_xmss_cleanup(struct sshkey *k)
{
	freezero(k->xmss_pk, sshkey_xmss_pklen(k));
	k->xmss_pk = NULL;
	freezero(k->xmss_sk, sshkey_xmss_sklen(k));
	k->xmss_sk = NULL;
	sshkey_xmss_free_state(k);
	free(k->xmss_name);
	k->xmss_name = NULL;
	free(k->xmss_filename);
	k->xmss_filename = NULL;
}

static int
ssh_xmss_equal(const struct sshkey *a, const struct sshkey *b)
{
	if (a->xmss_pk == NULL || b->xmss_pk == NULL)
		return 0;
	if (sshkey_xmss_pklen(a) != sshkey_xmss_pklen(b))
		return 0;
	if (memcmp(a->xmss_pk, b->xmss_pk, sshkey_xmss_pklen(a)) != 0)
		return 0;
	return 1;
}

static void
ssh_xmss_move_public(struct sshkey *from, struct sshkey *to) {
	free(to->xmss_pk);
	to->xmss_pk = from->xmss_pk;
	from->xmss_pk = NULL;
	free(to->xmss_state);
	to->xmss_state = from->xmss_state;
	from->xmss_state = NULL;
	free(to->xmss_name);
	to->xmss_name = from->xmss_name;
	from->xmss_name = NULL;
	free(to->xmss_filename);
	to->xmss_filename = from->xmss_filename;
	from->xmss_filename = NULL;
}

static int
ssh_xmss_copy_public(const struct sshkey *from, struct sshkey *to)
{
	int r;

	if ((r = sshkey_xmss_init(to, from->xmss_name)) != 0)
		return r;
	if (from->xmss_pk == NULL)
		return 0; /* XXX SSH_ERR_INTERNAL_ERROR ? */

{	size_t pklen = sshkey_xmss_pklen(from);
	if (pklen == 0 || sshkey_xmss_pklen(to) != pklen)
		return SSH_ERR_INTERNAL_ERROR;
	if ((to->xmss_pk = malloc(pklen)) == NULL)
		return SSH_ERR_ALLOC_FAIL;
	memcpy(to->xmss_pk, from->xmss_pk, pklen);
}
{	/* simulate number of signatures left on pubkey */
	u_int32_t left = sshkey_xmss_signatures_left(from);
	if (left)
		sshkey_xmss_enable_maxsign(to, left);
}
	return 0;
}

int
ssh_xmss_sign(const ssh_sign_ctx *ctx,
    u_char **sigp, size_t *lenp,
    const u_char *data, size_t datalen)
{
	const struct sshkey *key = ctx->key;
	u_char *sig = NULL;
	size_t slen = 0, len = 0, required_siglen;
	unsigned long long smlen;
	int r, ret;
	struct sshbuf *b = NULL;

	if (lenp != NULL)
		*lenp = 0;
	if (sigp != NULL)
		*sigp = NULL;

	if (key == NULL ||
	    sshkey_type_plain(key->type) != KEY_XMSS ||
	    key->xmss_sk == NULL ||
	    sshkey_xmss_params(key) == NULL)
		return SSH_ERR_INVALID_ARGUMENT;
	if ((r = sshkey_xmss_siglen(key, &required_siglen)) != 0)
		return r;
	if (datalen >= INT_MAX - required_siglen)
		return SSH_ERR_INVALID_ARGUMENT;
	smlen = slen = datalen + required_siglen;
	if ((sig = malloc(slen)) == NULL)
		return SSH_ERR_ALLOC_FAIL;
	if ((r = sshkey_xmss_get_state(key, 1)) != 0)
		goto out;
	if ((ret = xmss_sign(key->xmss_sk, sshkey_xmss_bds_state(key), sig, &smlen,
	    data, datalen, sshkey_xmss_params(key))) != 0 || smlen <= datalen) {
		r = SSH_ERR_INVALID_ARGUMENT; /* XXX better error? */
		goto out;
	}
	/* encode signature */
	if ((b = sshbuf_new()) == NULL) {
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	if ((r = sshbuf_put_cstring(b, "ssh-xmss@openssh.com")) != 0 ||
	    (r = sshbuf_put_string(b, sig, smlen - datalen)) != 0)
		goto out;
	len = sshbuf_len(b);
	if (sigp != NULL) {
		if ((*sigp = malloc(len)) == NULL) {
			r = SSH_ERR_ALLOC_FAIL;
			goto out;
		}
		memcpy(*sigp, sshbuf_ptr(b), len);
	}
	if (lenp != NULL)
		*lenp = len;
	/* success */
	r = 0;
 out:
	if ((ret = sshkey_xmss_update_state(key, 1)) != 0) {
		/* discard signature since we cannot update the state */
		if (r == 0 && sigp != NULL && *sigp != NULL)
			freezero(*sigp, len);
		if (sigp != NULL)
			*sigp = NULL;
		if (lenp != NULL)
			*lenp = 0;
		r = ret;
	}
	sshbuf_free(b);
	if (sig != NULL)
		freezero(sig, slen);

	return r;
}

int
ssh_xmss_verify(const ssh_verify_ctx *ctx,
    const u_char *sig, size_t siglen,
    const u_char *data, size_t dlen)
{
	const struct sshkey *key = ctx->key;
	struct sshbuf *b = NULL;
	char *ktype = NULL;
	const u_char *sigblob;
	u_char *sm = NULL, *m = NULL;
	size_t len, required_siglen;
	unsigned long long smlen = 0, mlen = 0;
	int r, ret;

	if (key == NULL ||
	    sshkey_type_plain(key->type) != KEY_XMSS ||
	    key->xmss_pk == NULL ||
	    sshkey_xmss_params(key) == NULL ||
	    sig == NULL || siglen == 0)
		return SSH_ERR_INVALID_ARGUMENT;
	if ((r = sshkey_xmss_siglen(key, &required_siglen)) != 0)
		return r;
	if (dlen >= INT_MAX - required_siglen)
		return SSH_ERR_INVALID_ARGUMENT;

	if ((b = sshbuf_from(sig, siglen)) == NULL)
		return SSH_ERR_ALLOC_FAIL;
	if ((r = sshbuf_get_cstring(b, &ktype, NULL)) != 0 ||
	    (r = sshbuf_get_string_direct(b, &sigblob, &len)) != 0)
		goto out;
	if (strcmp("ssh-xmss@openssh.com", ktype) != 0) {
		r = SSH_ERR_KEY_TYPE_MISMATCH;
		goto out;
	}
	if (sshbuf_len(b) != 0) {
		r = SSH_ERR_UNEXPECTED_TRAILING_DATA;
		goto out;
	}
	if (len != required_siglen) {
		r = SSH_ERR_INVALID_FORMAT;
		goto out;
	}
	if (dlen >= SIZE_MAX - len) {
		r = SSH_ERR_INVALID_ARGUMENT;
		goto out;
	}
	smlen = len + dlen;
	mlen = smlen;
	if ((sm = malloc(smlen)) == NULL || (m = malloc(mlen)) == NULL) {
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	memcpy(sm, sigblob, len);
	memcpy(sm+len, data, dlen);
	if ((ret = xmss_sign_open(m, &mlen, sm, smlen,
	    key->xmss_pk, sshkey_xmss_params(key))) != 0) {
		debug2_f("xmss_sign_open failed: %d", ret);
	}
	if (ret != 0 || mlen != dlen) {
		r = SSH_ERR_SIGNATURE_INVALID;
		goto out;
	}
	/* XXX compare 'm' and 'data' ? */
	/* success */
	r = 0;
 out:
	if (sm != NULL)
		freezero(sm, smlen);
	if (m != NULL)
		freezero(m, smlen);
	sshbuf_free(b);
	free(ktype);
	return r;
}

static const struct sshkey_impl_funcs sshkey_xmss_funcs = {
	/* .size = */		NULL,
	/* .alloc =		NULL, */
	/* .cleanup = */	ssh_xmss_cleanup,
	/* .equal = */		ssh_xmss_equal,
	/* .generate = */	sshkey_xmss_generate_private_key,
	/* .move_public = */	ssh_xmss_move_public,
	/* .copy_public = */	ssh_xmss_copy_public
};

const struct sshkey_impl sshkey_xmss_impl = {
	/* .name = */		"ssh-xmss@openssh.com",
	/* .shortname = */	"XMSS",
	/* .sigalg = */		NULL,
	/* .type = */		KEY_XMSS,
	/* .nid = */		0,
	/* .cert = */		0,
	/* .sigonly = */	0,
	/* .keybits = */	256,
	/* .funcs = */		&sshkey_xmss_funcs
};

const struct sshkey_impl sshkey_xmss_cert_impl = {
	/* .name = */		"ssh-xmss-cert-v01@openssh.com",
	/* .shortname = */	"XMSS-CERT",
	/* .sigalg = */		NULL,
	/* .type = */		KEY_XMSS_CERT,
	/* .nid = */		0,
	/* .cert = */		1,
	/* .sigonly = */	0,
	/* .keybits = */	256,
	/* .funcs = */		&sshkey_xmss_funcs
};
#else

typedef int ssh_xmss_empty_translation_unit;

#endif /* WITH_XMSS */
