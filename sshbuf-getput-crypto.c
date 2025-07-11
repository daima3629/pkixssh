/*	$OpenBSD: sshbuf-getput-crypto.c,v 1.12 2024/08/15 00:51:51 djm Exp $	*/
/*
 * Copyright (c) 2011 Damien Miller
 * Copyright (c) 2020-2024 Roumen Petrov
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

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#ifndef USE_OPENSSL_PROVIDER
/* TODO: implement OpenSSL 4.0 API, as OpenSSL 3.* is quite nonfunctional */
# define OPENSSL_SUPPRESS_DEPRECATED
#endif

#define SSHBUF_INTERNAL
#include "includes.h"

#include <sys/types.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#ifdef WITH_OPENSSL

#include "evp-compat.h"
#include "ssherr.h"
#include "sshbuf.h"

int
sshbuf_get_bignum2(struct sshbuf *buf, BIGNUM **valp)
{
	const u_char *d;
	size_t len;
	int r;

	if (valp != NULL) *valp = NULL;
	if ((r = sshbuf_get_bignum2_bytes_direct(buf, &d, &len)) != 0)
		return r;
	if (valp == NULL) return 0;

	*valp = BN_bin2bn(d, len, NULL);
	return *valp != NULL ? 0 : SSH_ERR_ALLOC_FAIL;
}

int
sshbuf_to_dhpub(const struct sshbuf *buf, BIGNUM **valp)
{
	/* TODO: direct read */
	struct sshbuf *tmp;
	int r;

	tmp = sshbuf_new();
	if (tmp == NULL) return SSH_ERR_ALLOC_FAIL;

	if ((r = sshbuf_put_stringb(tmp, buf)) != 0)
		goto out;
	r = sshbuf_get_bignum2(tmp, valp);

 out:
	sshbuf_free(tmp);
	return r;
}

#ifdef OPENSSL_HAS_ECC
static int
get_ecpub(const EC_KEY *key, const u_char *d, size_t len, EC_POINT **valp)
{
	const EC_GROUP *g;
	EC_POINT *v;

	/* Refuse overlong bignums */
	if (len == 0 || len > SSHBUF_MAX_ECPOINT)
		return SSH_ERR_ECPOINT_TOO_LARGE;
	/* Only handle uncompressed points */
	if (*d != POINT_CONVERSION_UNCOMPRESSED)
		return SSH_ERR_INVALID_FORMAT;

	if ((g = EC_KEY_get0_group(key)) == NULL)
		return SSH_ERR_INTERNAL_ERROR;

	if ((v = EC_POINT_new(g)) == NULL) {
		SSHBUF_DBG(("SSH_ERR_ALLOC_FAIL"));
		return SSH_ERR_ALLOC_FAIL;
	}
	if (EC_POINT_oct2point(g, v, d, len, NULL) != 1) {
		EC_POINT_clear_free(v);
		return SSH_ERR_INVALID_FORMAT; /* XXX assumption */
	}
	*valp = v;

	return 0;
}

int
sshbuf_to_ecpub(const struct sshbuf *buf, EVP_PKEY *pk, EC_POINT **valp)
{
	EC_KEY *key;
	int r;

	if ((key = EVP_PKEY_get1_EC_KEY(pk)) == NULL)
		return SSH_ERR_INVALID_ARGUMENT;

	r = get_ecpub(key, sshbuf_ptr(buf), sshbuf_len(buf), valp);

	EC_KEY_free(key);
	return r;
}

static int
sshbuf_get_ecpub(struct sshbuf *buf, const EC_KEY *key, EC_POINT **valp)
{
	const u_char *d;
	size_t len;
	int r;

	if ((r = sshbuf_peek_string_direct(buf, &d, &len)) < 0)
		return r;
	if ((r = get_ecpub(key, d, len, valp)) != 0)
		return r;
	/* Skip string */
	if (sshbuf_get_string_direct(buf, NULL, NULL) != 0) {
		/* Shouldn't happen */
		EC_POINT_clear_free(*valp);
		*valp = NULL;
		SSHBUF_DBG(("SSH_ERR_INTERNAL_ERROR"));
		SSHBUF_ABORT();
		return SSH_ERR_INTERNAL_ERROR;
	}
	return 0;
}

int
sshbuf_get_eckey(struct sshbuf *buf, EC_KEY *v)
{
	EC_POINT *pt = NULL;
	int r;

	if ((r = sshbuf_get_ecpub(buf, v, &pt)) != 0)
		return r;
	if (EC_KEY_set_public_key(v, pt) != 1) {
		EC_POINT_free(pt);
		return SSH_ERR_ALLOC_FAIL; /* XXX assumption */
	}
	EC_POINT_free(pt);
	return 0;
}
#endif /* OPENSSL_HAS_ECC */

int
sshbuf_put_bignum2(struct sshbuf *buf, const BIGNUM *v)
{
	u_char d[SSHBUF_MAX_BIGNUM + 1];
	int len = BN_num_bytes(v), prepend = 0, r;

	if (len < 0 || len > SSHBUF_MAX_BIGNUM)
		return SSH_ERR_INVALID_ARGUMENT;
	*d = '\0';
	if (BN_bn2bin(v, d + 1) != len)
		return SSH_ERR_INTERNAL_ERROR; /* Shouldn't happen */
	/* If MSB is set, prepend a \0 */
	if (len > 0 && (d[1] & 0x80) != 0)
		prepend = 1;
	if ((r = sshbuf_put_string(buf, d + 1 - prepend, len + prepend)) < 0) {
		explicit_bzero(d, sizeof(d));
		return r;
	}
	explicit_bzero(d, sizeof(d));
	return 0;
}

/*
 * This is almost exactly the bignum1 encoding, but with 32 bit for length
 * instead of 16.
 */
int
sshbuf_get_bignum1x(struct sshbuf *buf, BIGNUM **valp) {
	int r;
	u_int32_t bignum_bits;
	int bytes;
	BIGNUM *val;

	if ((r = sshbuf_get_u32(buf, &bignum_bits)) != 0)
		return r;

	bytes = (bignum_bits + 7) / 8;
	if (sshbuf_len(buf) < (size_t)bytes)
		return SSH_ERR_NO_BUFFER_SPACE;

	val = BN_bin2bn(sshbuf_ptr(buf), bytes, NULL);
	if (val == NULL)
		return SSH_ERR_ALLOC_FAIL;

	if ((r = sshbuf_consume(buf, bytes)) != 0) {
		r = SSH_ERR_INTERNAL_ERROR;
		goto out;
	}

	/* success */
	*valp = val;
	val = NULL;
	r = 0;

out:
	BN_clear_free(val);
	return r;
}
#endif /* WITH_OPENSSL */
