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

#ifdef OPENSSL_HAS_ECC
static int
get_ecpub(const EC_GROUP *g, const u_char *d, size_t len, EC_POINT **valp)
{
	EC_POINT *v;

	/* Refuse overlong bignums */
	if (len == 0 || len > SSHBUF_MAX_ECPOINT)
		return SSH_ERR_ECPOINT_TOO_LARGE;
	/* Only handle uncompressed points */
	if (*d != POINT_CONVERSION_UNCOMPRESSED)
		return SSH_ERR_INVALID_FORMAT;

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
sshbuf_get_ecpub(struct sshbuf *buf, const EC_GROUP *g, EC_POINT **valp)
{
	const u_char *d;
	size_t len;
	int r;

	if ((r = sshbuf_peek_string_direct(buf, &d, &len)) < 0)
		return r;
	if ((r = get_ecpub(g, d, len, valp)) != 0)
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
	const u_char *d;
	size_t len;

	if ((r = sshbuf_peek_string_direct(buf, &d, &len)) < 0)
		return r;
	if ((r = get_ecpub(EC_KEY_get0_group(v), d, len, &pt)) != 0) {
		EC_POINT_free(pt);
		return r;
	}
	if (EC_KEY_set_public_key(v, pt) != 1) {
		EC_POINT_free(pt);
		return SSH_ERR_ALLOC_FAIL; /* XXX assumption */
	}
	EC_POINT_free(pt);
	/* Skip string */
	if (sshbuf_get_string_direct(buf, NULL, NULL) != 0) {
		/* Shouldn't happen */
		SSHBUF_DBG(("SSH_ERR_INTERNAL_ERROR"));
		SSHBUF_ABORT();
		return SSH_ERR_INTERNAL_ERROR;
	}
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

#ifdef OPENSSL_HAS_ECC
static int
sshbuf_put_ec(struct sshbuf *buf, const EC_POINT *v, const EC_GROUP *g)
{
	u_char d[SSHBUF_MAX_ECPOINT];
	size_t len;
	int ret;

	if ((len = EC_POINT_point2oct(g, v, POINT_CONVERSION_UNCOMPRESSED,
	    NULL, 0, NULL)) > SSHBUF_MAX_ECPOINT) {
		return SSH_ERR_INVALID_ARGUMENT;
	}
	if (EC_POINT_point2oct(g, v, POINT_CONVERSION_UNCOMPRESSED,
	    d, len, NULL) != len) {
		return SSH_ERR_INTERNAL_ERROR; /* Shouldn't happen */
	}
	ret = sshbuf_put_string(buf, d, len);
	explicit_bzero(d, len);
	return ret;
}

int
sshbuf_put_eckey(struct sshbuf *buf, const EC_KEY *v)
{
	return sshbuf_put_ec(buf, EC_KEY_get0_public_key(v),
	    EC_KEY_get0_group(v));
}
#endif /* OPENSSL_HAS_ECC */

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
