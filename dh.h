/* $OpenBSD: dh.h,v 1.18 2019/09/06 05:23:55 djm Exp $ */

/*
 * Copyright (c) 2000 Niels Provos.  All rights reserved.
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
#ifndef DH_H
#define DH_H

#include "includes.h"

#ifdef WITH_OPENSSL
#include <openssl/bn.h>
#include <openssl/dh.h>

#ifndef HAVE_DH_GET0_KEY	/* OpenSSL < 1.1 */
/* Partial backport of opaque DH from OpenSSL >= 1.1, commits
 * "Make DH opaque", "RSA, DSA, DH: Allow some given input to be NULL
 * on already initialised keys" and etc.
 */
static inline void
DH_get0_key(const DH *dh, const BIGNUM **pub_key, const BIGNUM **priv_key) {
	if (pub_key  != NULL) *pub_key  = dh->pub_key;
	if (priv_key != NULL) *priv_key = dh->priv_key;
}

static inline void
DH_get0_pqg(const DH *dh, const BIGNUM **p, const BIGNUM **q, const BIGNUM **g) {
	if (p != NULL) *p = dh->p;
	if (q != NULL) *q = dh->q;
	if (g != NULL) *g = dh->g;
}
#endif /*ndef HAVE_DH_GET0_KEY*/


struct dhgroup {
	int size;
	BIGNUM *g;
	BIGNUM *p;
};

DH	*dh_new_group_asc(const char *, const char *);
DH	*dh_new_group(BIGNUM *, BIGNUM *);
DH	*dh_new_group_num(int);

int	 dh_gen_key(DH *, int);
int	 dh_pub_is_valid(const DH *, const BIGNUM *);

u_int	 dh_estimate(int);

/*
 * Max value from RFC4419.
 * Min value from RFC8270.
 */
#define DH_GRP_MIN	2048
#define DH_GRP_MAX	8192

/*
 * Values for "type" field of moduli(5)
 * Specifies the internal structure of the prime modulus.
 */
#define MODULI_TYPE_UNKNOWN		(0)
#define MODULI_TYPE_UNSTRUCTURED	(1)
#define MODULI_TYPE_SAFE		(2)
#define MODULI_TYPE_SCHNORR		(3)
#define MODULI_TYPE_SOPHIE_GERMAIN	(4)
#define MODULI_TYPE_STRONG		(5)

/*
 * Values for "tests" field of moduli(5)
 * Specifies the methods used in checking for primality.
 * Usually, more than one test is used.
 */
#define MODULI_TESTS_UNTESTED		(0x00)
#define MODULI_TESTS_COMPOSITE		(0x01)
#define MODULI_TESTS_SIEVE		(0x02)
#define MODULI_TESTS_MILLER_RABIN	(0x04)
#define MODULI_TESTS_JACOBI		(0x08)
#define MODULI_TESTS_ELLIPTIC		(0x10)

#endif /* WITH_OPENSSL */

#endif /* DH_H */
