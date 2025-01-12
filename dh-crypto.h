#ifndef DH_CRYPTO_H
#define DH_CRYPTO_H
/*
 * Copyright (c) 2016-2025 Roumen Petrov.  All rights reserved.
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


#ifndef HAVE_BN_IS_NEGATIVE	/*macro before OpenSSL 1.1*/
# ifndef BN_is_negative		/*not defined before OpenSSL 0.9.8*/
#  define BN_is_negative(a) ((a)->neg != 0)
# endif
#endif

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

static inline int
DH_set0_key(DH *dh, BIGNUM *pub_key, BIGNUM *priv_key) {
	if (pub_key != NULL) {
		BN_clear_free(dh->pub_key);
		dh->pub_key = pub_key;
	}
	if (priv_key != NULL) {
		BN_clear_free(dh->priv_key);
		dh->priv_key = priv_key;
	}
	return 1;
}

static inline int
DH_set_length(DH *dh, long length) {
	dh->length = length;
	return 1;
}

static inline void
DH_get0_pqg(const DH *dh, const BIGNUM **p, const BIGNUM **q, const BIGNUM **g) {
	if (p != NULL) *p = dh->p;
	if (q != NULL) *q = dh->q;
	if (g != NULL) *g = dh->g;
}

static inline int
DH_set0_pqg(DH *dh, BIGNUM *p, BIGNUM *q, BIGNUM *g) {
/* If the fields p and g in d are NULL, the corresponding input
 * parameters MUST be non-NULL.  q may remain NULL.
 *
 * It is an error to give the results from get0 on d as input
 * parameters.
 */
	if (p == dh->p || (dh->q != NULL && q == dh->q) || g == dh->g)
		return 0;

	if (p != NULL) { BN_free(dh->p); dh->p = p; }
	if (q != NULL) { BN_free(dh->q); dh->q = q; }
	if (g != NULL) { BN_free(dh->g); dh->g = g; }

	if (q != NULL)
	        (void)DH_set_length(dh, BN_num_bits(q));

	return 1;
}
#endif /*ndef HAVE_DH_GET0_KEY*/

#endif /*ndef DH_CRYPTO_H*/
