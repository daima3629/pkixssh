#ifndef EVP_COMPAT_H
#define EVP_COMPAT_H
/*
 * Copyright (c) 2011-2022 Roumen Petrov.  All rights reserved.
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

#ifdef WITH_OPENSSL
# include <openssl/rsa.h>
# include <openssl/dsa.h>
# ifdef HAVE_OPENSSL_EC_H
#  include <openssl/ec.h>
# else
#  define EC_GROUP	void
#  define EC_POINT	void
# endif
# if defined(OPENSSL_HAS_ECC)
#  include <openssl/ecdsa.h>
#  if defined(OPENSSL_VERSION_NUMBER) && (OPENSSL_VERSION_NUMBER < 0x00908000L)
    /* before OpenSSL 0.9.8 */
#   define EC_KEY	void
#  endif
# else /* OPENSSL_HAS_ECC */
#  define EC_KEY	void
# endif /* OPENSSL_HAS_ECC */
#else /* WITH_OPENSSL */
# define BIGNUM		void
# define EVP_PKEY	void
# define RSA		void
# define DSA		void
# define EC_KEY		void
# define EC_GROUP	void
# define EC_POINT	void
#endif /* WITH_OPENSSL */

#ifdef WITH_OPENSSL
#include "openbsd-compat/openssl-compat.h"

#ifndef OPENSSL_clear_free		/* OpenSSL < 1.1 */
/* still missing in some forks */
static inline void
ssh_OPENSSL_clear_free (void *ptr, size_t num) {
	if (ptr == NULL) return;
	if (num > 0)
		OPENSSL_cleanse(ptr, num);
	OPENSSL_free(ptr);
}
# define OPENSSL_clear_free(addr, num) \
	ssh_OPENSSL_clear_free(addr, num)
#endif

#ifndef HAVE_EVP_MD_CTX_NEW		/* OpenSSL < 1.1 */
static inline EVP_MD_CTX*
EVP_MD_CTX_new(void) {
	EVP_MD_CTX *ctx;

	ctx = OPENSSL_malloc(sizeof(EVP_MD_CTX));
	if (ctx != NULL) {
		EVP_MD_CTX_init(ctx);
	}
	return(ctx);
}


static inline void
EVP_MD_CTX_free(EVP_MD_CTX *ctx) {
	EVP_MD_CTX_cleanup(ctx);
	OPENSSL_free(ctx);
}
#endif/* ndef HAVE_EVP_MD_CTX_NEW	OpenSSL < 1.1 */


#ifndef HAVE_EVP_MD_FLAGS		/* OpenSSL < 1.0 */
# ifdef HAVE_EVP_MD_GET_FLAGS		/* OpenSSL >= 3.0 */
/* EVP_MD_flags is define to EVP_MD_get_flags */
/* TODO use EVP_MD_get_flags? :( */
# else
static inline unsigned long
EVP_MD_flags(const EVP_MD *md) {
	return md->flags;
}
# endif
#endif /* ndef HAVE_EVP_MD_FLAGS	OpenSSL < 1.0 */


#ifndef HAVE_EVP_PKEY_BASE_ID		/* OpenSSL < 1.0 */
# ifdef HAVE_EVP_PKEY_GET_BASE_ID	/* OpenSSL >= 3.0 */
/* EVP_PKEY_base_id is define to EVP_PKEY_get_base_id */
/* TODO use EVP_PKEY_get_base_id? :( */
# else
static inline int
EVP_PKEY_id(const EVP_PKEY *pkey) {
	return pkey->type;
}

static inline int
EVP_PKEY_base_id(const EVP_PKEY *pkey) {
	return(EVP_PKEY_type(EVP_PKEY_id(pkey)));
}
# endif
#endif /*ndef HAVE_EVP_PKEY_BASE_ID */


int ssh_EVP_PKEY_eq(const EVP_PKEY *a, const EVP_PKEY *b);


#if !HAVE_DECL_UTF8_GETC
/* hidden in some OpenSSL compatible libraries */
int UTF8_getc(const unsigned char *str, int len, unsigned long *val);
int UTF8_putc(unsigned char *str, int len, unsigned long value);
#endif

#endif /*def WITH_OPENSSL */

#endif /* ndef EVP_COMPAT_H*/
