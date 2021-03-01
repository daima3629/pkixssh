/*
 * Copyright (c) 2005 Darren Tucker <dtucker@zip.com.au>
 * Copyright (c) 2011-2021 Roumen Petrov.  All rights reserved.
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF MIND, USE, DATA OR PROFITS, WHETHER
 * IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING
 * OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#ifndef _OPENSSL_COMPAT_H
#define _OPENSSL_COMPAT_H

#include "includes.h"
#ifdef WITH_OPENSSL

#include <openssl/opensslv.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>

#if defined(OPENSSL_VERSION_NUMBER) && (OPENSSL_VERSION_NUMBER < 0x00907000L)
# error "OpenSSL 0.9.7 or greater is required"
#endif

#if defined(OPENSSL_VERSION_NUMBER) && (OPENSSL_VERSION_NUMBER < 0x10000000L)
# define LIBCRYPTO_EVP_INL_TYPE unsigned int
#else
# define LIBCRYPTO_EVP_INL_TYPE size_t
#endif


#ifndef HAVE_EVP_PKEY_PRINT_PARAMS
int EVP_PKEY_print_params(BIO *out, const EVP_PKEY *pkey,
    int indent, /*ASN1_PCTX*/void *pctx);
#endif

extern int  ssh_FIPS_mode(int onoff);

extern void ssh_OpenSSL_startup(void);
extern void ssh_OpenSSL_shuthdown(void);

#ifndef HAVE_OPENSSL_INIT_CRYPTO
# include <openssl/err.h>
#endif
static inline void
ssh_OpenSSL_load_error_strings(void) {
#ifdef HAVE_OPENSSL_INIT_CRYPTO
	OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CRYPTO_STRINGS, NULL);
#else
	ERR_load_crypto_strings();
#endif
}

#endif /* WITH_OPENSSL */

static inline const char*
ssh_OpenSSL_version_text(void) {
#ifndef WITH_OPENSSL
    return "without OpenSSL";
#else
# ifndef HAVE_OPENSSL_INIT_CRYPTO	/* OpenSSL < 1.1 */
    return SSLeay_version(SSLEAY_VERSION);
# else
    return OpenSSL_version(OPENSSL_VERSION);
# endif
#endif
}

#endif /* _OPENSSL_COMPAT_H */
