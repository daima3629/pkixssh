/* $OpenBSD: cipher.h,v 1.55 2020/01/23 10:24:29 dtucker Exp $ */

/*
 * Author: Tatu Ylonen <ylo@cs.hut.fi>
 * Copyright (c) 1995 Tatu Ylonen <ylo@cs.hut.fi>, Espoo, Finland
 *                    All rights reserved
 *
 * As far as I am concerned, the code I have written for this software
 * can be used freely for any purpose.  Any derived versions of this
 * software must be clearly marked as such, and if the derived work is
 * incompatible with the protocol description in the RFC file, it must be
 * called by a name other than "ssh" or "Secure Shell".
 *
 * Copyright (c) 2000 Markus Friedl.  All rights reserved.
 * Copyright (c) 2011-2021 Roumen Petrov.  All rights reserved.
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

#ifndef CIPHER_H
#define CIPHER_H

#include "includes.h"

#include <sys/types.h>
#ifdef WITH_OPENSSL
#include <openssl/evp.h>
#include "evp-compat.h"
#endif

#include "cipher-chachapoly.h"
#include "cipher-aesctr.h"


#ifdef WITH_OPENSSL

#if defined(OPENSSL_VERSION_NUMBER) && (OPENSSL_VERSION_NUMBER < 0x00908000L)
/* Workaround for bug in some openssl versions before 0.9.8f
 * We will not use configure check as 0.9.7x define correct
 * macro or some verdors patch their versions.
 */
#undef EVP_CIPHER_CTX_key_length
#define EVP_CIPHER_CTX_key_length ssh_EVP_CIPHER_CTX_key_length

static inline int
ssh_EVP_CIPHER_CTX_key_length(const EVP_CIPHER_CTX *ctx) { return ctx->key_len; }
#endif


#ifndef HAVE_EVP_CIPHER_CTX_NEW		/* OpenSSL < 0.9.8 */
static inline EVP_CIPHER_CTX*
EVP_CIPHER_CTX_new(void) {
	EVP_CIPHER_CTX *ctx;

	ctx = OPENSSL_malloc(sizeof(EVP_CIPHER_CTX));
	if (ctx != NULL) {
		EVP_CIPHER_CTX_init(ctx);
	}
	return(ctx);
}


static inline void
EVP_CIPHER_CTX_free(EVP_CIPHER_CTX *ctx) {
	if (ctx == NULL) return;

	EVP_CIPHER_CTX_cleanup(ctx);
	OPENSSL_free(ctx);
}
#endif /* ndef HAVE_EVP_CIPHER_CTX_NEW	OpenSSL < 0.9.8 */

#endif /*def WITH_OPENSSL*/


#define CIPHER_ENCRYPT		1
#define CIPHER_DECRYPT		0

struct sshcipher;
struct sshcipher_ctx;

const struct sshcipher *cipher_by_name(const char *);
const char *cipher_warning_message(const struct sshcipher_ctx *);
int	 ciphers_valid(const char *);
char	*cipher_alg_list(char, int);
const char *compression_alg_list(int);
int	 cipher_init(struct sshcipher_ctx **, const struct sshcipher *,
    const u_char *, u_int, const u_char *, u_int, int);
int	 cipher_crypt(struct sshcipher_ctx *, u_int, u_char *, const u_char *,
    u_int, u_int, u_int);
int	 cipher_get_length(struct sshcipher_ctx *, u_int *, u_int,
    const u_char *, u_int);
void	 cipher_free(struct sshcipher_ctx *);
u_int	 cipher_blocksize(const struct sshcipher *);
u_int	 cipher_keylen(const struct sshcipher *);
u_int	 cipher_seclen(const struct sshcipher *);
u_int	 cipher_authlen(const struct sshcipher *);
u_int	 cipher_ivlen(const struct sshcipher *);
u_int	 cipher_is_cbc(const struct sshcipher *);

u_int	 cipher_ctx_is_plaintext(struct sshcipher_ctx *);

int	 cipher_get_keyiv(struct sshcipher_ctx *, u_char *, size_t);
int	 cipher_set_keyiv(struct sshcipher_ctx *, const u_char *, size_t);
int	 cipher_get_keyiv_len(const struct sshcipher_ctx *);

#endif				/* CIPHER_H */
