#ifndef SSHXKEY_H
#define SSHXKEY_H
/*
 * Copyright (c) 2017-2022 Roumen Petrov.  All rights reserved.
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
#include "sshkey.h"
#include "sshbuf.h"

/* extended key support */

const char**	Xkey_algoriths(const struct sshkey *k);

int	Xkey_from_blob(const char *pkalg, const u_char *blob, size_t blen, struct sshkey **keyp);
int	Xkey_to_blob(const char *pkalg, const struct sshkey *key, u_char **blobp, size_t *lenp);

int	Xkey_puts(const char *pkalg, const struct sshkey *key, struct sshbuf *b);
int	Xkey_putb(const char *pkalg, const struct sshkey *key, struct sshbuf *b);

int	Akey_puts_opts(const struct sshkey *key, struct sshbuf *b, enum sshkey_serialize_rep opts);
int	Akey_gets(struct sshbuf *b, struct sshkey **keyp);

int	Akey_to_blob(const struct sshkey *key, u_char **blobp, size_t *lenp);
int	Akey_from_blob(const u_char *blob, size_t blen, struct sshkey **keyp);


int	Xkey_sign(ssh_sign_ctx *ctx, u_char **sigp, size_t *lenp, const u_char *data, size_t datalen);
int	Xkey_check_sigalg(ssh_sign_ctx *ctx, const u_char *sig, size_t siglen);


int	Xkey_verify(ssh_verify_ctx *ctx, const u_char *sig, size_t siglen, const u_char *data, size_t dlen);


/* extended digest support */
#define SSH_MD_RSA_MD5		1
#define SSH_MD_RSA_SHA1		2
#define SSH_MD_DSA_SHA1		3	/* ASN1 */
#define SSH_MD_DSA_RAW		4
#define SSH_MD_EC_SHA256	11	/* ASN1 */
#define SSH_MD_EC_SHA384	12	/* ASN1 */
#define SSH_MD_EC_SHA512	13	/* ASN1 */
#define SSH_MD_EC_SHA256_SSH	20
#define SSH_MD_EC_SHA384_SSH	21
#define SSH_MD_EC_SHA512_SSH	22
#define SSH_MD_RSA_SHA256	23

typedef int	(*fEVP_SignFinal)(EVP_MD_CTX *ctx, unsigned char *md, unsigned int *s, EVP_PKEY *pkey);
typedef int	(*fEVP_VerifyFinal)(EVP_MD_CTX *ctx, const unsigned char *sigbuf, unsigned int siglen, EVP_PKEY *pkey);

struct ssh_evp_md_st {
	int id;
	const EVP_MD *(*md)(void);
	fEVP_SignFinal SignFinal;
	fEVP_VerifyFinal VerifyFinal;
};

ssh_evp_md*	ssh_evp_md_find(int id);


void	ssh_xkalg_dgst_compat(ssh_evp_md *dest, const ssh_evp_md *src, ssh_compat *compat);

#endif /* SSHXKEY_H */
