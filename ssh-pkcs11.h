#ifndef SSH_PKCS11_H
#define SSH_PKCS11_H
/* $OpenBSD: ssh-pkcs11.h,v 1.4 2015/01/15 09:40:00 djm Exp $ */
/*
 * Copyright (c) 2010 Markus Friedl.  All rights reserved.
 * Copyright (c) 2018 Roumen Petrov.  All rights reserved.
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

#include "sshkey.h"

int	pkcs11_init(int);
void	pkcs11_terminate(void);

#ifdef ENABLE_PKCS11
int	pkcs11_add_provider(char *, char *, struct sshkey ***);
int	pkcs11_del_provider(char *);

/* crypto library errors */
/* Function codes. */
#define PKCS11_LOGIN			100
#define PKCS11_REAUTHENTICATE		101
#define PKCS11_RSA_PRIVATE_ENCRYPT	110
#define PKCS11_DSA_DO_SIGN		111
#define PKCS11_ECDSA_DO_SIGN		112
/* Reason codes. */
#define PKCS11_SIGNREQ_FAIL		100
#define PKCS11_C_SIGNINIT_FAIL		101
#define PKCS11_C_SIGN_FAIL		102
#define PKCS11_C_LOGIN_FAIL		103

void ERR_PKCS11_PUT_error(int function, int reason, char *file, int line);
#define PKCS11err(f,r) ERR_PKCS11_PUT_error((f),(r),__FILE__,__LINE__)


void ERR_load_PKCS11_strings(void);

#endif /*def ENABLE_PKCS11*/
#endif /*ndef SSH_PKCS11_H*/
