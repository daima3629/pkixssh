/* $OpenBSD: myproposal.h,v 1.77 2024/12/02 14:06:42 djm Exp $ */
/*
 * Copyright (c) 2000 Markus Friedl.  All rights reserved.
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

#include "includes.h"

#ifdef ENABLE_KEX_SNTRUP761X25519
# define KEX_SNTRUP761X25519	\
	"sntrup761x25519-sha512," \
	"sntrup761x25519-sha512@openssh.com,"
#else
# define KEX_SNTRUP761X25519
#endif
#ifdef ENABLE_KEX_MLKEM768X25519
# define KEX_MLKEM768X25519	\
	"mlkem768x25519-sha256,"
#else
# define KEX_MLKEM768X25519
#endif
#if 0
/* OpenSSH EtM modes are subject of prefix truncation i.e.,
 * "Terrapin Attack: Breaking SSH Channel Integrity By Sequence Number Manipulation".
 */
# define WITHOUT_ETM_FUNCTIONALITY
#endif

#define KEX_SERVER_KEX \
	"curve448-sha512," \
	"curve25519-sha256," \
	"curve25519-sha256@libssh.org," \
	"ecdh-sha2-nistp256," \
	"ecdh-sha2-nistp384," \
	"ecdh-sha2-nistp521," \
	"diffie-hellman-group-exchange-sha256," \
	"diffie-hellman-group18-sha512," \
	"diffie-hellman-group16-sha512," \
	"diffie-hellman-group14-sha256," \
	"diffie-hellman-group17-sha512," \
	"diffie-hellman-group15-sha512," \
	KEX_MLKEM768X25519 \
	KEX_SNTRUP761X25519 \
	"diffie-hellman-group14-sha1"

#define KEX_CLIENT_KEX KEX_SERVER_KEX

#define	KEX_DEFAULT_PK_ALG	\
	"ssh-ed25519-cert-v01@openssh.com," \
	"ecdsa-sha2-nistp256-cert-v01@openssh.com," \
	"ecdsa-sha2-nistp384-cert-v01@openssh.com," \
	"ecdsa-sha2-nistp521-cert-v01@openssh.com," \
	"rsa-sha2-256-cert-v01@openssh.com," \
	"rsa-sha2-512-cert-v01@openssh.com," \
	"ssh-ed25519," \
	"ecdsa-sha2-nistp256," \
	"ecdsa-sha2-nistp384," \
	"ecdsa-sha2-nistp521," \
	"rsa-sha2-256," \
	"rsa-sha2-512," \
	"ssh-rsa"


#ifdef WITHOUT_ETM_FUNCTIONALITY
# define KEX_CHACHA20_POLY1305
#else
# define KEX_CHACHA20_POLY1305 \
	",chacha20-poly1305@openssh.com"
#endif

#define	KEX_SERVER_ENCRYPT \
	"aes128-ctr,aes192-ctr,aes256-ctr," \
	"aes128-gcm@openssh.com,aes256-gcm@openssh.com" \
	KEX_CHACHA20_POLY1305

#define KEX_CLIENT_ENCRYPT KEX_SERVER_ENCRYPT


#ifdef WITHOUT_ETM_FUNCTIONALITY
# define KEX_ETM
#else
# define KEX_ETM \
	",umac-64-etm@openssh.com" \
	",umac-128-etm@openssh.com" \
	",hmac-sha2-256-etm@openssh.com" \
	",hmac-sha2-512-etm@openssh.com" \
	",hmac-sha1-etm@openssh.com"
#endif

#define	KEX_SERVER_MAC \
	"umac-64@openssh.com," \
	"umac-128@openssh.com," \
	"hmac-sha2-256," \
	"hmac-sha2-512," \
	"hmac-sha1" \
	KEX_ETM

#define KEX_CLIENT_MAC KEX_SERVER_MAC

/* Not a KEX value, but here so all the algorithm defaults are together */
#define	SSH_ALLOWED_CA_SIGALGS	\
	"ssh-ed25519," \
	"ecdsa-sha2-nistp256," \
	"ecdsa-sha2-nistp384," \
	"ecdsa-sha2-nistp521," \
	"rsa-sha2-256," \
	"rsa-sha2-512," \
	"ssh-rsa"

#ifdef WITH_ZLIB
#define	KEX_DEFAULT_COMP	"none,zlib@openssh.com"
#else
#define	KEX_DEFAULT_COMP	"none"
#endif
#define	KEX_DEFAULT_LANG	""

#define KEX_CLIENT \
	KEX_CLIENT_KEX, \
	KEX_DEFAULT_PK_ALG, \
	KEX_CLIENT_ENCRYPT, \
	KEX_CLIENT_ENCRYPT, \
	KEX_CLIENT_MAC, \
	KEX_CLIENT_MAC, \
	KEX_DEFAULT_COMP, \
	KEX_DEFAULT_COMP, \
	KEX_DEFAULT_LANG, \
	KEX_DEFAULT_LANG

#define KEX_SERVER \
	KEX_SERVER_KEX, \
	KEX_DEFAULT_PK_ALG, \
	KEX_SERVER_ENCRYPT, \
	KEX_SERVER_ENCRYPT, \
	KEX_SERVER_MAC, \
	KEX_SERVER_MAC, \
	KEX_DEFAULT_COMP, \
	KEX_DEFAULT_COMP, \
	KEX_DEFAULT_LANG, \
	KEX_DEFAULT_LANG
