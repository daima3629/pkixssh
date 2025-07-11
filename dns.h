/* $OpenBSD: dns.h,v 1.20 2023/02/10 04:56:30 djm Exp $ */
/*
 * Copyright (c) 2003 Wesley Griffin. All rights reserved.
 * Copyright (c) 2003 Jakob Schlyter. All rights reserved.
 * Copyright (c) 2005-2023 Roumen Petrov.  All rights reserved.
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

#ifndef DNS_H
#define DNS_H

#include "includes.h"

struct ssh_conn_info;

enum sshfp_types {
	SSHFP_KEY_RESERVED = 0,
	SSHFP_KEY_RSA = 1,
	SSHFP_KEY_DSA = 2,
	SSHFP_KEY_ECDSA = 3,
	SSHFP_KEY_ED25519 = 4,
	SSHFP_KEY_XMSS = 5
};

enum dns_cert_types {
	DNS_CERT_TYPE_RESERVER =   0,
	DNS_CERT_TYPE_PKIX     =   1, /* X.509 as per PKIX */
	DNS_CERT_TYPE_SPKI     =   2, /* SPKI cert */
	DNS_CERT_TYPE_PGP      =   3, /* PGP cert */
/* 4-252  available for IANA assignment */
	DNS_CERT_TYPE_URI      = 253, /* URI private */
	DNS_CERT_TYPE_OID      = 254, /* OID private */
/* 255-65534  available for IANA assignment */
	DNS_CERT_TYPE_RESERVER2 = 65535
};

enum sshfp_hashes {
	SSHFP_HASH_RESERVED = 0,
	SSHFP_HASH_SHA1 = 1,
#ifdef HAVE_EVP_SHA256
	SSHFP_HASH_SHA256 = 2,
	SSHFP_HASH_MAX = 3
#else
	SSHFP_HASH_MAX = 2
#endif
};

enum dns_key_algo {
	DNS_KEY_ALGO_RESERVED   =   0, /* reserved, see [RFC 2535] Section 11 */
	DNS_KEY_ALGO_UNKNOWN    =   0, /* when algorithm is unknown to a secure DNS [RFC 2538] */
	DNS_KEY_ALGO_RSAMD5     =   1, /* RSA/MD5 [RFC 2537] */
	DNS_KEY_ALGO_DH         =   2, /* Diffie-Hellman [RFC 2539] */
	DNS_KEY_ALGO_DSA        =   3, /* DSA [RFC 2536] */
	DNS_KEY_ALGO_ECC        =   4, /* reserved for elliptic curve crypto */
/* 5-251  available, see [RFC 2535] Section 11 */
	DNS_KEY_ALGO_RSASHA1    =   5, /* RSA/SHA1 [RFC 3110] */
/* 6-251  available, see [RFC 4034] Section A.1. */
	DNS_KEY_ALGO_INDIRECT   = 252, /* reserved for indirect keys */
	DNS_KEY_ALGO_PRIVATEDNS = 253, /* private - domain name (see [RFC 2535]) */
	DNS_KEY_ALGO_PRIVATEOID = 254, /* private - OID (see [RFC 2535]) */
	DNS_KEY_ALGO_RESERVED2  = 255  /* reserved, see [RFC 2535] Section 11 */
};

#define DNS_RDATACLASS_IN	1
#define DNS_RDATATYPE_CERT	37
#define DNS_RDATATYPE_SSHFP	44

#define DNS_VERIFY_FOUND	0x00000001
#define DNS_VERIFY_MATCH	0x00000002
#define DNS_VERIFY_SECURE	0x00000004
#define DNS_VERIFY_FAILED	0x00000008

int	verify_host_key_dns(const char *, struct sockaddr *,
    const struct ssh_conn_info *, struct sshkey *, int *);
int	export_dns_rr(const char *, struct sshkey *, FILE *, int, int);

#endif /* DNS_H */
