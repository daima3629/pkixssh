/* $OpenBSD: sshkey.c,v 1.148 2024/12/03 15:53:51 tb Exp $ */
/*
 * Copyright (c) 2000, 2001 Markus Friedl.  All rights reserved.
 * Copyright (c) 2008 Alexander von Gernler.  All rights reserved.
 * Copyright (c) 2010,2011 Damien Miller.  All rights reserved.
 * Copyright (c) 2002-2024 Roumen Petrov.  All rights reserved.
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

#include <sys/types.h>
#include <sys/mman.h>
#include <netinet/in.h>

#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <resolv.h>
#include <time.h>
#ifdef HAVE_UTIL_H
#include <util.h>
#endif /* HAVE_UTIL_H */

#include "ssh2.h"
#include "ssherr.h"
#include "misc.h"
#include "sshbuf.h"
#include "xmalloc.h"
#include "cipher.h"
#include "digest.h"
#define SSHKEY_INTERNAL
#include "ssh-x509.h"
#include "ssh-xkalg.h"
#include "compat.h"
#include "match.h"
#include "log.h"

/* openssh private key file format */
#define MARK_BEGIN		"-----BEGIN OPENSSH PRIVATE KEY-----\n"
#define MARK_END		"-----END OPENSSH PRIVATE KEY-----\n"
#define MARK_BEGIN_LEN		(sizeof(MARK_BEGIN) - 1)
#define MARK_END_LEN		(sizeof(MARK_END) - 1)
#define KDFNAME			"bcrypt"
#define AUTH_MAGIC		"openssh-key-v1"
#define SALT_LEN		16
#define DEFAULT_CIPHERNAME	"aes256-ctr"
#define	DEFAULT_ROUNDS		24

#ifdef USE_SSHKEY_SHIELDING
/*
 * Constants relating to "shielding" support; protection of keys expected
 * to remain in memory for long durations
 */
#define SSHKEY_SHIELD_PREKEY_LEN	(16 * 1024)
#define SSHKEY_SHIELD_CIPHER		"aes256-ctr" /* XXX want AES-EME* */
#define SSHKEY_SHIELD_PREKEY_HASH	SSH_DIGEST_SHA512
#endif /*def USE_SSHKEY_SHIELDING*/

int	sshkey_private_serialize_opt(struct sshkey *key,
    struct sshbuf *buf, enum sshkey_serialize_rep);
static int sshkey_from_blob_internal(struct sshbuf *buf,
    struct sshkey **keyp, int allow_cert);

/* Supported key types */
extern const struct sshkey_impl sshkey_ed25519_impl;
extern const struct sshkey_impl sshkey_ed25519_cert_impl;
#ifdef WITH_OPENSSL
# ifdef OPENSSL_HAS_ECC
extern const struct sshkey_impl sshkey_ecdsa_nistp256_impl;
extern const struct sshkey_impl sshkey_ecdsa_nistp256_cert_impl;
extern const struct sshkey_impl sshkey_ecdsa_nistp384_impl;
extern const struct sshkey_impl sshkey_ecdsa_nistp384_cert_impl;
#  ifdef OPENSSL_HAS_NISTP521
extern const struct sshkey_impl sshkey_ecdsa_nistp521_impl;
extern const struct sshkey_impl sshkey_ecdsa_nistp521_cert_impl;
#  endif /* OPENSSL_HAS_NISTP521 */
# endif /* OPENSSL_HAS_ECC */
extern const struct sshkey_impl sshkey_rsa_impl;
extern const struct sshkey_impl sshkey_rsa_cert_impl;
#ifdef HAVE_EVP_SHA256
extern const struct sshkey_impl sshkey_rsa_sha256_impl;
extern const struct sshkey_impl sshkey_rsa_sha256_cert_impl;
extern const struct sshkey_impl sshkey_rsa_sha512_impl;
extern const struct sshkey_impl sshkey_rsa_sha512_cert_impl;
#endif /*def HAVE_EVP_SHA256*/
# ifdef WITH_DSA
extern const struct sshkey_impl sshkey_dss_impl;
extern const struct sshkey_impl sshkey_dsa_cert_impl;
# endif
#endif /* WITH_OPENSSL */
#ifdef WITH_XMSS
extern const struct sshkey_impl sshkey_xmss_impl;
extern const struct sshkey_impl sshkey_xmss_cert_impl;
#endif /* WITH_XMSS */

static const struct sshkey_impl * const keyimpls[] = {
	&sshkey_ed25519_impl,
	&sshkey_ed25519_cert_impl,
#ifdef WITH_OPENSSL
# ifdef OPENSSL_HAS_ECC
	&sshkey_ecdsa_nistp256_impl,
	&sshkey_ecdsa_nistp256_cert_impl,
	&sshkey_ecdsa_nistp384_impl,
	&sshkey_ecdsa_nistp384_cert_impl,
#  ifdef OPENSSL_HAS_NISTP521
	&sshkey_ecdsa_nistp521_impl,
	&sshkey_ecdsa_nistp521_cert_impl,
#  endif /* OPENSSL_HAS_NISTP521 */
# endif /* OPENSSL_HAS_ECC */
	&sshkey_rsa_impl,
	&sshkey_rsa_cert_impl,
#ifdef HAVE_EVP_SHA256
	&sshkey_rsa_sha256_impl,
	&sshkey_rsa_sha256_cert_impl,
	&sshkey_rsa_sha512_impl,
	&sshkey_rsa_sha512_cert_impl,
#endif /*def HAVE_EVP_SHA256*/
#ifdef WITH_DSA
	&sshkey_dss_impl,
	&sshkey_dsa_cert_impl,
#endif
#endif /* WITH_OPENSSL */
#ifdef WITH_XMSS
	&sshkey_xmss_impl,
	&sshkey_xmss_cert_impl,
#endif /* WITH_XMSS */
	NULL
};


static const struct sshkey_impl *
sshkey_impl_from_type(int type)
{
	const struct sshkey_impl *const* p;

	for (p = keyimpls; *p != NULL; p++) {
		if ((*p)->type == type)
			return *p;
	}
	return NULL;
}

static const struct sshkey_impl *
sshkey_impl_from_type_nid(int type, int nid)
{
	const struct sshkey_impl *const* p;

	for (p = keyimpls; *p != NULL; p++) {
		if ((*p)->type == type &&
		    ((*p)->nid == 0 || (*p)->nid == nid))
			return *p;
	}
	return NULL;
}

static const struct sshkey_impl *
sshkey_impl_from_key(const struct sshkey *k)
{
	if (k == NULL) return NULL;

	return sshkey_impl_from_type_nid(k->type, k->ecdsa_nid);
}

const char *
sshkey_type(const struct sshkey *k)
{
	if (sshkey_is_x509(k)) {
		switch (sshkey_type_plain(k->type)) {
		case KEY_RSA:
			return k->pk ? "RSA+cert" : "X509(rsa)";
		case KEY_ECDSA:
			return k->pk ? "ECDSA+cert" : "X509(ecdsa)";
	#ifdef WITH_DSA
		case KEY_DSA:
			return k->pk ? "DSA+cert" : "X509(dsa)";
	#endif
		case KEY_ED25519:
			return k->pk ? "ED25519+cert" : "X509(ed25519)";
		default:
			break;
		}
	}

{
	const struct sshkey_impl *impl = sshkey_impl_from_key(k);

	return (impl != NULL) ? impl->shortname : "unknown";
}
}

static const char *
sshkey_ssh_name_from_type_nid(int type, int nid)
{
	const struct sshkey_impl *impl = sshkey_impl_from_type_nid(type, nid);

	return (impl != NULL) ? impl->name : "ssh-unknown";
}

int
sshkey_type_is_cert(int type)
{
	const struct sshkey_impl *impl = sshkey_impl_from_type(type);

	return (impl != NULL) ? impl->cert : 0;
}

const char *
sshkey_ssh_name(const struct sshkey *k)
{
{
	const char* p = ssh_x509key_name(k);
	if (p != NULL) return p;
}
	return sshkey_ssh_name_from_type_nid(k->type, k->ecdsa_nid);
}

const char *
sshkey_ssh_name_plain(const struct sshkey *k)
{
	return sshkey_ssh_name_from_type_nid(sshkey_type_plain(k->type),
	    k->ecdsa_nid);
}

static int
type_from_name(const char *name, int allow_short)
{
{
	int k = ssh_x509key_type(name);
	if (k != KEY_UNSPEC) return k;
}
{
	const struct sshkey_impl *const* p;

	for (p = keyimpls; *p != NULL; p++) {
		/* only plain key type could match shortname */
		if ((strcmp((*p)->name, name) == 0) ||
		    (allow_short && !(*p)->cert &&
		    strcasecmp((*p)->shortname, name) == 0))
			return (*p)->type;
	}
}
	return KEY_UNSPEC;
}

int
sshkey_type_from_name(const char *name)
{
	return type_from_name(name, 0);
}

int
sshkey_type_from_shortname(const char *name)
{
	return type_from_name(name, 1);
}

static int
key_type_is_ecdsa_variant(int type)
{
	switch (type) {
	case KEY_ECDSA:
	case KEY_ECDSA_CERT:
		return 1;
	}
	return 0;
}

void
sshkey_types_from_name(const char *name, int *type, int *subtype) {

	if (type == NULL || subtype == NULL) {
		fatal_f("NULL arguments");
		return; /* unreachible code */
	}

	*type = sshkey_type_from_name((char*)name);

	if (key_type_is_ecdsa_variant(*type))
		*subtype = sshkey_ecdsa_nid_from_name(name);
	else
		*subtype = -1;
}

int
sshkey_ecdsa_nid_from_name(const char *name)
{
	if (strncmp(name, "x509v3-ecdsa-", 13) == 0) {
		return sshkey_ecdsa_nid_from_name(name+7);
	}

{
	const struct sshkey_impl *const* p;

	for (p = keyimpls; *p != NULL; p++) {
		if (!key_type_is_ecdsa_variant((*p)->type))
			continue;
		if (strcmp((*p)->name, name) == 0)
			return (*p)->nid;
	}
}
	return -1;
}

char *
sshkey_alg_list(int certs_only, int plain_only, int include_sigonly, char sep)
{
	char *ret = NULL;
	size_t rlen = 0;

	if (!certs_only || plain_only) {
		struct sshbuf *b;

		fill_default_xkalg();
		if ((b = sshbuf_new()) == NULL)
			fatal_f("sshbuf_new failed");
	{	char sep_s[2] = { sep, '\0' };
		ssh_xkalg_listall(b, sep_s);
	}
		ret = xstrdup(sshbuf_ptr(b));
		rlen = sshbuf_len(b);
		sshbuf_free(b);
	}
{
	const struct sshkey_impl *const* p;

	for (p = keyimpls; *p != NULL; p++) {
		size_t nlen;

		if (!include_sigonly && (*p)->sigonly)
			continue;
		if ((certs_only && !(*p)->cert) || (plain_only && (*p)->cert))
			continue;
		if (ret != NULL)
			ret[rlen++] = sep;
		nlen = strlen((*p)->name);
	{	char *tmp = realloc(ret, rlen + nlen + 2);
		if (tmp == NULL) {
			free(ret);
			return NULL;
		}
		ret = tmp;
	}
		memcpy(ret + rlen, (*p)->name, nlen + 1);
		rlen += nlen;
	}
}
	return ret;
}

int
sshkey_algind(const char **name, u_int filter, int loc) {
	int k, n;
	int plain = (filter & SSHKEY_ALG_PLAINKEY) != 0;
	int cert  = (filter & SSHKEY_ALG_CUSTCERT) != 0;

	k = (loc < 0) ? 0 : (loc + 1);
	n = sizeof(keyimpls) / sizeof(keyimpls[0]);

	for (; k < n; k++) {
		const struct sshkey_impl *p = keyimpls[k];
		if (p == NULL) continue;
		if (p->cert) {
			if (!cert) continue;
		} else {
			if (!plain) continue;
		}

		if (name != NULL)
			*name = p->name;

		return k;
	}
	return -1;
}

int
sshkey_names_valid2(const char *names, int allow_wildcard, int plain_only)
{
	char *s, *cp, *p;
	int type;

	if (names == NULL || strcmp(names, "") == 0)
		return 0;
	if ((s = cp = strdup(names)) == NULL)
		return 0;
	for ((p = strsep(&cp, ",")); p && *p != '\0';
	    (p = strsep(&cp, ","))) {
		type = sshkey_type_from_name(p);
		if (type == KEY_UNSPEC) {
			if (allow_wildcard) {
				/*
				 * Try matching key types against the string.
				 * If any has a positive or negative match then
				 * the component is accepted.
				 */
			{
				const SSHX509KeyAlgs *xkalg;
				int loc;
				for (
				    loc = ssh_xkalg_ind(&xkalg, -1);
				    loc >= 0;
				    loc = ssh_xkalg_ind(&xkalg, loc)
				) {
					if (match_pattern_list(
					    xkalg->name, p, 0) == 1) {
						break;
					}
				}
				if (loc >= 0)
					continue;
			}
			{
				const struct sshkey_impl *const* q;

				for (q = keyimpls; *q != NULL; q++) {
					if (match_pattern_list(
					    (*q)->name, p, 0) == 1) {
						break;
					}
				}
				if (q != NULL)
					continue;
			}
			}
			free(s);
			return 0;
		} else if (plain_only && sshkey_type_is_cert(type)) {
			free(s);
			return 0;
		}
	}
	free(s);
	return 1;
}

u_int
sshkey_size(const struct sshkey *k)
{
	const struct sshkey_impl *impl = sshkey_impl_from_key(k);

	if (impl == NULL) return 0;

	if (impl->funcs->size != NULL)
		return impl->funcs->size(k);
	return impl->keybits;
}

static int
sshkey_type_is_valid_ca(int type)
{
	const struct sshkey_impl *impl;

	if ((impl = sshkey_impl_from_type(type)) == NULL)
		return 0;
	/* All non-certificate types may act as CAs */
	return !impl->cert;
}

int
sshkey_is_cert(const struct sshkey *k)
{
	if (k == NULL)
		return 0;
	return sshkey_type_is_cert(k->type);
}

/* Return the cert-less equivalent to a certified key type */
/* Also for X.509 certificate return base key type */
int
sshkey_type_plain(int type)
{
	switch (type) {
	case KEY_RSA_CERT:
		return KEY_RSA;
#ifdef WITH_DSA
	case KEY_DSA_CERT:
		return KEY_DSA;
#endif
	case KEY_ECDSA_CERT:
		return KEY_ECDSA;
	case KEY_ED25519_CERT:
		return KEY_ED25519;
#ifdef WITH_XMSS
	case KEY_XMSS_CERT:
		return KEY_XMSS;
#endif /* WITH_XMSS */
	default:
		return type;
	}
}

/* Return the cert equivalent to a plain key type */
static int
sshkey_type_certified(int type)
{
	switch (type) {
#ifdef WITH_OPENSSL
	case KEY_RSA:
		return KEY_RSA_CERT;
#ifdef WITH_DSA
	case KEY_DSA:
		return KEY_DSA_CERT;
#endif
# ifdef OPENSSL_HAS_ECC
	case KEY_ECDSA:
		return KEY_ECDSA_CERT;
# endif /* OPENSSL_HAS_ECC */
#endif /* WITH_OPENSSL */
	case KEY_ED25519:
		return KEY_ED25519_CERT;
#ifdef WITH_XMSS
	case KEY_XMSS:
		return KEY_XMSS_CERT;
#endif /* WITH_XMSS */
	default:
		return -1;
	}
}

#ifdef WITH_OPENSSL
#ifdef OPENSSL_HAS_ECC
/* XXX: these are really begging for a table-driven approach */
int
sshkey_curve_name_to_nid(const char *name)
{
	if (strcmp(name, "nistp256") == 0)
		return NID_X9_62_prime256v1;
	else if (strcmp(name, "nistp384") == 0)
		return NID_secp384r1;
# ifdef OPENSSL_HAS_NISTP521
	else if (strcmp(name, "nistp521") == 0)
		return NID_secp521r1;
# endif /* OPENSSL_HAS_NISTP521 */
	else
		return -1;
}

u_int
sshkey_curve_nid_to_bits(int nid)
{
	switch (nid) {
	case NID_X9_62_prime256v1:
		return 256;
	case NID_secp384r1:
		return 384;
# ifdef OPENSSL_HAS_NISTP521
	case NID_secp521r1:
		return 521;
# endif /* OPENSSL_HAS_NISTP521 */
	default:
		return 0;
	}
}

int
sshkey_ecdsa_bits_to_nid(int bits)
{
	switch (bits) {
	case 256:
		return NID_X9_62_prime256v1;
	case 384:
		return NID_secp384r1;
# ifdef OPENSSL_HAS_NISTP521
	case 521:
		return NID_secp521r1;
# endif /* OPENSSL_HAS_NISTP521 */
	default:
		return -1;
	}
}

const char *
sshkey_curve_nid_to_name(int nid)
{
	switch (nid) {
	case NID_X9_62_prime256v1:
		return "nistp256";
	case NID_secp384r1:
		return "nistp384";
# ifdef OPENSSL_HAS_NISTP521
	case NID_secp521r1:
		return "nistp521";
# endif /* OPENSSL_HAS_NISTP521 */
	default:
		return NULL;
	}
}

int
sshkey_ec_nid_to_hash_alg(int nid)
{
	int kbits = sshkey_curve_nid_to_bits(nid);

	if (kbits <= 0)
		return -1;

	/* RFC5656 section 6.2.1 */
	if (kbits <= 256)
		return SSH_DIGEST_SHA256;
	else if (kbits <= 384)
		return SSH_DIGEST_SHA384;
	else
		return SSH_DIGEST_SHA512;
}

#else /*ndef OPENSSL_HAS_ECC*/

int   sshkey_curve_name_to_nid(const char *name)	{ (void)name;	return -1; }
u_int sshkey_curve_nid_to_bits(int nid)			{ (void)nid;	return  0; }
int   sshkey_ecdsa_bits_to_nid(int bits)		{ (void)bits;	return -1; }

#endif /*ndef OPENSSL_HAS_ECC*/
#endif /* WITH_OPENSSL */

static void
cert_free(struct sshkey_cert *cert)
{
	u_int i;

	if (cert == NULL)
		return;
	sshbuf_free(cert->certblob);
	sshbuf_free(cert->critical);
	sshbuf_free(cert->extensions);
	free(cert->key_id);
	for (i = 0; i < cert->nprincipals; i++)
		free(cert->principals[i]);
	free(cert->principals);
	sshkey_free(cert->signature_key);
	free(cert->signature_type);
	freezero(cert, sizeof(*cert));
}

static struct sshkey_cert *
cert_new(void)
{
	struct sshkey_cert *cert;

	if ((cert = calloc(1, sizeof(*cert))) == NULL)
		return NULL;
	if ((cert->certblob = sshbuf_new()) == NULL ||
	    (cert->critical = sshbuf_new()) == NULL ||
	    (cert->extensions = sshbuf_new()) == NULL) {
		cert_free(cert);
		return NULL;
	}
	cert->key_id = NULL;
	cert->principals = NULL;
	cert->signature_key = NULL;
	cert->signature_type = NULL;
	return cert;
}

struct sshkey *
sshkey_new(int type)
{
	struct sshkey *k;
	const struct sshkey_impl *impl = NULL;

	if (type != KEY_UNSPEC) {
		impl = sshkey_impl_from_type(type);
		if (impl == NULL) return NULL;
	}

	if ((k = calloc(1, sizeof(*k))) == NULL)
		return NULL;
	k->type = type;
	k->pk = NULL;
	k->ecdsa_nid = -1;
	k->x509_data = NULL;
	k->cert = NULL;
	k->ed25519_sk = NULL;
	k->ed25519_pk = NULL;
	k->xmss_sk = NULL;
	k->xmss_pk = NULL;
#if 0	/* reserved */
	if (impl != NULL && impl->funcs->alloc != NULL) {
		if (impl->funcs->alloc(k) != 0) {
			free(k);
			return NULL;
		}
	}
#endif
	if (sshkey_is_cert(k)) {
		if ((k->cert = cert_new()) == NULL) {
			sshkey_free(k);
			return NULL;
		}
	}

	return k;
}

#ifdef USE_SSHKEY_SHIELDING

#if defined(MAP_NOCORE)		/* FreeBSD and etc. */
# define PREKEY_MMAP_FLAG	MAP_NOCORE
#elif defined(MAP_CONCEAL)	/* OpenBSD */
# define PREKEY_MMAP_FLAG	MAP_CONCEAL
#else
# define PREKEY_MMAP_FLAG	0
#endif

static int
sshkey_prekey_alloc(u_char **prekeyp, size_t len)
{
	u_char *prekey;

	*prekeyp = NULL;
	if ((prekey = mmap(NULL, len, PROT_READ|PROT_WRITE,
	    MAP_ANON|MAP_PRIVATE|PREKEY_MMAP_FLAG, -1, 0)) == MAP_FAILED)
		return SSH_ERR_SYSTEM_ERROR;
#if PREKEY_MMAP_FLAG == 0
#  ifdef MADV_DONTDUMP		/* Linux */
	(void)madvise(prekey, len, MADV_DONTDUMP);
#  endif
#endif
	*prekeyp = prekey;
	return 0;
}

static void
sshkey_prekey_free(void *prekey, size_t len)
{
	if (prekey == NULL)
		return;
	munmap(prekey, len);
}
#endif /*def USE_SSHKEY_SHIELDING*/

void
sshkey_free(struct sshkey *k)
{
	if (k == NULL)
		return;
{	const struct sshkey_impl *impl = (k->type != KEY_UNSPEC)
	    ? sshkey_impl_from_type(k->type)
	    : NULL;
	if (impl != NULL && impl->funcs->cleanup != NULL)
		impl->funcs->cleanup(k);
}
	if (k->x509_data != NULL) {
		SSH_X509_free(k->x509_data);
		k->x509_data = NULL;
	}
	if (sshkey_is_cert(k))
		cert_free(k->cert);
#ifdef USE_SSHKEY_SHIELDING
	freezero(k->shielded_private, k->shielded_len);
	sshkey_prekey_free(k->shield_prekey, k->shield_prekey_len);
#endif /*def USE_SSHKEY_SHIELDING*/
	freezero(k, sizeof(*k));
}

static int
cert_compare(struct sshkey_cert *a, struct sshkey_cert *b)
{
	if (a == NULL && b == NULL)
		return 1;
	if (a == NULL || b == NULL)
		return 0;
	if (sshbuf_len(a->certblob) != sshbuf_len(b->certblob))
		return 0;
	if (timingsafe_bcmp(sshbuf_ptr(a->certblob), sshbuf_ptr(b->certblob),
	    sshbuf_len(a->certblob)) != 0)
		return 0;
	return 1;
}

/*
 * Compare public portions of key only, allowing comparisons between
 * certificates and plain keys too.
 */
int
sshkey_equal_public(const struct sshkey *a, const struct sshkey *b)
{
	const struct sshkey_impl *impl;

	if (a == NULL || b == NULL ||
	    sshkey_type_plain(a->type) != sshkey_type_plain(b->type))
		return 0;

	if (sshkey_is_x509(a) && sshkey_is_x509(b))
		return ssh_x509_equal(a, b) == 0;
/*
#else
  Either public key or X.509 certificate must present. In latter
  case public key is extracted from X.509 certificate and stored
  into 'key'(rsa,dsa,..) member of key structure.
*/

	if ((impl = sshkey_impl_from_type(a->type)) == NULL)
		return 0;
	return impl->funcs->equal(a, b);
}

int
sshkey_equal(const struct sshkey *a, const struct sshkey *b)
{
	if (a == NULL || b == NULL || a->type != b->type)
		return 0;
	if (sshkey_is_cert(a)) {
		if (!cert_compare(a->cert, b->cert))
			return 0;
	}
	return sshkey_equal_public(a, b);
}

int/*bool*/
sshkey_match_pkalg(struct sshkey *key, const char* pkalg) {
	int keytype, subtype;

	if (key == NULL) return 0;
	if (pkalg == NULL) return 0;

	sshkey_types_from_name(pkalg, &keytype, &subtype);
	return (
	    (keytype == key->type) &&
	    (subtype == key->ecdsa_nid)
	);
}

static int
to_blob_buf(const struct sshkey *key, struct sshbuf *b, int force_plain,
  enum sshkey_serialize_rep opts)
{
	int type, ret;
	const struct sshkey_impl *impl;

	if (key == NULL)
		return SSH_ERR_INVALID_ARGUMENT;

	type = force_plain ? sshkey_type_plain(key->type) : key->type;
	if ((impl = sshkey_impl_from_type(type)) == NULL)
		return SSH_ERR_KEY_TYPE_UNKNOWN;

	if (sshkey_type_is_cert(type)) {
		if (key->cert == NULL)
			return SSH_ERR_EXPECTED_CERT;
		if (sshbuf_len(key->cert->certblob) == 0)
			return SSH_ERR_KEY_LACKS_CERTBLOB;
		/* Use the existing blob */
		if ((ret = sshbuf_putb(b, key->cert->certblob)) != 0)
			return ret;
		return 0;
	}

{	const char *typename;
	typename = sshkey_ssh_name_from_type_nid(type, key->ecdsa_nid);
	if ((ret = sshbuf_put_cstring(b, typename)) != 0)
		return ret;
}
	return impl->funcs->serialize_public(key, b, opts);
}

int
sshkey_putb(const struct sshkey *key, struct sshbuf *b)
{
	return to_blob_buf(key, b, 0, SSHKEY_SERIALIZE_DEFAULT);
}

int
sshkey_puts_opts(const struct sshkey *key, struct sshbuf *b,
    enum sshkey_serialize_rep opts)
{
	struct sshbuf *tmp;
	int r;

	if ((tmp = sshbuf_new()) == NULL)
		return SSH_ERR_ALLOC_FAIL;
	r = to_blob_buf(key, tmp, 0, opts);
	if (r == 0)
		r = sshbuf_put_stringb(b, tmp);
	sshbuf_free(tmp);
	return r;
}

#if 1 /* used in unit tests only */
int
sshkey_puts(const struct sshkey *key, struct sshbuf *b)
{
	return sshkey_puts_opts(key, b, SSHKEY_SERIALIZE_DEFAULT);
}

int
sshkey_putb_plain(const struct sshkey *key, struct sshbuf *b)
{
	return to_blob_buf(key, b, 1, SSHKEY_SERIALIZE_DEFAULT);
}
#endif

static int
to_blob(const struct sshkey *key, u_char **blobp, size_t *lenp, int force_plain,
    enum sshkey_serialize_rep opts)
{
	int ret = SSH_ERR_INTERNAL_ERROR;
	size_t len;
	struct sshbuf *b = NULL;

	if (lenp != NULL)
		*lenp = 0;
	if (blobp != NULL)
		*blobp = NULL;
	if ((b = sshbuf_new()) == NULL)
		return SSH_ERR_ALLOC_FAIL;
	if ((ret = to_blob_buf(key, b, force_plain, opts)) != 0)
		goto out;
	len = sshbuf_len(b);
	if (lenp != NULL)
		*lenp = len;
	if (blobp != NULL) {
		if ((*blobp = malloc(len)) == NULL) {
			ret = SSH_ERR_ALLOC_FAIL;
			goto out;
		}
		memcpy(*blobp, sshbuf_ptr(b), len);
	}
	ret = 0;
 out:
	sshbuf_free(b);
	return ret;
}

int
sshkey_to_blob(const struct sshkey *key, u_char **blobp, size_t *lenp)
{
	return to_blob(key, blobp, lenp, 0, SSHKEY_SERIALIZE_DEFAULT);
}

#if 0 /* unused */
int
sshkey_plain_to_blob(const struct sshkey *key, u_char **blobp, size_t *lenp)
{
	return to_blob(key, blobp, lenp, 1, SSHKEY_SERIALIZE_DEFAULT);
}
#endif

int
sshkey_fingerprint_raw(const struct sshkey *k, int dgst_alg,
    u_char **retp, size_t *lenp)
{
	u_char *blob = NULL, *ret = NULL;
	size_t blob_len = 0;
	int r = SSH_ERR_INTERNAL_ERROR;

	if (retp != NULL)
		*retp = NULL;
	if (lenp != NULL)
		*lenp = 0;
#ifdef OPENSSL_FIPS
	/* avoid digest like md5 if FIPS mode is activated */
	if (ssh_digest_alg_name(dgst_alg) == NULL)
		dgst_alg = SSH_DIGEST_SHA256;
#endif
	if (ssh_digest_bytes(dgst_alg) == 0) {
		r = SSH_ERR_INVALID_ARGUMENT;
		goto out;
	}
	if ((r = to_blob(k, &blob, &blob_len, 1, SSHKEY_SERIALIZE_DEFAULT))
	    != 0)
		goto out;
	if ((ret = calloc(1, SSH_DIGEST_MAX_LENGTH)) == NULL) {
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	if ((r = ssh_digest_memory(dgst_alg, blob, blob_len,
	    ret, SSH_DIGEST_MAX_LENGTH)) != 0)
		goto out;
	/* success */
	if (retp != NULL) {
		*retp = ret;
		ret = NULL;
	}
	if (lenp != NULL)
		*lenp = ssh_digest_bytes(dgst_alg);
	r = 0;
 out:
	free(ret);
	if (blob != NULL)
		freezero(blob, blob_len);
	return r;
}

static char *
fingerprint_b64(const char *alg, u_char *dgst_raw, size_t dgst_raw_len)
{
	char *ret;
	size_t plen = strlen(alg) + 1;
	size_t rlen = ((dgst_raw_len + 2) / 3) * 4 + plen + 1;

	if (dgst_raw_len > 65536 || (ret = calloc(1, rlen)) == NULL)
		return NULL;
	strlcpy(ret, alg, rlen);
	strlcat(ret, ":", rlen);
	if (dgst_raw_len == 0)
		return ret;
	if (b64_ntop(dgst_raw, dgst_raw_len, ret + plen, rlen - plen) == -1) {
		freezero(ret, rlen);
		return NULL;
	}
	/* Trim padding characters from end */
	ret[strcspn(ret, "=")] = '\0';
	return ret;
}

static char *
fingerprint_hex(const char *alg, u_char *dgst_raw, size_t dgst_raw_len)
{
	char *retval, hex[5];
	size_t i, rlen = dgst_raw_len * 3 + strlen(alg) + 2;

	if (dgst_raw_len > 65536 || (retval = calloc(1, rlen)) == NULL)
		return NULL;
	strlcpy(retval, alg, rlen);
	strlcat(retval, ":", rlen);
	for (i = 0; i < dgst_raw_len; i++) {
		snprintf(hex, sizeof(hex), "%s%02x",
		    i > 0 ? ":" : "", dgst_raw[i]);
		strlcat(retval, hex, rlen);
	}
	return retval;
}

static char *
fingerprint_bubblebabble(u_char *dgst_raw, size_t dgst_raw_len)
{
	char vowels[] = { 'a', 'e', 'i', 'o', 'u', 'y' };
	char consonants[] = { 'b', 'c', 'd', 'f', 'g', 'h', 'k', 'l', 'm',
	    'n', 'p', 'r', 's', 't', 'v', 'z', 'x' };
	u_int i, j = 0, rounds, seed = 1;
	char *retval;

	rounds = (dgst_raw_len / 2) + 1;
	if ((retval = calloc(rounds, 6)) == NULL)
		return NULL;
	retval[j++] = 'x';
	for (i = 0; i < rounds; i++) {
		u_int idx0, idx1, idx2, idx3, idx4;
		if ((i + 1 < rounds) || (dgst_raw_len % 2 != 0)) {
			idx0 = (((((u_int)(dgst_raw[2 * i])) >> 6) & 3) +
			    seed) % 6;
			idx1 = (((u_int)(dgst_raw[2 * i])) >> 2) & 15;
			idx2 = ((((u_int)(dgst_raw[2 * i])) & 3) +
			    (seed / 6)) % 6;
			retval[j++] = vowels[idx0];
			retval[j++] = consonants[idx1];
			retval[j++] = vowels[idx2];
			if ((i + 1) < rounds) {
				idx3 = (((u_int)(dgst_raw[(2 * i) + 1])) >> 4) & 15;
				idx4 = (((u_int)(dgst_raw[(2 * i) + 1]))) & 15;
				retval[j++] = consonants[idx3];
				retval[j++] = '-';
				retval[j++] = consonants[idx4];
				seed = ((seed * 5) +
				    ((((u_int)(dgst_raw[2 * i])) * 7) +
				    ((u_int)(dgst_raw[(2 * i) + 1])))) % 36;
			}
		} else {
			idx0 = seed % 6;
			idx1 = 16;
			idx2 = seed / 6;
			retval[j++] = vowels[idx0];
			retval[j++] = consonants[idx1];
			retval[j++] = vowels[idx2];
		}
	}
	retval[j++] = 'x';
	retval[j++] = '\0';
	return retval;
}

/*
 * Draw an ASCII-Art representing the fingerprint so human brain can
 * profit from its built-in pattern recognition ability.
 * This technique is called "random art" and can be found in some
 * scientific publications like this original paper:
 *
 * "Hash Visualization: a New Technique to improve Real-World Security",
 * Perrig A. and Song D., 1999, International Workshop on Cryptographic
 * Techniques and E-Commerce (CrypTEC '99)
 * sparrow.ece.cmu.edu/~adrian/projects/validation/validation.pdf
 *
 * The subject came up in a talk by Dan Kaminsky, too.
 *
 * If you see the picture is different, the key is different.
 * If the picture looks the same, you still know nothing.
 *
 * The algorithm used here is a worm crawling over a discrete plane,
 * leaving a trace (augmenting the field) everywhere it goes.
 * Movement is taken from dgst_raw 2bit-wise.  Bumping into walls
 * makes the respective movement vector be ignored for this turn.
 * Graphs are not unambiguous, because circles in graphs can be
 * walked in either direction.
 */

/*
 * Field sizes for the random art.  Have to be odd, so the starting point
 * can be in the exact middle of the picture, and FLDBASE should be >=8 .
 * Else pictures would be too dense, and drawing the frame would
 * fail, too, because the key type would not fit in anymore.
 */
#define	FLDBASE		8
#define	FLDSIZE_Y	(FLDBASE + 1)
#define	FLDSIZE_X	(FLDBASE * 2 + 1)
static char *
fingerprint_randomart(const char *alg, u_char *dgst_raw, size_t dgst_raw_len,
    const struct sshkey *k)
{
	/*
	 * Chars to be used after each other every time the worm
	 * intersects with itself.  Matter of taste.
	 */
	char	*augmentation_string = " .o+=*BOX@%&#/^SE";
	char	*retval, *p, title[FLDSIZE_X], hash[FLDSIZE_X];
	u_char	 field[FLDSIZE_X][FLDSIZE_Y];
	size_t	 i, tlen, hlen;
	u_int	 b;
	int	 x, y, r;
	size_t	 len = strlen(augmentation_string) - 1;

	if ((retval = calloc((FLDSIZE_X + 3), (FLDSIZE_Y + 2))) == NULL)
		return NULL;

	/* initialize field */
	memset(field, 0, FLDSIZE_X * FLDSIZE_Y * sizeof(char));
	x = FLDSIZE_X / 2;
	y = FLDSIZE_Y / 2;

	/* process raw key */
	for (i = 0; i < dgst_raw_len; i++) {
		int input;
		/* each byte conveys four 2-bit move commands */
		input = dgst_raw[i];
		for (b = 0; b < 4; b++) {
			/* evaluate 2 bit, rest is shifted later */
			x += (input & 0x1) ? 1 : -1;
			y += (input & 0x2) ? 1 : -1;

			/* assure we are still in bounds */
			x = MAXIMUM(x, 0);
			y = MAXIMUM(y, 0);
			x = MINIMUM(x, FLDSIZE_X - 1);
			y = MINIMUM(y, FLDSIZE_Y - 1);

			/* augment the field */
			if (field[x][y] < len - 2)
				field[x][y]++;
			input = input >> 2;
		}
	}

	/* mark starting point and end point*/
	field[FLDSIZE_X / 2][FLDSIZE_Y / 2] = len - 1;
	field[x][y] = len;

	/* assemble title */
	r = snprintf(title, sizeof(title), "[%s %u]",
		sshkey_type(k), sshkey_size(k));
	/* If [type size] won't fit, then try [type]; fits "[ED25519-CERT]" */
	if (r < 0 || r > (int)sizeof(title))
		r = snprintf(title, sizeof(title), "[%s]", sshkey_type(k));
	tlen = (r <= 0) ? 0 : strlen(title);

	/* assemble hash ID. */
	r = snprintf(hash, sizeof(hash), "[%s]", alg);
	hlen = (r <= 0) ? 0 : strlen(hash);

	/* output upper border */
	p = retval;
	*p++ = '+';
	i = 0;
	memcpy(p, title, tlen);
	p += tlen;
	for (i += tlen; i < FLDSIZE_X; i++)
		*p++ = '-';
	*p++ = '+';
	*p++ = '\n';

	/* output content */
	for (y = 0; y < FLDSIZE_Y; y++) {
		*p++ = '|';
		for (x = 0; x < FLDSIZE_X; x++)
			*p++ = augmentation_string[MINIMUM(field[x][y], len)];
		*p++ = '|';
		*p++ = '\n';
	}

	/* output lower border */
	*p++ = '+';
	i = 0;
	memcpy(p, hash, hlen);
	p += hlen;
	for (i += hlen; i < FLDSIZE_X; i++)
		*p++ = '-';
#ifdef OPENSSL_FIPS
	if (FIPS_mode()) {
		/* width is enough to write over text*/
		strcpy(p - 6, "[FIPS]");
	}
#endif
	*p++ = '+';

	return retval;
}

char *
sshkey_fingerprint(const struct sshkey *k, int dgst_alg,
    enum sshkey_fp_rep dgst_rep)
{
	char *retval = NULL;
	u_char *dgst_raw;
	size_t dgst_raw_len;

#ifdef OPENSSL_FIPS
	/* avoid digest like md5 if FIPS mode is activated */
	if (ssh_digest_alg_name(dgst_alg) == NULL)
		dgst_alg = SSH_DIGEST_SHA256;
#endif
	if (sshkey_fingerprint_raw(k, dgst_alg, &dgst_raw, &dgst_raw_len) != 0)
		return NULL;
	switch (dgst_rep) {
	case SSH_FP_DEFAULT:
		if (dgst_alg == SSH_DIGEST_MD5) {
			retval = fingerprint_hex(ssh_digest_alg_name(dgst_alg),
			    dgst_raw, dgst_raw_len);
		} else {
			retval = fingerprint_b64(ssh_digest_alg_name(dgst_alg),
			    dgst_raw, dgst_raw_len);
		}
		break;
	case SSH_FP_HEX:
		retval = fingerprint_hex(ssh_digest_alg_name(dgst_alg),
		    dgst_raw, dgst_raw_len);
		break;
	case SSH_FP_BASE64:
		retval = fingerprint_b64(ssh_digest_alg_name(dgst_alg),
		    dgst_raw, dgst_raw_len);
		break;
	case SSH_FP_BUBBLEBABBLE:
		retval = fingerprint_bubblebabble(dgst_raw, dgst_raw_len);
		break;
	case SSH_FP_RANDOMART:
		retval = fingerprint_randomart(ssh_digest_alg_name(dgst_alg),
		    dgst_raw, dgst_raw_len, k);
		break;
	default:
		freezero(dgst_raw, dgst_raw_len);
		return NULL;
	}
	freezero(dgst_raw, dgst_raw_len);
	return retval;
}

/* XXX this can now be made const char * */
int
sshkey_read(struct sshkey *ret, char **cpp)
{
	return sshkey_read_pkalg(ret, cpp, NULL);
}

int
sshkey_read_pkalg(struct sshkey *ret, char **cpp, char **pkalg)
{
	struct sshkey *k;
	char pkname[64];
	char *cp, *blobcopy;
	size_t space;
	int r, type, curve_nid = -1;
	struct sshbuf *blob;

	if (ret == NULL)
		return SSH_ERR_INVALID_ARGUMENT;

	/* caller is responsible to free memory allocated for pkalg */
	if (pkalg) *pkalg = NULL;

	switch (ret->type) {
	case KEY_UNSPEC:
	case KEY_RSA:
	case KEY_ECDSA:
	case KEY_ED25519:
	case KEY_ECDSA_CERT:
	case KEY_RSA_CERT:
	case KEY_ED25519_CERT:
#ifdef WITH_DSA
	case KEY_DSA:
	case KEY_DSA_CERT:
#endif
#ifdef WITH_XMSS
	case KEY_XMSS:
	case KEY_XMSS_CERT:
#endif /* WITH_XMSS */
		break; /* ok */
	default:
		return SSH_ERR_INVALID_ARGUMENT;
	}

	/* Decode type */
	cp = *cpp;
	space = strcspn(cp, " \t");
	if (space == strlen(cp))
		return SSH_ERR_INVALID_FORMAT;
	if ((space < 1) || (space >= sizeof(pkname)))
		return SSH_ERR_INVALID_FORMAT;

	strncpy(pkname, cp, space);
	pkname[space] = '\0';

	sshkey_types_from_name(pkname, &type, &curve_nid);
	if (type == KEY_UNSPEC)
		return SSH_ERR_INVALID_FORMAT;
	if (ret->type != KEY_UNSPEC && ret->type != type)
		return SSH_ERR_KEY_TYPE_MISMATCH;

	/* skip whitespace */
	cp += space;
	cp += strspn(cp, " \t");
	if (*cp == '\0')
		return SSH_ERR_INVALID_FORMAT;

{	char *ep;
	k = X509key_from_subject(pkname, cp, &ep);
	if (k != NULL) {
		cp = ep;
		goto noblob;
	}
}

	if ((blob = sshbuf_new()) == NULL)
		return SSH_ERR_ALLOC_FAIL;

	/* find end of keyblob and decode */
	space = strcspn(cp, " \t");
	if ((blobcopy = strndup(cp, space)) == NULL) {
		sshbuf_free(blob);
		return SSH_ERR_ALLOC_FAIL;
	}
	if ((r = sshbuf_b64tod(blob, blobcopy)) != 0) {
		free(blobcopy);
		sshbuf_free(blob);
		return r;
	}
	free(blobcopy);
	r = parse_key_from_blob(sshbuf_ptr(blob), sshbuf_len(blob), &k, NULL);
	if (r != 0) {
		sshbuf_free(blob);
		return r;
	}
	sshbuf_free(blob);

	/* ensure type of blob matches type at start of line */
	if (k->type != type) {
		sshkey_free(k);
		return SSH_ERR_KEY_TYPE_MISMATCH;
	}
	if (sshkey_type_plain(type) == KEY_ECDSA && curve_nid != k->ecdsa_nid) {
		sshkey_free(k);
		return SSH_ERR_EC_CURVE_MISMATCH;
	}

noblob:
	/* skip whitespace and leave cp at start of comment */
	cp += space;
	cp += strspn(cp, " \t");;

	/* Fill in ret from parsed key */
	ret->type = type;
	if (sshkey_is_cert(ret)) {
		if (!sshkey_is_cert(k)) {
			sshkey_free(k);
			return SSH_ERR_EXPECTED_CERT;
		}
		if (ret->cert != NULL)
			cert_free(ret->cert);
		ret->cert = k->cert;
		k->cert = NULL;
	}
{	const struct sshkey_impl *impl = sshkey_impl_from_type(
	    sshkey_type_plain(ret->type));
	if (impl == NULL) {
		sshkey_free(k);
		return SSH_ERR_INTERNAL_ERROR;
	}
	impl->funcs->move_public(k, ret);
}
	/* Test with loaded key, as for X.509 certificates
	   we consider keys as equivalent if base type match
	 */
	if (sshkey_is_x509(k))
		x509key_move_identity(k, ret);

	sshkey_free(k);

	/* success */
	*cpp = cp;
	if (pkalg)
		*pkalg = xstrdup(pkname); /*fatal on error*/
	return 0;
}


int
sshkey_to_base64(const struct sshkey *key, char **b64p)
{
	int r = SSH_ERR_INTERNAL_ERROR;
	struct sshbuf *b = NULL;
	char *uu = NULL;

	if (b64p != NULL)
		*b64p = NULL;
	if ((b = sshbuf_new()) == NULL)
		return SSH_ERR_ALLOC_FAIL;
	if ((r = sshkey_putb(key, b)) != 0)
		goto out;
	if ((uu = sshbuf_dtob64_string(b, 0)) == NULL) {
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	/* Success */
	if (b64p != NULL) {
		*b64p = uu;
		uu = NULL;
	}
	r = 0;
 out:
	sshbuf_free(b);
	free(uu);
	return r;
}

int
sshkey_format_text(const struct sshkey *key, struct sshbuf *b)
{
	int r = SSH_ERR_INTERNAL_ERROR;
	char *uu = NULL;

	if (sshkey_is_x509(key))
		return x509key_write(key, b);

	if ((r = sshkey_to_base64(key, &uu)) != 0)
		goto out;
	if ((r = sshbuf_putf(b, "%s %s",
	    sshkey_ssh_name(key), uu)) != 0)
		goto out;
	r = 0;
 out:
	free(uu);
	return r;
}

int
sshkey_write(const struct sshkey *key, FILE *f)
{
	struct sshbuf *b = NULL;
	int r = SSH_ERR_INTERNAL_ERROR;

	if ((b = sshbuf_new()) == NULL)
		return SSH_ERR_ALLOC_FAIL;
	if ((r = sshkey_format_text(key, b)) != 0)
		goto out;
	if (fwrite(sshbuf_ptr(b), sshbuf_len(b), 1, f) != 1) {
		if (feof(f))
			errno = EPIPE;
		r = SSH_ERR_SYSTEM_ERROR;
		goto out;
	}
	/* Success */
	r = 0;
 out:
	sshbuf_free(b);
	return r;
}

const char *
sshkey_cert_type(const struct sshkey *k)
{
	switch (k->cert->type) {
	case SSH2_CERT_TYPE_USER:
		return "user";
	case SSH2_CERT_TYPE_HOST:
		return "host";
	default:
		return "unknown";
	}
}

int
sshkey_generate(int type, u_int bits, struct sshkey **keyp)
{
	struct sshkey *k;
	int ret = SSH_ERR_INTERNAL_ERROR;
	const struct sshkey_impl *impl;

	if (keyp == NULL || type != sshkey_type_plain(type))
		return SSH_ERR_INVALID_ARGUMENT;
	*keyp = NULL;
	if ((impl = sshkey_impl_from_type(type)) == NULL)
		return SSH_ERR_KEY_TYPE_UNKNOWN;
	if (impl->funcs->generate == NULL)
		return SSH_ERR_FEATURE_UNSUPPORTED;
	if ((k = sshkey_new(type)) == NULL)
		return SSH_ERR_ALLOC_FAIL;
	if ((ret = impl->funcs->generate(k, bits)) != 0) {
		sshkey_free(k);
		if (ret == SSH_ERR_LIBCRYPTO_ERROR)
			do_log_crypto_errors(SYSLOG_LEVEL_ERROR);
		return ret;
	}
	/* success */
	*keyp = k;
	return 0;
}

int
sshkey_cert_copy(const struct sshkey *from_key, struct sshkey *to_key)
{
	u_int i;
	const struct sshkey_cert *from;
	struct sshkey_cert *to;
	int r = SSH_ERR_INTERNAL_ERROR;

	if (to_key == NULL || (from = from_key->cert) == NULL)
		return SSH_ERR_INVALID_ARGUMENT;

	if ((to = cert_new()) == NULL)
		return SSH_ERR_ALLOC_FAIL;

	if ((r = sshbuf_putb(to->certblob, from->certblob)) != 0 ||
	    (r = sshbuf_putb(to->critical, from->critical)) != 0 ||
	    (r = sshbuf_putb(to->extensions, from->extensions)) != 0)
		goto out;

	to->serial = from->serial;
	to->type = from->type;
	if (from->key_id == NULL)
		to->key_id = NULL;
	else if ((to->key_id = strdup(from->key_id)) == NULL) {
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	to->valid_after = from->valid_after;
	to->valid_before = from->valid_before;
	if (from->signature_key == NULL)
		to->signature_key = NULL;
	else if ((r = sshkey_from_private(from->signature_key,
	    &to->signature_key)) != 0)
		goto out;
	if (from->signature_type != NULL &&
	    (to->signature_type = strdup(from->signature_type)) == NULL) {
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	if (from->nprincipals > SSHKEY_CERT_MAX_PRINCIPALS) {
		r = SSH_ERR_INVALID_ARGUMENT;
		goto out;
	}
	if (from->nprincipals > 0) {
		if ((to->principals = calloc(from->nprincipals,
		    sizeof(*to->principals))) == NULL) {
			r = SSH_ERR_ALLOC_FAIL;
			goto out;
		}
		for (i = 0; i < from->nprincipals; i++) {
			to->principals[i] = strdup(from->principals[i]);
			if (to->principals[i] == NULL) {
				to->nprincipals = i;
				r = SSH_ERR_ALLOC_FAIL;
				goto out;
			}
		}
	}
	to->nprincipals = from->nprincipals;

	/* success */
	cert_free(to_key->cert);
	to_key->cert = to;
	to = NULL;
	r = 0;
 out:
	cert_free(to);
	return r;
}

int
sshkey_from_private(const struct sshkey *k, struct sshkey **pkp)
{
	struct sshkey *n;
	int r;
	const struct sshkey_impl *impl;

	*pkp = NULL;
	if ((impl = sshkey_impl_from_key(k)) == NULL)
		return SSH_ERR_KEY_TYPE_UNKNOWN;
	if ((n = sshkey_new(k->type)) == NULL)
		return SSH_ERR_ALLOC_FAIL;
	if ((r = impl->funcs->copy_public(k, n)) != 0)
		goto out;
	if (sshkey_is_cert(k) && (r = sshkey_cert_copy(k, n)) != 0)
		goto out;

	x509key_copy_identity(k, n);

	/* success */
	*pkp = n;
	n = NULL;
	r = 0;
 out:
	sshkey_free(n);
	return r;
}

/* Check deterministic padding after private key */
static int
private2_check_padding(struct sshbuf *decrypted)
{
	u_char pad;
	size_t i;
	int r;

	i = 0;
	while (sshbuf_len(decrypted)) {
		if ((r = sshbuf_get_u8(decrypted, &pad)) != 0)
			goto out;
		if (pad != (++i & 0xff)) {
			r = SSH_ERR_INVALID_FORMAT;
			goto out;
		}
	}
	/* success */
	r = 0;
 out:
	explicit_bzero(&pad, sizeof(pad));
	explicit_bzero(&i, sizeof(i));
	return r;
}

#ifdef USE_SSHKEY_SHIELDING
int
sshkey_is_shielded(struct sshkey *k)
{
	return k != NULL && k->shielded_private != NULL;
}

int
sshkey_shield_private(struct sshkey *k)
{
	struct sshbuf *prvbuf = NULL;
	u_char *prekey = NULL, *enc = NULL, keyiv[SSH_DIGEST_MAX_LENGTH];
	struct sshcipher_ctx *cctx = NULL;
	const struct sshcipher *cipher;
	size_t i, enclen = 0;
	struct sshkey *kswap = NULL, tmp;
	int r = SSH_ERR_INTERNAL_ERROR;

#ifdef DEBUG_PK
	fprintf(stderr, "%s: entering for %s\n", __func__, sshkey_ssh_name(k));
#endif
	if ((cipher = cipher_by_name(SSHKEY_SHIELD_CIPHER)) == NULL) {
		r = SSH_ERR_INVALID_ARGUMENT;
		goto out;
	}
	if (cipher_keylen(cipher) + cipher_ivlen(cipher) >
	    ssh_digest_bytes(SSHKEY_SHIELD_PREKEY_HASH)) {
		r = SSH_ERR_INTERNAL_ERROR;
		goto out;
	}

	/* Prepare a random pre-key, and from it an ephemeral key */
	if ((r = sshkey_prekey_alloc(&prekey, SSHKEY_SHIELD_PREKEY_LEN)) != 0)
		goto out;
	arc4random_buf(prekey, SSHKEY_SHIELD_PREKEY_LEN);
	if ((r = ssh_digest_memory(SSHKEY_SHIELD_PREKEY_HASH,
	    prekey, SSHKEY_SHIELD_PREKEY_LEN,
	    keyiv, SSH_DIGEST_MAX_LENGTH)) != 0)
		goto out;
#ifdef DEBUG_PK
	fprintf(stderr, "%s: key+iv\n", __func__);
	sshbuf_dump_data(keyiv, ssh_digest_bytes(SSHKEY_SHIELD_PREKEY_HASH),
	    stderr);
#endif
	if ((r = cipher_init(&cctx, cipher, keyiv, cipher_keylen(cipher),
	    keyiv + cipher_keylen(cipher), cipher_ivlen(cipher), 1)) != 0)
		goto out;

	/* Serialise and encrypt the private key using the ephemeral key */
	if ((prvbuf = sshbuf_new()) == NULL) {
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	if (sshkey_is_shielded(k) && (r = sshkey_unshield_private(k)) != 0)
		goto out;
	if ((r = sshkey_private_serialize_opt(k, prvbuf,
	    SSHKEY_SERIALIZE_SHIELD)) != 0)
		goto out;
	/* pad to cipher blocksize */
	i = 0;
	while (sshbuf_len(prvbuf) % cipher_blocksize(cipher)) {
		if ((r = sshbuf_put_u8(prvbuf, ++i & 0xff)) != 0)
			goto out;
	}
#ifdef DEBUG_PK
	fprintf(stderr, "%s: serialised\n", __func__);
	sshbuf_dump(prvbuf, stderr);
#endif
	/* encrypt */
	enclen = sshbuf_len(prvbuf);
	if ((enc = malloc(enclen)) == NULL) {
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	if ((r = cipher_crypt(cctx, 0, enc,
	    sshbuf_ptr(prvbuf), sshbuf_len(prvbuf), 0, 0)) != 0)
		goto out;
#ifdef DEBUG_PK
	fprintf(stderr, "%s: encrypted\n", __func__);
	sshbuf_dump_data(enc, enclen, stderr);
#endif

	/* Make a scrubbed, public-only copy of our private key argument */
	if ((r = sshkey_from_private(k, &kswap)) != 0)
		goto out;

	/* Swap the private key out (it will be destroyed below) */
	tmp = *kswap;
	*kswap = *k;
	*k = tmp;

	/* Insert the shielded key into our argument */
	k->shielded_private = enc;
	k->shielded_len = enclen;
	k->shield_prekey = prekey;
	k->shield_prekey_len = SSHKEY_SHIELD_PREKEY_LEN;
	enc = prekey = NULL; /* transferred */
	enclen = 0;

	/* success */
	r = 0;

 out:
	/* XXX behaviour on error - invalidate original private key? */
	cipher_free(cctx);
	explicit_bzero(keyiv, sizeof(keyiv));
	explicit_bzero(&tmp, sizeof(tmp));
	freezero(enc, enclen);
	sshkey_prekey_free(prekey, SSHKEY_SHIELD_PREKEY_LEN);
	sshkey_free(kswap);
	sshbuf_free(prvbuf);
	return r;
}

int
sshkey_unshield_private(struct sshkey *k)
{
	struct sshbuf *prvbuf = NULL;
	u_char *cp, keyiv[SSH_DIGEST_MAX_LENGTH];
	struct sshcipher_ctx *cctx = NULL;
	const struct sshcipher *cipher;
	struct sshkey *kswap = NULL, tmp;
	int r = SSH_ERR_INTERNAL_ERROR;

#ifdef DEBUG_PK
	fprintf(stderr, "%s: entering for %s\n", __func__, sshkey_ssh_name(k));
#endif
	if (!sshkey_is_shielded(k))
		return 0; /* nothing to do */

	if ((cipher = cipher_by_name(SSHKEY_SHIELD_CIPHER)) == NULL) {
		r = SSH_ERR_INVALID_ARGUMENT;
		goto out;
	}
	if (cipher_keylen(cipher) + cipher_ivlen(cipher) >
	    ssh_digest_bytes(SSHKEY_SHIELD_PREKEY_HASH)) {
		r = SSH_ERR_INTERNAL_ERROR;
		goto out;
	}
	/* check size of shielded key blob */
	if (k->shielded_len < cipher_blocksize(cipher) ||
	    (k->shielded_len % cipher_blocksize(cipher)) != 0) {
		r = SSH_ERR_INVALID_FORMAT;
		goto out;
	}

	/* Calculate the ephemeral key from the prekey */
	if ((r = ssh_digest_memory(SSHKEY_SHIELD_PREKEY_HASH,
	    k->shield_prekey, k->shield_prekey_len,
	    keyiv, SSH_DIGEST_MAX_LENGTH)) != 0)
		goto out;
	if ((r = cipher_init(&cctx, cipher, keyiv, cipher_keylen(cipher),
	    keyiv + cipher_keylen(cipher), cipher_ivlen(cipher), 0)) != 0)
		goto out;
#ifdef DEBUG_PK
	fprintf(stderr, "%s: key+iv\n", __func__);
	sshbuf_dump_data(keyiv, ssh_digest_bytes(SSHKEY_SHIELD_PREKEY_HASH),
	    stderr);
#endif

	/* Decrypt and parse the shielded private key using the ephemeral key */
	if ((prvbuf = sshbuf_new()) == NULL) {
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	if ((r = sshbuf_reserve(prvbuf, k->shielded_len, &cp)) != 0)
		goto out;
	/* decrypt */
#ifdef DEBUG_PK
	fprintf(stderr, "%s: encrypted\n", __func__);
	sshbuf_dump_data(k->shielded_private, k->shielded_len, stderr);
#endif
	if ((r = cipher_crypt(cctx, 0, cp,
	    k->shielded_private, k->shielded_len, 0, 0)) != 0)
		goto out;
#ifdef DEBUG_PK
	fprintf(stderr, "%s: serialised\n", __func__);
	sshbuf_dump(prvbuf, stderr);
#endif
	/* Parse private key */
	if ((r = sshkey_private_deserialize(prvbuf, &kswap)) != 0)
		goto out;

	if ((r = private2_check_padding(prvbuf)) != 0)
		goto out;

	/* Swap the parsed key back into place */
	tmp = *kswap;
	*kswap = *k;
	*k = tmp;

	/* success */
	r = 0;

 out:
	cipher_free(cctx);
	explicit_bzero(keyiv, sizeof(keyiv));
	explicit_bzero(&tmp, sizeof(tmp));
	sshkey_free(kswap);
	sshbuf_free(prvbuf);
	return r;
}
#endif /*def USE_SSHKEY_SHIELDING*/

static int
cert_parse(struct sshbuf *b, struct sshkey *key, struct sshbuf *certbuf)
{
	struct sshbuf *principals = NULL, *crit = NULL;
	struct sshbuf *exts = NULL, *ca = NULL;
	u_char *sig = NULL;
	size_t signed_len = 0, slen = 0, kidlen = 0;
	int ret = SSH_ERR_INTERNAL_ERROR;

	/* Copy the entire key blob for verification and later serialisation */
	if ((ret = sshbuf_putb(key->cert->certblob, certbuf)) != 0)
		return ret;

	/* Parse body of certificate up to signature */
	if ((ret = sshbuf_get_u64(b, &key->cert->serial)) != 0 ||
	    (ret = sshbuf_get_u32(b, &key->cert->type)) != 0 ||
	    (ret = sshbuf_get_cstring(b, &key->cert->key_id, &kidlen)) != 0 ||
	    (ret = sshbuf_froms(b, &principals)) != 0 ||
	    (ret = sshbuf_get_u64(b, &key->cert->valid_after)) != 0 ||
	    (ret = sshbuf_get_u64(b, &key->cert->valid_before)) != 0 ||
	    (ret = sshbuf_froms(b, &crit)) != 0 ||
	    (ret = sshbuf_froms(b, &exts)) != 0 ||
	    (ret = sshbuf_get_string_direct(b, NULL, NULL)) != 0 ||
	    (ret = sshbuf_froms(b, &ca)) != 0) {
		/* XXX debug print error for ret */
		ret = SSH_ERR_INVALID_FORMAT;
		goto out;
	}

	/* Signature is left in the buffer so we can calculate this length */
	signed_len = sshbuf_len(key->cert->certblob) - sshbuf_len(b);

	if ((ret = sshbuf_get_string(b, &sig, &slen)) != 0) {
		ret = SSH_ERR_INVALID_FORMAT;
		goto out;
	}

	if (key->cert->type != SSH2_CERT_TYPE_USER &&
	    key->cert->type != SSH2_CERT_TYPE_HOST) {
		ret = SSH_ERR_KEY_CERT_UNKNOWN_TYPE;
		goto out;
	}

	/* Parse principals section */
	while (sshbuf_len(principals) > 0) {
		char *principal = NULL;
		char **oprincipals = NULL;

		if (key->cert->nprincipals >= SSHKEY_CERT_MAX_PRINCIPALS) {
			ret = SSH_ERR_INVALID_FORMAT;
			goto out;
		}
		if ((ret = sshbuf_get_cstring(principals, &principal,
		    NULL)) != 0) {
			ret = SSH_ERR_INVALID_FORMAT;
			goto out;
		}
		oprincipals = key->cert->principals;
		key->cert->principals = recallocarray(key->cert->principals,
		    key->cert->nprincipals, key->cert->nprincipals + 1,
		    sizeof(*key->cert->principals));
		if (key->cert->principals == NULL) {
			free(principal);
			key->cert->principals = oprincipals;
			ret = SSH_ERR_ALLOC_FAIL;
			goto out;
		}
		key->cert->principals[key->cert->nprincipals++] = principal;
	}

	/*
	 * Stash a copies of the critical options and extensions sections
	 * for later use.
	 */
	if ((ret = sshbuf_putb(key->cert->critical, crit)) != 0 ||
	    (exts != NULL &&
	    (ret = sshbuf_putb(key->cert->extensions, exts)) != 0))
		goto out;

	/*
	 * Validate critical options and extensions sections format.
	 */
	while (sshbuf_len(crit) != 0) {
		if ((ret = sshbuf_get_string_direct(crit, NULL, NULL)) != 0 ||
		    (ret = sshbuf_get_string_direct(crit, NULL, NULL)) != 0) {
			sshbuf_reset(key->cert->critical);
			ret = SSH_ERR_INVALID_FORMAT;
			goto out;
		}
	}
	while (exts != NULL && sshbuf_len(exts) != 0) {
		if ((ret = sshbuf_get_string_direct(exts, NULL, NULL)) != 0 ||
		    (ret = sshbuf_get_string_direct(exts, NULL, NULL)) != 0) {
			sshbuf_reset(key->cert->extensions);
			ret = SSH_ERR_INVALID_FORMAT;
			goto out;
		}
	}

	/* Parse CA key and check signature */
	if (sshkey_from_blob_internal(ca, &key->cert->signature_key, 0) != 0) {
		ret = SSH_ERR_KEY_CERT_INVALID_SIGN_KEY;
		goto out;
	}
	if (!sshkey_type_is_valid_ca(key->cert->signature_key->type)) {
		ret = SSH_ERR_KEY_CERT_INVALID_SIGN_KEY;
		goto out;
	}
{	ssh_compat ctx_compat = { 0, 0 };
	ssh_verify_ctx ctx = { NULL, key->cert->signature_key, &ctx_compat };

	if ((ret = sshkey_verify(&ctx, sig, slen,
	    sshbuf_ptr(key->cert->certblob), signed_len)) != 0)
		goto out;
}
	if ((ret = sshkey_sigtype(sig, slen, &key->cert->signature_type)) != 0)
		goto out;

	/* Success */
	ret = 0;
 out:
	sshbuf_free(ca);
	sshbuf_free(crit);
	sshbuf_free(exts);
	sshbuf_free(principals);
	free(sig);
	return ret;
}


int
sshkey_check_length(const struct sshkey *k)
{
#ifdef WITH_OPENSSL
	/* NOTE RSA/DSA keys validates only length */
	switch(sshkey_type_plain(k->type)) {
	case KEY_RSA:
		return ssh_pkey_validate_public_rsa(k->pk);
#ifdef WITH_DSA
	case KEY_DSA:
		return ssh_pkey_validate_public_dsa(k->pk);
#endif
	}
#else
	UNUSED(k);
#endif
	return 0;
}


static int
sshkey_from_blob_internal(struct sshbuf *b, struct sshkey **keyp,
    int allow_cert)
{
	int type, ret = SSH_ERR_INTERNAL_ERROR;
	char *ktype = NULL;
	struct sshkey *key = NULL;
	struct sshbuf *copy;

#ifdef DEBUG_PK /* XXX */
	sshbuf_dump(b, stderr);
#endif
	if (keyp != NULL)
		*keyp = NULL;

	if ((copy = sshbuf_fromb(b)) == NULL) {
		ret = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	if (sshbuf_get_cstring(b, &ktype, NULL) != 0) {
		ret = SSH_ERR_INVALID_FORMAT;
		goto out;
	}

	type = sshkey_type_from_name(ktype);
	debug3_f("ktype=%.100s", ktype);
	if (!allow_cert && sshkey_type_is_cert(type)) {
		ret = SSH_ERR_KEY_CERT_INVALID_SIGN_KEY;
		goto out;
	}
	if ((key = sshkey_new(type)) == NULL) {
		ret = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	/* skip nonce that precedes all custom certificates */
	if (sshkey_type_is_cert(type)) {
		if (sshbuf_get_string_direct(b, NULL, NULL) != 0) {
			ret = SSH_ERR_INVALID_FORMAT;
			goto out;
		}
	}
{	const struct sshkey_impl *impl = sshkey_impl_from_type(type);
	if (impl == NULL) {
		ret = SSH_ERR_KEY_TYPE_UNKNOWN;
		goto out;
	}
	ret = impl->funcs->deserialize_public(ktype, b, key);
	if (ret != SSH_ERR_SUCCESS) goto out;
}
	/* parse custom certificate portion */
	if (sshkey_is_cert(key) && (ret = cert_parse(b, key, copy)) != 0)
		goto out;

	if (key != NULL && sshbuf_len(b) != 0) {
		ret = SSH_ERR_INVALID_FORMAT;
		goto out;
	}
	ret = 0;
	if (keyp != NULL) {
		*keyp = key;
		key = NULL;
	}
 out:
	sshbuf_free(copy);
	sshkey_free(key);
	free(ktype);
	return ret;
}

int
sshkey_from_blob(const u_char *blob, size_t blen, struct sshkey **keyp)
{
	struct sshbuf *b;
	int r;

	if ((b = sshbuf_from(blob, blen)) == NULL)
		return SSH_ERR_ALLOC_FAIL;
	r = sshkey_from_blob_internal(b, keyp, 1);
	sshbuf_free(b);
	return r;
}

int
sshkey_fromb(struct sshbuf *b, struct sshkey **keyp)
{
	return sshkey_from_blob_internal(b, keyp, 1);
}

int
sshkey_froms(struct sshbuf *buf, struct sshkey **keyp)
{
	struct sshbuf *b;
	int r;

	if ((r = sshbuf_froms(buf, &b)) != 0)
		return r;
	r = sshkey_from_blob_internal(b, keyp, 1);
	sshbuf_free(b);
	return r;
}

int
sshkey_sigtype(const u_char *sig, size_t siglen, char **sigtypep)
{
	int r;
	struct sshbuf *b = NULL;
	char *sigtype = NULL;

	if (sigtypep != NULL)
		*sigtypep = NULL;
	if ((b = sshbuf_from(sig, siglen)) == NULL)
		return SSH_ERR_ALLOC_FAIL;
	if ((r = sshbuf_get_cstring(b, &sigtype, NULL)) != 0)
		goto out;
	/* success */
	if (sigtypep != NULL) {
		*sigtypep = sigtype;
		sigtype = NULL;
	}
	r = 0;
 out:
	free(sigtype);
	sshbuf_free(b);
	return r;
}

/*
 *
 * Checks whether a certificate's signature type is allowed.
 * Returns 0 (success) if the certificate signature type appears in the
 * "allowed" pattern-list, or the key is not a certificate to begin with.
 * Otherwise returns a ssherr.h code.
 */
int
sshkey_check_cert_sigtype(const struct sshkey *key, const char *allowed)
{
	if (key == NULL || allowed == NULL)
		return SSH_ERR_INVALID_ARGUMENT;
	if (!sshkey_type_is_cert(key->type))
		return 0;
	if (key->cert == NULL || key->cert->signature_type == NULL)
		return SSH_ERR_INVALID_ARGUMENT;
	if (match_pattern_list(key->cert->signature_type, allowed, 0) != 1)
		return SSH_ERR_SIGN_ALG_UNSUPPORTED;
	return 0;
}

/*
 * Returns the expected signature algorithm for a given public key algorithm.
 */
static const char *
sshkey_sigalg_by_name(const char *name)
{
	const struct sshkey_impl *const* p;

	for (p = keyimpls; *p != NULL; p++) {
		if (strcmp((*p)->name, name) != 0)
			continue;
		if ((*p)->sigalg != NULL)
			return (*p)->sigalg;
		if (!(*p)->cert)
			return (*p)->name;
		return sshkey_ssh_name_from_type_nid(
		    sshkey_type_plain((*p)->type), (*p)->nid);
	}
	return NULL;
}

/*
 * Verifies that the signature algorithm appearing inside the signature blob
 * matches that which was requested.
 */
int
sshkey_check_sigtype(const u_char *sig, size_t siglen,
    const char *requested_alg)
{
	const char *expected_alg;
	char *sigtype = NULL;
	int r;

	if (requested_alg == NULL)
		return 0;
	if ((expected_alg = sshkey_sigalg_by_name(requested_alg)) == NULL)
		return SSH_ERR_INVALID_ARGUMENT;
	if ((r = sshkey_sigtype(sig, siglen, &sigtype)) != 0)
		return r;
	r = strcmp(expected_alg, sigtype) == 0;
	free(sigtype);
	return r ? 0 : SSH_ERR_SIGN_ALG_UNSUPPORTED;
}

int
ssh_encode_signature(u_char **sigp, size_t *lenp,
    const u_char *signame, const u_char *sigret, size_t siglen
) {
	int r;
	struct sshbuf *buf;

	debug3_f("signame=%s", signame);

	buf = sshbuf_new();
	if (buf == NULL)
		return SSH_ERR_ALLOC_FAIL;

	r = sshbuf_put_cstring(buf, signame);
	if (r != 0) goto done;

	r = sshbuf_put_string(buf, sigret, siglen);
	if (r != 0) goto done;

{	size_t len = sshbuf_len(buf);
	if (sigp != NULL) {
		*sigp = xmalloc(len); /*fatal on error*/
		memcpy(*sigp, sshbuf_ptr(buf), len);
	}
	if (lenp != NULL)
		*lenp = len;
}

done:
	sshbuf_free(buf);

	return r;
}

int
sshkey_sign(const ssh_sign_ctx *ctx,
    u_char **sigp, size_t *lenp,
    const u_char *data, size_t dlen)
{
	struct sshkey *key = ctx->key;
	int was_shielded;
	int r;
	const struct sshkey_impl *impl;

	if (sigp != NULL)
		*sigp = NULL;
	if (lenp != NULL)
		*lenp = 0;
	if (dlen > SSH_KEY_MAX_SIGN_DATA_SIZE)
		return SSH_ERR_INVALID_ARGUMENT;
	if ((impl = sshkey_impl_from_key(key)) == NULL)
		return SSH_ERR_KEY_TYPE_UNKNOWN;
	was_shielded = sshkey_is_shielded(key);
	if ((r = sshkey_unshield_private(key)) != 0)
		return r;
	r = impl->funcs->sign(ctx, sigp, lenp, data, dlen);
	if (was_shielded) {
		int r2 = sshkey_shield_private(key);
		if (r == 0) r = r2;
	}
	return r;
}

/*
 * ssh_key_verify returns 0 for a correct signature  and < 0 on error.
 * If "alg" specified, then the signature must use that algorithm.
 */
int
sshkey_verify(const ssh_verify_ctx *ctx,
    const u_char *sig, size_t siglen,
    const u_char *data, size_t dlen)
{
	struct sshkey *key = ctx->key;
	const struct sshkey_impl *impl;

	if (siglen == 0 || dlen > SSH_KEY_MAX_SIGN_DATA_SIZE)
		return SSH_ERR_INVALID_ARGUMENT;
	if ((impl = sshkey_impl_from_key(key)) == NULL)
		return SSH_ERR_KEY_TYPE_UNKNOWN;
	return impl->funcs->verify(ctx, sig, siglen, data, dlen);
}

/* Convert a plain key to their _CERT equivalent */
int
sshkey_to_certified(struct sshkey *k)
{
	int newtype;

	if ((newtype = sshkey_type_certified(k->type)) == -1)
		return SSH_ERR_INVALID_ARGUMENT;
	if ((k->cert = cert_new()) == NULL)
		return SSH_ERR_ALLOC_FAIL;
	k->type = newtype;
	return 0;
}

/* Convert a certificate to its raw key equivalent */
int
sshkey_drop_cert(struct sshkey *k)
{
	if (!sshkey_type_is_cert(k->type))
		return SSH_ERR_KEY_TYPE_UNKNOWN;
	cert_free(k->cert);
	k->cert = NULL;
	k->type = sshkey_type_plain(k->type);
	return 0;
}

/* Sign a certified key, (re-)generating the signed certblob. */
int
sshkey_certify_custom(struct sshkey *k, struct sshkey *ca, const char *alg,
    const char *sk_provider, const char *sk_pin,
    sshkey_certify_signer *signer, void *signer_ctx)
{
	const struct sshkey_impl *impl;
	struct sshbuf *principals = NULL;
	u_char *ca_blob = NULL, *sig_blob = NULL, nonce[32];
	size_t i, ca_len, sig_len;
	int ret = SSH_ERR_INTERNAL_ERROR;
	struct sshbuf *cert = NULL;
	char *sigtype = NULL;

	if (k == NULL || k->cert == NULL ||
	    k->cert->certblob == NULL || ca == NULL)
		return SSH_ERR_INVALID_ARGUMENT;
	if (!sshkey_is_cert(k))
		return SSH_ERR_KEY_TYPE_UNKNOWN;
	if (!sshkey_type_is_valid_ca(ca->type))
		return SSH_ERR_KEY_CERT_INVALID_SIGN_KEY;
	if ((impl = sshkey_impl_from_key(k)) == NULL)
		return SSH_ERR_INVALID_ARGUMENT;

	/*
	 * If no alg specified as argument but a signature_type was set,
	 * then prefer that. If both were specified, then they must match.
	 */
	if (alg == NULL)
		alg = k->cert->signature_type;
	else if (k->cert->signature_type != NULL &&
	    strcmp(alg, k->cert->signature_type) != 0)
		return SSH_ERR_INVALID_ARGUMENT;

	/*
	 * If no signing algorithm or signature_type was specified and we're
	 * using a RSA key, then default to a good signature algorithm.
	 */
	if (alg == NULL && ca->type == KEY_RSA)
#ifdef HAVE_EVP_SHA256
		alg = "rsa-sha2-256";
#else
		alg = "ssh-rsa";
#endif

	if ((ret = sshkey_to_blob(ca, &ca_blob, &ca_len)) != 0)
		return SSH_ERR_KEY_CERT_INVALID_SIGN_KEY;

	cert = k->cert->certblob; /* for readability */
	sshbuf_reset(cert);
	if ((ret = sshbuf_put_cstring(cert, sshkey_ssh_name(k))) != 0)
		goto out;

	/* -v01 certs put nonce first */
	arc4random_buf(&nonce, sizeof(nonce));
	if ((ret = sshbuf_put_string(cert, nonce, sizeof(nonce))) != 0)
		goto out;

	/* Public key next */
	if ((ret = impl->funcs->serialize_public(k, cert,
	    SSHKEY_SERIALIZE_DEFAULT)) != 0)
		goto out;

	/* Then remaining cert fields */
	if ((ret = sshbuf_put_u64(cert, k->cert->serial)) != 0 ||
	    (ret = sshbuf_put_u32(cert, k->cert->type)) != 0 ||
	    (ret = sshbuf_put_cstring(cert, k->cert->key_id)) != 0)
		goto out;

	if ((principals = sshbuf_new()) == NULL) {
		ret = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	for (i = 0; i < k->cert->nprincipals; i++) {
		if ((ret = sshbuf_put_cstring(principals,
		    k->cert->principals[i])) != 0)
			goto out;
	}
	if ((ret = sshbuf_put_stringb(cert, principals)) != 0 ||
	    (ret = sshbuf_put_u64(cert, k->cert->valid_after)) != 0 ||
	    (ret = sshbuf_put_u64(cert, k->cert->valid_before)) != 0 ||
	    (ret = sshbuf_put_stringb(cert, k->cert->critical)) != 0 ||
	    (ret = sshbuf_put_stringb(cert, k->cert->extensions)) != 0 ||
	    (ret = sshbuf_put_string(cert, NULL, 0)) != 0 || /* Reserved */
	    (ret = sshbuf_put_string(cert, ca_blob, ca_len)) != 0)
		goto out;

	/* Sign the whole mess */
	if ((ret = signer(ca, &sig_blob, &sig_len, sshbuf_ptr(cert),
	    sshbuf_len(cert), alg, sk_provider, sk_pin, 0, signer_ctx)) != 0)
		goto out;
	/* Check and update signature_type against what was actually used */
	if ((ret = sshkey_sigtype(sig_blob, sig_len, &sigtype)) != 0)
		goto out;
	if (alg != NULL && strcmp(alg, sigtype) != 0) {
		ret = SSH_ERR_SIGN_ALG_UNSUPPORTED;
		goto out;
	}
	if (k->cert->signature_type == NULL) {
		k->cert->signature_type = sigtype;
		sigtype = NULL;
	}
	/* Append signature and we are done */
	if ((ret = sshbuf_put_string(cert, sig_blob, sig_len)) != 0)
		goto out;
	ret = 0;
 out:
	if (ret != 0)
		sshbuf_reset(cert);
	free(sig_blob);
	free(ca_blob);
	free(sigtype);
	sshbuf_free(principals);
	return ret;
}

static int /* TODO: use ssh_sign_ctx */
default_key_sign(struct sshkey *key, u_char **sigp, size_t *lenp,
    const u_char *data, size_t datalen,
    const char *alg, const char *sk_provider, const char *sk_pin,
    u_int compat, void *reserved)
{
	ssh_compat ctx_compat = { compat, 0 };
	ssh_sign_ctx ctx = { alg, key, &ctx_compat, sk_provider, sk_pin };

	if (reserved != NULL)
		return SSH_ERR_INVALID_ARGUMENT;
	return sshkey_sign(&ctx, sigp, lenp, data, datalen);
}

int
sshkey_certify(struct sshkey *k, struct sshkey *ca, const char *alg,
    const char *sk_provider, const char *sk_pin)
{
	return sshkey_certify_custom(k, ca, alg, sk_provider, sk_pin,
	    default_key_sign, NULL);
}

int
sshkey_cert_check_authority(const struct sshkey *k,
    int want_host, int require_principal, int wildcard_pattern,
    uint64_t verify_time, const char *name, const char **reason)
{
	u_int i, principal_matches;

	if (reason == NULL)
		return SSH_ERR_INVALID_ARGUMENT;
	if (!sshkey_is_cert(k)) {
		*reason = "Key is not a certificate";
		return SSH_ERR_KEY_CERT_INVALID;
	}
	if (want_host) {
		if (k->cert->type != SSH2_CERT_TYPE_HOST) {
			*reason = "Certificate invalid: not a host certificate";
			return SSH_ERR_KEY_CERT_INVALID;
		}
	} else {
		if (k->cert->type != SSH2_CERT_TYPE_USER) {
			*reason = "Certificate invalid: not a user certificate";
			return SSH_ERR_KEY_CERT_INVALID;
		}
	}
	if (verify_time < k->cert->valid_after) {
		*reason = "Certificate invalid: not yet valid";
		return SSH_ERR_KEY_CERT_INVALID;
	}
	if (verify_time >= k->cert->valid_before) {
		*reason = "Certificate invalid: expired";
		return SSH_ERR_KEY_CERT_INVALID;
	}
	if (k->cert->nprincipals == 0) {
		if (require_principal) {
			*reason = "Certificate lacks principal list";
			return SSH_ERR_KEY_CERT_INVALID;
		}
	} else if (name != NULL) {
		principal_matches = 0;
		for (i = 0; i < k->cert->nprincipals; i++) {
			if (wildcard_pattern) {
				if (match_pattern(k->cert->principals[i],
				    name)) {
					principal_matches = 1;
					break;
				}
			} else if (strcmp(name, k->cert->principals[i]) == 0) {
				principal_matches = 1;
				break;
			}
		}
		if (!principal_matches) {
			*reason = "Certificate invalid: name is not a listed "
			    "principal";
			return SSH_ERR_KEY_CERT_INVALID;
		}
	}
	return 0;
}

int
sshkey_cert_check_authority_now(const struct sshkey *k,
    int want_host, int require_principal, int wildcard_pattern,
    const char *name, const char **reason)
{
	time_t now;

	if ((now = time(NULL)) < 0) {
		/* yikes - system clock before epoch! */
		*reason = "Certificate invalid: not yet valid";
		return SSH_ERR_KEY_CERT_INVALID;
	}
	return sshkey_cert_check_authority(k, want_host, require_principal,
	    wildcard_pattern, (uint64_t)now, name, reason);
}

int
sshkey_cert_check_host(const struct sshkey *key, const char *host,
    int wildcard_principals, const char *ca_sign_algorithms,
    const char **reason)
{
	int r;

	if ((r = sshkey_cert_check_authority_now(key, 1, 0, wildcard_principals,
	    host, reason)) != 0)
		return r;
	if (sshbuf_len(key->cert->critical) != 0) {
		*reason = "Certificate contains unsupported critical options";
		return SSH_ERR_KEY_CERT_INVALID;
	}
	if (ca_sign_algorithms != NULL &&
	    (r = sshkey_check_cert_sigtype(key, ca_sign_algorithms)) != 0) {
		*reason = "Certificate signed with disallowed algorithm";
		return SSH_ERR_KEY_CERT_INVALID;
	}
	return 0;
}

size_t
sshkey_format_cert_validity(const struct sshkey_cert *cert, char *s, size_t l)
{
	char from[32], to[32], ret[128];

	*from = *to = '\0';
	if (cert->valid_after == 0 &&
	    cert->valid_before == 0xffffffffffffffffULL)
		return strlcpy(s, "forever", l);

	if (cert->valid_after != 0)
		format_absolute_time(cert->valid_after, from, sizeof(from));
	if (cert->valid_before != 0xffffffffffffffffULL)
		format_absolute_time(cert->valid_before, to, sizeof(to));

	if (cert->valid_after == 0)
		snprintf(ret, sizeof(ret), "before %s", to);
	else if (cert->valid_before == 0xffffffffffffffffULL)
		snprintf(ret, sizeof(ret), "after %s", from);
	else
		snprintf(ret, sizeof(ret), "from %s to %s", from, to);

	return strlcpy(s, ret, l);
}

int
sshkey_private_serialize_opt(struct sshkey *key, struct sshbuf *buf,
    enum sshkey_serialize_rep opts)
{
	const struct sshkey_impl *impl;
	const char *pkalg = NULL;
	int r;
	int was_shielded;
	struct sshbuf *b;

	impl = sshkey_impl_from_key(key);
	if (impl == NULL)
		return SSH_ERR_INVALID_ARGUMENT;
	if (sshkey_type_is_cert(key->type)) {
		if (key->cert == NULL ||
		    sshbuf_len(key->cert->certblob) == 0)
			return SSH_ERR_INVALID_ARGUMENT;
	}
#ifdef WITH_XMSS
	if (sshkey_type_plain(key->type) == KEY_XMSS) {
		if (key->xmss_name == NULL)
			return SSH_ERR_INVALID_ARGUMENT;
	}
#endif /* WITH_XMSS */
	if ((b = sshbuf_new()) == NULL)
		return SSH_ERR_ALLOC_FAIL;

	was_shielded = sshkey_is_shielded(key);
	if ((r = sshkey_unshield_private(key)) != 0)
		goto out;
	pkalg = sshkey_ssh_name(key);
	if ((r = sshbuf_put_cstring(b, pkalg)) != 0)
		goto out;
	if (sshkey_type_is_cert(key->type)) {
		r = sshbuf_put_stringb(b, key->cert->certblob);
		if (r != 0) goto out;
	}

	r = impl->funcs->serialize_private(key, b, opts);
	if (r != SSH_ERR_SUCCESS) goto out;

	r = X509key_encode_identity(pkalg, key, b);
	if (r != SSH_ERR_SUCCESS) goto out;

	/*
	 * success (but we still need to append the output to buf after
	 * possibly re-shielding the private key)
	 */
	r = 0;
 out:
	if (was_shielded) {
		int r2 = sshkey_shield_private(key);
		if (r == 0) r = r2;
	}
	if (r == 0)
		r = sshbuf_putb(buf, b);
	sshbuf_free(b);

	return r;
}

int
sshkey_private_serialize(struct sshkey *key, struct sshbuf *b)
{
	return sshkey_private_serialize_opt(key, b,
	    SSHKEY_SERIALIZE_DEFAULT);
}

int
sshkey_private_deserialize(struct sshbuf *buf, struct sshkey **kp)
{
	char *tname = NULL;
	struct sshkey *k = NULL;
	int type, r = SSH_ERR_INTERNAL_ERROR;

	if (kp != NULL)
		*kp = NULL;
	if ((r = sshbuf_get_cstring(buf, &tname, NULL)) != 0)
		goto out;
	type = sshkey_type_from_name(tname);
	if (sshkey_type_is_cert(type)) {
		/*
		 * Certificate key private keys begin with the certificate
		 * itself. Make sure this matches the type of the enclosing
		 * private key.
		 */
		if ((r = sshkey_froms(buf, &k)) != 0)
			goto out;
		if (k->type != type) {
			r = SSH_ERR_KEY_CERT_MISMATCH;
			goto out;
		}
		/* For ECDSA keys, the group must match too */
		if (k->type == KEY_ECDSA &&
		    k->ecdsa_nid != sshkey_ecdsa_nid_from_name(tname)) {
			r = SSH_ERR_KEY_CERT_MISMATCH;
			goto out;
		}
	} else {
		if ((k = sshkey_new(type)) == NULL) {
			r = SSH_ERR_ALLOC_FAIL;
			goto out;
		}
	}
{	const struct sshkey_impl *impl = sshkey_impl_from_type(type);
	if (impl == NULL) {
		r = SSH_ERR_KEY_TYPE_UNKNOWN;
		goto out;
	}
	r = impl->funcs->deserialize_private(tname, buf, k);
	if (r != SSH_ERR_SUCCESS) goto out;
}
	r = X509key_decode_identity(tname, buf, k);
	if (r != SSH_ERR_SUCCESS) goto out;
	/* success */
	r = 0;
	if (kp != NULL) {
		*kp = k;
		k = NULL;
	}
 out:
	free(tname);
	sshkey_free(k);
	return r;
}

static int
sshkey_private_to_blob2(struct sshkey *prv, struct sshbuf *blob,
    const char *passphrase, const char *comment, const char *ciphername,
    int rounds)
{
	u_char *cp, *key = NULL, *pubkeyblob = NULL;
	u_char salt[SALT_LEN];
	size_t i, pubkeylen, keylen, ivlen, blocksize, authlen;
	u_int check;
	int r = SSH_ERR_INTERNAL_ERROR;
	struct sshcipher_ctx *ciphercontext = NULL;
	const struct sshcipher *cipher;
	const char *kdfname = KDFNAME;
	struct sshbuf *encoded = NULL, *encrypted = NULL, *kdf = NULL;

	if (rounds <= 0)
		rounds = DEFAULT_ROUNDS;
	if (passphrase == NULL || !strlen(passphrase)) {
		ciphername = "none";
		kdfname = "none";
	} else if (ciphername == NULL)
		ciphername = DEFAULT_CIPHERNAME;
	if ((cipher = cipher_by_name(ciphername)) == NULL) {
		r = SSH_ERR_INVALID_ARGUMENT;
		goto out;
	}

	if ((kdf = sshbuf_new()) == NULL ||
	    (encoded = sshbuf_new()) == NULL ||
	    (encrypted = sshbuf_new()) == NULL) {
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	blocksize = cipher_blocksize(cipher);
	keylen = cipher_keylen(cipher);
	ivlen = cipher_ivlen(cipher);
	authlen = cipher_authlen(cipher);
	if ((key = calloc(1, keylen + ivlen)) == NULL) {
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	if (strcmp(kdfname, "bcrypt") == 0) {
		arc4random_buf(salt, SALT_LEN);
		if (bcrypt_pbkdf(passphrase, strlen(passphrase),
		    salt, SALT_LEN, key, keylen + ivlen, rounds) < 0) {
			r = SSH_ERR_INVALID_ARGUMENT;
			goto out;
		}
		if ((r = sshbuf_put_string(kdf, salt, SALT_LEN)) != 0 ||
		    (r = sshbuf_put_u32(kdf, rounds)) != 0)
			goto out;
	} else if (strcmp(kdfname, "none") != 0) {
		/* Unsupported KDF type */
		r = SSH_ERR_KEY_UNKNOWN_CIPHER;
		goto out;
	}
	if ((r = cipher_init(&ciphercontext, cipher, key, keylen,
	    key + keylen, ivlen, 1)) != 0)
		goto out;

	if ((r = sshbuf_put(encoded, AUTH_MAGIC, sizeof(AUTH_MAGIC))) != 0 ||
	    (r = sshbuf_put_cstring(encoded, ciphername)) != 0 ||
	    (r = sshbuf_put_cstring(encoded, kdfname)) != 0 ||
	    (r = sshbuf_put_stringb(encoded, kdf)) != 0 ||
	    (r = sshbuf_put_u32(encoded, 1)) != 0 ||	/* number of keys */
	    (r = sshkey_to_blob(prv, &pubkeyblob, &pubkeylen)) != 0 ||
	    (r = sshbuf_put_string(encoded, pubkeyblob, pubkeylen)) != 0)
		goto out;

	/* set up the buffer that will be encrypted */

	/* Random check bytes */
	check = arc4random();
	if ((r = sshbuf_put_u32(encrypted, check)) != 0 ||
	    (r = sshbuf_put_u32(encrypted, check)) != 0)
		goto out;

	/* append private key and comment*/
	if ((r = sshkey_private_serialize_opt(prv, encrypted,
	    SSHKEY_SERIALIZE_FULL)) != 0 ||
	    (r = sshbuf_put_cstring(encrypted, comment)) != 0)
		goto out;

	/* padding */
	i = 0;
	while (sshbuf_len(encrypted) % blocksize) {
		if ((r = sshbuf_put_u8(encrypted, ++i & 0xff)) != 0)
			goto out;
	}

	/* length in destination buffer */
	if ((r = sshbuf_put_u32(encoded, sshbuf_len(encrypted))) != 0)
		goto out;

	/* encrypt */
	if ((r = sshbuf_reserve(encoded,
	    sshbuf_len(encrypted) + authlen, &cp)) != 0)
		goto out;
	if ((r = cipher_crypt(ciphercontext, 0, cp,
	    sshbuf_ptr(encrypted), sshbuf_len(encrypted), 0, authlen)) != 0)
		goto out;

	sshbuf_reset(blob);

	/* assemble base64-encoded key */
	if ((r = sshbuf_put(blob, MARK_BEGIN, MARK_BEGIN_LEN)) != 0 ||
	    (r = sshbuf_dtob64(encoded, blob, 1)) != 0 ||
	    (r = sshbuf_put(blob, MARK_END, MARK_END_LEN)) != 0)
		goto out;

	/* success */
	r = 0;

 out:
	sshbuf_free(kdf);
	sshbuf_free(encoded);
	sshbuf_free(encrypted);
	cipher_free(ciphercontext);
	explicit_bzero(salt, sizeof(salt));
	if (key != NULL)
		freezero(key, keylen + ivlen);
	if (pubkeyblob != NULL)
		freezero(pubkeyblob, pubkeylen);
	return r;
}

static int
private2_uudecode(struct sshbuf *blob, struct sshbuf **decodedp)
{
	const u_char *cp;
	size_t encoded_len;
	int r;
	u_char last;
	struct sshbuf *encoded = NULL, *decoded = NULL;

	if (blob == NULL || decodedp == NULL)
		return SSH_ERR_INVALID_ARGUMENT;

	*decodedp = NULL;

	if ((encoded = sshbuf_new()) == NULL ||
	    (decoded = sshbuf_new()) == NULL) {
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}

	/* check preamble */
	cp = sshbuf_ptr(blob);
	encoded_len = sshbuf_len(blob);
	if (encoded_len < (MARK_BEGIN_LEN + MARK_END_LEN) ||
	    memcmp(cp, MARK_BEGIN, MARK_BEGIN_LEN) != 0) {
		r = SSH_ERR_INVALID_FORMAT;
		goto out;
	}
	cp += MARK_BEGIN_LEN;
	encoded_len -= MARK_BEGIN_LEN;

	/* Look for end marker, removing whitespace as we go */
	while (encoded_len > 0) {
		if (*cp != '\n' && *cp != '\r') {
			if ((r = sshbuf_put_u8(encoded, *cp)) != 0)
				goto out;
		}
		last = *cp;
		encoded_len--;
		cp++;
		if (last == '\n') {
			if (encoded_len >= MARK_END_LEN &&
			    memcmp(cp, MARK_END, MARK_END_LEN) == 0) {
				/* \0 terminate */
				if ((r = sshbuf_put_u8(encoded, 0)) != 0)
					goto out;
				break;
			}
		}
	}
	if (encoded_len == 0) {
		r = SSH_ERR_INVALID_FORMAT;
		goto out;
	}

	/* decode base64 */
	if ((r = sshbuf_b64tod(decoded, sshbuf_mutable_ptr(encoded))) != 0)
		goto out;

	/* check magic */
	if (sshbuf_len(decoded) < sizeof(AUTH_MAGIC) ||
	    memcmp(sshbuf_ptr(decoded), AUTH_MAGIC, sizeof(AUTH_MAGIC))) {
		r = SSH_ERR_INVALID_FORMAT;
		goto out;
	}
	/* success */
	*decodedp = decoded;
	decoded = NULL;
	r = 0;
 out:
	sshbuf_free(encoded);
	sshbuf_free(decoded);
	return r;
}

static int
private2_decrypt(struct sshbuf *decoded, const char *passphrase,
    struct sshbuf **decryptedp, struct sshkey **pubkeyp)
{
	char *ciphername = NULL, *kdfname = NULL;
	const struct sshcipher *cipher = NULL;
	int r = SSH_ERR_INTERNAL_ERROR;
	size_t keylen = 0, ivlen = 0, authlen = 0, slen = 0;
	struct sshbuf *kdf = NULL, *decrypted = NULL;
	struct sshcipher_ctx *ciphercontext = NULL;
	struct sshkey *pubkey = NULL;
	u_char *key = NULL, *salt = NULL, *dp;
	u_int blocksize, rounds, nkeys, encrypted_len, check1, check2;

	if (decoded == NULL || decryptedp == NULL || pubkeyp == NULL)
		return SSH_ERR_INVALID_ARGUMENT;

	*decryptedp = NULL;
	*pubkeyp = NULL;

	if ((decrypted = sshbuf_new()) == NULL) {
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}

	/* parse public portion of key */
	if ((r = sshbuf_consume(decoded, sizeof(AUTH_MAGIC))) != 0 ||
	    (r = sshbuf_get_cstring(decoded, &ciphername, NULL)) != 0 ||
	    (r = sshbuf_get_cstring(decoded, &kdfname, NULL)) != 0 ||
	    (r = sshbuf_froms(decoded, &kdf)) != 0 ||
	    (r = sshbuf_get_u32(decoded, &nkeys)) != 0)
		goto out;

	if (nkeys != 1) {
		/* XXX only one key supported at present */
		r = SSH_ERR_INVALID_FORMAT;
		goto out;
	}

	if ((r = sshkey_froms(decoded, &pubkey)) != 0 ||
	    (r = sshbuf_get_u32(decoded, &encrypted_len)) != 0)
		goto out;

	if ((cipher = cipher_by_name(ciphername)) == NULL) {
		r = SSH_ERR_KEY_UNKNOWN_CIPHER;
		goto out;
	}
	if (strcmp(kdfname, "none") != 0 && strcmp(kdfname, "bcrypt") != 0) {
		r = SSH_ERR_KEY_UNKNOWN_CIPHER;
		goto out;
	}
	if (strcmp(kdfname, "none") == 0 && strcmp(ciphername, "none") != 0) {
		r = SSH_ERR_INVALID_FORMAT;
		goto out;
	}
	if ((passphrase == NULL || strlen(passphrase) == 0) &&
	    strcmp(kdfname, "none") != 0) {
		/* passphrase required */
		r = SSH_ERR_KEY_WRONG_PASSPHRASE;
		goto out;
	}

	/* check size of encrypted key blob */
	blocksize = cipher_blocksize(cipher);
	if (encrypted_len < blocksize || (encrypted_len % blocksize) != 0) {
		r = SSH_ERR_INVALID_FORMAT;
		goto out;
	}

	/* setup key */
	keylen = cipher_keylen(cipher);
	ivlen = cipher_ivlen(cipher);
	authlen = cipher_authlen(cipher);
	if ((key = calloc(1, keylen + ivlen)) == NULL) {
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	if (strcmp(kdfname, "bcrypt") == 0) {
		if ((r = sshbuf_get_string(kdf, &salt, &slen)) != 0 ||
		    (r = sshbuf_get_u32(kdf, &rounds)) != 0)
			goto out;
		if (bcrypt_pbkdf(passphrase, strlen(passphrase), salt, slen,
		    key, keylen + ivlen, rounds) < 0) {
			r = SSH_ERR_INVALID_FORMAT;
			goto out;
		}
	}

	/* check that an appropriate amount of auth data is present */
	if (sshbuf_len(decoded) < authlen ||
	    sshbuf_len(decoded) - authlen < encrypted_len) {
		r = SSH_ERR_INVALID_FORMAT;
		goto out;
	}

	/* decrypt private portion of key */
	if ((r = sshbuf_reserve(decrypted, encrypted_len, &dp)) != 0 ||
	    (r = cipher_init(&ciphercontext, cipher, key, keylen,
	    key + keylen, ivlen, 0)) != 0)
		goto out;
	if ((r = cipher_crypt(ciphercontext, 0, dp, sshbuf_ptr(decoded),
	    encrypted_len, 0, authlen)) != 0) {
		/* an integrity error here indicates an incorrect passphrase */
		if (r == SSH_ERR_MAC_INVALID)
			r = SSH_ERR_KEY_WRONG_PASSPHRASE;
		goto out;
	}
	if ((r = sshbuf_consume(decoded, encrypted_len + authlen)) != 0)
		goto out;
	/* there should be no trailing data */
	if (sshbuf_len(decoded) != 0) {
		r = SSH_ERR_INVALID_FORMAT;
		goto out;
	}

	/* check check bytes */
	if ((r = sshbuf_get_u32(decrypted, &check1)) != 0 ||
	    (r = sshbuf_get_u32(decrypted, &check2)) != 0)
		goto out;
	if (check1 != check2) {
		r = SSH_ERR_KEY_WRONG_PASSPHRASE;
		goto out;
	}
	/* success */
	*decryptedp = decrypted;
	decrypted = NULL;
	*pubkeyp = pubkey;
	pubkey = NULL;
	r = 0;
 out:
	cipher_free(ciphercontext);
	free(ciphername);
	free(kdfname);
	sshkey_free(pubkey);
	if (salt != NULL)
		freezero(salt, slen);
	if (key != NULL)
		freezero(key, keylen + ivlen);
	sshbuf_free(kdf);
	sshbuf_free(decrypted);
	return r;
}

static int
sshkey_parse_private2(struct sshbuf *blob, const char *passphrase,
    struct sshkey **keyp, char **commentp)
{
	char *comment = NULL;
	int r = SSH_ERR_INTERNAL_ERROR;
	struct sshbuf *decoded = NULL, *decrypted = NULL;
	struct sshkey *k = NULL, *pubkey = NULL;

	if (keyp != NULL)
		*keyp = NULL;
	if (commentp != NULL)
		*commentp = NULL;

	/* Undo base64 encoding and decrypt the private section */
	if ((r = private2_uudecode(blob, &decoded)) != 0 ||
	    (r = private2_decrypt(decoded, passphrase,
	    &decrypted, &pubkey)) != 0)
		goto out;

	/* Load the private key and comment */
	if ((r = sshkey_private_deserialize(decrypted, &k)) != 0 ||
	    (r = sshbuf_get_cstring(decrypted, &comment, NULL)) != 0)
		goto out;

	/* Check deterministic padding after private section */
	if ((r = private2_check_padding(decrypted)) != 0)
		goto out;

	/* Check that the public key in the envelope matches the private key */
	if (!sshkey_equal(pubkey, k)) {
		r = SSH_ERR_INVALID_FORMAT;
		goto out;
	}

	/* success */
	r = 0;
	if (keyp != NULL) {
		*keyp = k;
		k = NULL;
	}
	if (commentp != NULL) {
		*commentp = comment;
		comment = NULL;
	}
 out:
	free(comment);
	sshbuf_free(decoded);
	sshbuf_free(decrypted);
	sshkey_free(k);
	sshkey_free(pubkey);
	return r;
}

static int
sshkey_parse_private2_pubkey(struct sshbuf *blob,
    struct sshkey **keyp)
{
	int r = SSH_ERR_INTERNAL_ERROR;
	struct sshbuf *decoded = NULL;
	struct sshkey *pubkey = NULL;
	u_int nkeys = 0;

	if (keyp != NULL)
		*keyp = NULL;

	if ((r = private2_uudecode(blob, &decoded)) != 0)
		goto out;
	/* parse public key from unencrypted envelope */
	if ((r = sshbuf_consume(decoded, sizeof(AUTH_MAGIC))) != 0 ||
	    (r = sshbuf_skip_string(decoded)) != 0 || /* cipher */
	    (r = sshbuf_skip_string(decoded)) != 0 || /* KDF alg */
	    (r = sshbuf_skip_string(decoded)) != 0 || /* KDF hint */
	    (r = sshbuf_get_u32(decoded, &nkeys)) != 0)
		goto out;

	if (nkeys != 1) {
		/* XXX only one key supported at present */
		r = SSH_ERR_INVALID_FORMAT;
		goto out;
	}

	/* Parse the public key */
	if ((r = sshkey_froms(decoded, &pubkey)) != 0)
		goto out;

	/* success */
	r = 0;
	if (keyp != NULL) {
		*keyp = pubkey;
		pubkey = NULL;
	}
 out:
	sshbuf_free(decoded);
	sshkey_free(pubkey);
	return r;
}

#ifdef WITH_OPENSSL
static int
sshkey_private_pem_to_blob(struct sshkey *key, struct sshbuf *buf,
    const char *passphrase, int format)
{
	int was_shielded = sshkey_is_shielded(key);
	int r;
	int blen;
	char *bptr;
	BIO *bio;
	struct sshbuf *blob;

	if ((blob = sshbuf_new()) == NULL)
		return SSH_ERR_ALLOC_FAIL;
	if ((bio = BIO_new(BIO_s_mem())) == NULL) {
		sshbuf_free(blob);
		return SSH_ERR_ALLOC_FAIL;
	}
	if ((r = sshkey_unshield_private(key)) != 0)
		goto out;

	r = sshkey_private_to_bio(key, bio, passphrase, format);
	if (r != 0) goto out;

	if ((blen = BIO_get_mem_data(bio, &bptr)) <= 0) {
		r = SSH_ERR_INTERNAL_ERROR;
		goto out;
	}
	if ((r = sshbuf_put(blob, bptr, blen)) != 0)
		goto out;
	r = 0;
 out:
	if (was_shielded) {
		int r2 = sshkey_shield_private(key);
		if (r == 0) r = r2;
	}
	if (r == 0)
		r = sshbuf_putb(buf, blob);
	sshbuf_free(blob);

	BIO_free(bio);
	return r;
}
#endif /* WITH_OPENSSL */

/* Serialise "key" to buffer "blob" */
int
sshkey_private_to_fileblob(struct sshkey *key, struct sshbuf *blob,
    const char *passphrase, const char *comment,
    int format, const char *openssh_format_cipher, int openssh_format_rounds)
{
	if (key->type == KEY_UNSPEC)
		return SSH_ERR_INVALID_ARGUMENT;
	if (sshkey_is_cert(key)) /* paranoid check */
		return SSH_ERR_INVALID_ARGUMENT;

	/* never use proprietary format for X.509 keys */
	if (sshkey_is_x509(key)) {
		if (format == SSHKEY_PRIVATE_OPENSSH)
			format = SSHKEY_PRIVATE_PKCS8;
	}
#ifdef WITH_OPENSSL
	if (key->pk != NULL) {
		if (format != SSHKEY_PRIVATE_OPENSSH)
			return sshkey_private_pem_to_blob(key, blob,
			    passphrase, format);
	}
#endif /* WITH_OPENSSL */

	return sshkey_private_to_blob2(key, blob, passphrase,
	    comment, openssh_format_cipher, openssh_format_rounds);
}

int
sshkey_parse_private_fileblob(struct sshbuf *blob,
    const char *passphrase, struct sshkey **keyp, char **commentp)
{
	int r = SSH_ERR_INTERNAL_ERROR;

	if (keyp != NULL)
		*keyp = NULL;
	if (commentp != NULL)
		*commentp = NULL;

	r = sshkey_parse_private2(blob, passphrase, keyp, commentp);
	/* Do not fallback to PEM parser if only passphrase is wrong. */
	if (r == 0 || r == SSH_ERR_KEY_WRONG_PASSPHRASE)
		return r;
#ifdef WITH_OPENSSL
	return sshbuf_parse_private_pem(blob, passphrase, keyp);
#else
	return SSH_ERR_INVALID_FORMAT;
#endif /* WITH_OPENSSL */
}

int
sshkey_parse_pubkey_from_private_fileblob(struct sshbuf *blob,
    struct sshkey **pubkeyp)
{
	if (parse_x509_from_private_fileblob(blob, pubkeyp) == 0)
		return 0;

	/* custom-format private keys bundle a public key inside */
	return sshkey_parse_private2_pubkey(blob, pubkeyp);
}

int
sshkey_set_filename(struct sshkey *k, const char *filename)
{
	if (k == NULL)
		return SSH_ERR_INVALID_ARGUMENT;
#ifdef WITH_XMSS
	if (sshkey_type_plain(k->type) != KEY_XMSS)
		return 0;
	if (filename == NULL)
		return SSH_ERR_INVALID_ARGUMENT;
	if ((k->xmss_filename = strdup(filename)) == NULL)
		return SSH_ERR_ALLOC_FAIL;
#else
	UNUSED(filename);
#endif
	return 0;
}
