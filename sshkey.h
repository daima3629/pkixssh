/* $OpenBSD: sshkey.h,v 1.65 2024/09/04 05:33:34 djm Exp $ */
/*
 * Copyright (c) 2000, 2001 Markus Friedl.  All rights reserved.
 * Copyright (c) 2002-2025 Roumen Petrov.  All rights reserved.
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
#ifndef SSHKEY_H
#define SSHKEY_H

#include "evp-compat.h"


#define SSH_RSA_MINIMUM_MODULUS_SIZE	1024
#ifndef OPENSSL_RSA_MAX_MODULUS_BITS
# define OPENSSL_RSA_MAX_MODULUS_BITS	16384
#endif
#define SSH_DSA_BITS			1024
#define SSH_KEY_MAX_SIGN_DATA_SIZE	(1 << 20)

struct sshbuf;

/* Key types */
enum sshkey_types {
	KEY_RSA,
	KEY_ECDSA,
	KEY_ED25519,
	KEY_RSA_CERT,
	KEY_ECDSA_CERT,
	KEY_ED25519_CERT,
#ifdef WITH_DSA
	KEY_DSA,
	KEY_DSA_CERT,
#endif
#ifdef WITH_XMSS
	KEY_XMSS,
	KEY_XMSS_CERT,
#endif
	KEY_UNSPEC
};

/* Default fingerprint hash */
#ifdef HAVE_EVP_SHA256
#define SSH_FP_HASH_DEFAULT	SSH_DIGEST_SHA256
#else
#define SSH_FP_HASH_DEFAULT	SSH_DIGEST_SHA1
#endif

/* Fingerprint representation formats */
enum sshkey_fp_rep {
	SSH_FP_DEFAULT = 0,
	SSH_FP_HEX,
	SSH_FP_BASE64,
	SSH_FP_BUBBLEBABBLE,
	SSH_FP_RANDOMART
};

/* Private key serialisation formats, used on the wire */
enum sshkey_serialize_rep {
	SSHKEY_SERIALIZE_DEFAULT = 0,
	SSHKEY_SERIALIZE_STATE = 1,	/* only state is serialized */
	SSHKEY_SERIALIZE_FULL = 2,	/* include keys for saving to disk */
	SSHKEY_SERIALIZE_SHIELD = 3,	/* everything, for encrypting in ram */
	SSHKEY_SERIALIZE_INFO = 254,	/* minimal information */
};

/* Private key disk formats */
enum sshkey_private_format {
	SSHKEY_PRIVATE_OPENSSH = 0,
	SSHKEY_PRIVATE_PEM = 1,
	SSHKEY_PRIVATE_PKCS8 = 2,
};

/* key is stored in external hardware */
#define SSHKEY_FLAG_EXT		0x0001

#define SSHKEY_CERT_MAX_PRINCIPALS	256
/* XXX opaquify? */
struct sshkey_cert {
	struct sshbuf	*certblob; /* Kept around for use on wire */
	u_int		 type; /* SSH2_CERT_TYPE_USER or SSH2_CERT_TYPE_HOST */
	u_int64_t	 serial;
	char		*key_id;
	u_int		 nprincipals;
	char		**principals;
	u_int64_t	 valid_after, valid_before;
	struct sshbuf	*critical;
	struct sshbuf	*extensions;
	struct sshkey	*signature_key;
	char		*signature_type;
};


typedef struct ssh_x509_st SSH_X509;

/* XXX opaquify? */
struct sshkey {
	int	 type;
	int	 flags;
	EVP_PKEY *pk;
	int	 ecdsa_nid;	/* NID of curve */
	u_char	*ed25519_sk;
	u_char	*ed25519_pk;
	SSH_X509 *x509_data;
	char	*xmss_name;
	char	*xmss_filename;	/* for state file updates */
	void	*xmss_state;	/* depends on xmss_name, opaque */
	u_char	*xmss_sk;
	u_char	*xmss_pk;
	struct sshkey_cert *cert;
#ifdef USE_SSHKEY_SHIELDING
	u_char	*shielded_private;
	size_t	shielded_len;
	u_char	*shield_prekey;
	size_t	shield_prekey_len;
#endif /*def USE_SSHKEY_SHIELDING*/
};

#define	ED25519_SK_SZ	crypto_sign_ed25519_SECRETKEYBYTES
#define	ED25519_PK_SZ	crypto_sign_ed25519_PUBLICKEYBYTES

struct ssh_sign_context_st {
	const char	*alg;		/* public key algorithm name (optional) */
	struct sshkey	*key;		/* signing key */
	ssh_compat	*compat;	/* ssh compatibilities */
	const char	*provider;	/* reserved for security key provider */
	const char	*pin;		/* reserved for security key pin */
};

struct ssh_verify_context_st {
	const char	*alg;		/* public key algorithm name (optional) */
	struct sshkey	*key;		/* signing key */
	ssh_compat	*compat;	/* ssh compatibilities */
};


struct sshkey_impl_funcs {
	u_int (*size)(const struct sshkey *);	/* optional */
/*	int (*alloc)(struct sshkey *);		 reserved */
	void (*cleanup)(struct sshkey *);	/* optional */
	int (*equal)(const struct sshkey *, const struct sshkey *);
	int (*serialize_public)(const struct sshkey *, struct sshbuf *,
	    enum sshkey_serialize_rep);
	int (*deserialize_public)(const char *, struct sshbuf *,
	    struct sshkey *);
	int (*serialize_private)(const struct sshkey *, struct sshbuf *,
	    enum sshkey_serialize_rep);
	int (*deserialize_private)(const char *, struct sshbuf *,
	    struct sshkey *);
	int (*generate)(struct sshkey *, int);	/* optional */
	void (*move_public)(struct sshkey *, struct sshkey *);
	int (*copy_public)(const struct sshkey *, struct sshkey *);
	int (*sign)(const ssh_sign_ctx *ctx,
	    u_char **sigp, size_t *lenp,
	    const u_char *data, size_t dlen);
	int (*verify)(const ssh_verify_ctx *ctx,
	    const u_char *sig, size_t siglen,
	    const u_char *data, size_t dlen);
};

struct sshkey_impl {
	const char *name;
	const char *shortname;
	const char *sigalg;
	int type;
	int nid;
	int cert;
	int sigonly;
	int keybits;
	const struct sshkey_impl_funcs *funcs;
};

struct sshkey	*sshkey_new(int);
void		 sshkey_free(struct sshkey *);
int		 sshkey_equal_public(const struct sshkey *,
    const struct sshkey *);
int		 sshkey_equal(const struct sshkey *, const struct sshkey *);
		 /*bool*/
int		 sshkey_match_pkalg(struct sshkey *key, const char* pkalg);
char		*sshkey_fingerprint(const struct sshkey *,
    int, enum sshkey_fp_rep);
int		 sshkey_fingerprint_raw(const struct sshkey *k,
    int, u_char **retp, size_t *lenp);
const char	*sshkey_type(const struct sshkey *);
const char	*sshkey_cert_type(const struct sshkey *);
int		 sshkey_format_text(const struct sshkey *, struct sshbuf *);
int		 sshkey_write(const struct sshkey *, FILE *);
int		 sshkey_read(struct sshkey *, char **);
int		 sshkey_read_pkalg(struct sshkey *, char **, char **);
u_int		 sshkey_size(const struct sshkey *);

int		 sshkey_generate(int type, u_int bits, struct sshkey **keyp);
int		 sshkey_from_private(const struct sshkey *, struct sshkey **);

#ifdef USE_SSHKEY_SHIELDING
int		 sshkey_is_shielded(struct sshkey *);
int		 sshkey_shield_private(struct sshkey *);
int		 sshkey_unshield_private(struct sshkey *);
#else
static inline int
sshkey_is_shielded(struct sshkey *key) {
	UNUSED(key);
	return 0;
}
static inline int
sshkey_shield_private(struct sshkey *key) {
	UNUSED(key);
	return 0/*SSH_ERR_SUCCESS*/;
}
static inline int
sshkey_unshield_private(struct sshkey *key) {
	UNUSED(key);
	return 0/*SSH_ERR_SUCCESS*/;
}
#endif /*ndef USE_SSHKEY_SHIELDING*/

int	 sshkey_type_from_name(const char *);
int	 sshkey_type_from_shortname(const char *);
void	 sshkey_types_from_name(const char *name, int *type, int *subtype);
int	 sshkey_is_cert(const struct sshkey *);
int	 sshkey_type_is_cert(int);
int	 sshkey_type_plain(int);
int	 sshkey_to_certified(struct sshkey *);
int	 sshkey_drop_cert(struct sshkey *);
int	 sshkey_cert_copy(const struct sshkey *, struct sshkey *);
int	 sshkey_cert_check_authority(const struct sshkey *, int, int, int,
    uint64_t, const char *, const char **);
int	 sshkey_cert_check_authority_now(const struct sshkey *, int, int, int,
    const char *, const char **);
int	 sshkey_cert_check_host(const struct sshkey *, const char *,
    int, const char *, const char **);
size_t	 sshkey_format_cert_validity(const struct sshkey_cert *,
    char *, size_t) __attribute__((__bounded__(__string__, 2, 3)));
int	 sshkey_check_cert_sigtype(const struct sshkey *, const char *);

int	 sshkey_certify(struct sshkey *, struct sshkey *,
    const char *, const char *, const char *);
/* Variant allowing use of a custom signature function (e.g. for ssh-agent) */
typedef int sshkey_certify_signer(struct sshkey *, u_char **, size_t *,
    const u_char *, size_t, const char *, const char *, const char *,
    u_int, void *);
int	 sshkey_certify_custom(struct sshkey *, struct sshkey *, const char *,
    const char *, const char *, sshkey_certify_signer *, void *);

int		 sshkey_ecdsa_nid_from_name(const char *);
int		 sshkey_curve_name_to_nid(const char *);
const char *	 sshkey_curve_nid_to_name(int);
u_int		 sshkey_curve_nid_to_bits(int);
int		 sshkey_ecdsa_bits_to_nid(int);
int		 sshkey_ec_nid_to_hash_alg(int nid);
const char	*sshkey_ssh_name(const struct sshkey *);
const char	*sshkey_ssh_name_plain(const struct sshkey *);
int		 sshkey_names_valid2(const char *, int, int);
char		*sshkey_alg_list(int, int, int, char);

#define SSHKEY_ALG_PLAINKEY	(1<<0)
#define SSHKEY_ALG_CUSTCERT	(1<<1)
#define SSHKEY_ALG_ALL		(SSHKEY_ALG_PLAINKEY|SSHKEY_ALG_CUSTCERT)
int	 sshkey_algind(const char **name, u_int filter, int loc);

int	 sshkey_from_blob(const u_char *, size_t, struct sshkey **);
int	 sshkey_fromb(struct sshbuf *, struct sshkey **);
int	 sshkey_froms(struct sshbuf *, struct sshkey **);
int	 sshkey_to_blob(const struct sshkey *, u_char **, size_t *);
int	 sshkey_to_base64(const struct sshkey *, char **);
int	 sshkey_putb(const struct sshkey *, struct sshbuf *);
int	 sshkey_puts(const struct sshkey *, struct sshbuf *);
int	 sshkey_puts_opts(const struct sshkey *, struct sshbuf *,
    enum sshkey_serialize_rep);
int	 sshkey_plain_to_blob(const struct sshkey *, u_char **, size_t *);
int	 sshkey_putb_plain(const struct sshkey *, struct sshbuf *);

int	 sshkey_sigtype(const u_char *, size_t, char **);
int	 sshkey_sign(const ssh_sign_ctx *, u_char **, size_t *,
    const u_char *, size_t);
int	 sshkey_verify(const ssh_verify_ctx *, const u_char *, size_t,
    const u_char *, size_t);
int	 sshkey_check_sigtype(const u_char *, size_t, const char *);

/* private key parsing and serialisation */
int	sshkey_private_serialize(struct sshkey *key, struct sshbuf *buf);
int	sshkey_private_serialize_opt(struct sshkey *key, struct sshbuf *buf,
    enum sshkey_serialize_rep);
int	sshkey_private_deserialize(struct sshbuf *buf,  struct sshkey **keyp);

/* private key file format parsing and serialisation */
int	sshkey_private_to_fileblob(struct sshkey *key, struct sshbuf *blob,
    const char *passphrase, const char *comment,
    int format, const char *openssh_format_cipher, int openssh_format_rounds);
#if defined(WITH_OPENSSL) && defined(SSHKEY_INTERNAL)
int	sshbuf_parse_private_pem(struct sshbuf *blob,
    const char *passphrase, struct sshkey **keyp);
#endif
int	sshkey_parse_private_fileblob(struct sshbuf *blob,
    const char *passphrase, struct sshkey **keyp, char **commentp);
int	sshkey_parse_pubkey_from_private_fileblob(struct sshbuf *blob,
    struct sshkey **pubkeyp);

int	sshkey_private_to_bio(struct sshkey *key, BIO *bio,
    const char *passphrase, int format);

int	sshkey_check_length(const struct sshkey *);

/* For XMSS */
int	sshkey_set_filename(struct sshkey *, const char *);

int	ssh_encode_signature(u_char **, size_t *, const u_char *,
    const u_char *, size_t);


#ifdef USE_EVP_PKEY_KEYGEN
int	ssh_pkey_keygen_simple(int type, EVP_PKEY **pk);
#endif

#ifdef SSHKEY_INTERNAL
# ifdef WITH_OPENSSL
int	sshkey_from_pkey(EVP_PKEY *pk, struct sshkey **keyp);

void	sshkey_clear_pkey(struct sshkey *key);

void	sshkey_move_pk(struct sshkey *from, struct sshkey *to);

void	ssh_EVP_PKEY_print_private_fp(FILE *fp, const EVP_PKEY *pkey);
#ifdef DEBUG_PK
static void sshkey_dump(const char *func, const struct sshkey *key);
#else
static inline void
sshkey_dump(const char *func, const struct sshkey *key) {
	UNUSED(func);
	UNUSED(key);
}
#endif
#define SSHKEY_DUMP(...)	sshkey_dump(__func__, __VA_ARGS__)

int	 ssh_pkey_validate_public_rsa(EVP_PKEY *pk);
#  ifdef WITH_DSA
int	 ssh_pkey_validate_public_dsa(EVP_PKEY *pk);
#endif
#  ifdef OPENSSL_HAS_ECC
int	 ssh_pkey_validate_public_ecdsa(EVP_PKEY *pk);
int	 ssh_EC_KEY_preserve_nid(EC_KEY *);
int	 ssh_EVP_PKEY_check_public_ec(EVP_PKEY *pk, const EC_POINT *public);
#  endif /* OPENSSL_HAS_ECC */
# endif /* WITH_OPENSSL */
#endif /* SSHKEY_INTERNAL */

int	sshkey_equal_public_pkey(const struct sshkey *, const struct sshkey *);

#endif /* SSHKEY_H */
