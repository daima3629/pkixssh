/* $OpenBSD: kex.h,v 1.126 2024/09/02 12:13:56 djm Exp $ */
/*
 * Copyright (c) 2000, 2001 Markus Friedl.  All rights reserved.
 * Copyright (c) 2014-2025 Roumen Petrov.  All rights reserved.
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
#ifndef KEX_H
#define KEX_H

#include <signal.h> /* for sig_atomic_t */

#include "evp-compat.h"

#include "mac.h"
#include "crypto_api.h"
#include "sshxkey.h"


#define KEX_COOKIE_LEN	16

#define COMP_NONE	0
/* pre-auth compression (COMP_ZLIB) is only supported in the client */
#define COMP_ZLIB	1
#define COMP_DELAYED	2

#define CURVE25519_SIZE 32

enum kex_init_proposals {
	PROPOSAL_KEX_ALGS,
	PROPOSAL_SERVER_HOST_KEY_ALGS,
	PROPOSAL_ENC_ALGS_CTOS,
	PROPOSAL_ENC_ALGS_STOC,
	PROPOSAL_MAC_ALGS_CTOS,
	PROPOSAL_MAC_ALGS_STOC,
	PROPOSAL_COMP_ALGS_CTOS,
	PROPOSAL_COMP_ALGS_STOC,
	PROPOSAL_LANG_CTOS,
	PROPOSAL_LANG_STOC,
	PROPOSAL_MAX
};

enum kex_modes {
	MODE_IN,
	MODE_OUT,
	MODE_MAX
};

/* kex->flags */
#define KEX_INIT_SENT			0x0001
#define KEX_INITIAL			0x0002
#define KEX_RSA_SHA2_256_SUPPORTED	0x0008 /* only set in server for now */
#define KEX_RSA_SHA2_512_SUPPORTED	0x0010 /* only set in server for now */

struct sshenc {
	char	*name;
	const struct sshcipher *cipher;
	int	enabled;
	u_int	key_len;
	u_int	iv_len;
	u_int	block_size;
	u_char	*key;
	u_char	*iv;
};
struct sshcomp {
	u_int	type;
	int	enabled;
	char	*name;
};
struct newkeys {
	struct sshenc	enc;
	struct sshmac	mac;
	struct sshcomp  comp;
};

struct ssh;
struct kex_impl;

struct kex {
	struct newkeys	*newkeys[MODE_MAX];
	u_int	we_need;
	u_int	dh_need;
	int	server;
	char	*name;
	const struct kex_impl *impl;
	char	*hostkey_alg;
	char	*pkalgs;
	int	ext_info_c;
	int	kex_strict;
	struct sshbuf *my;
	struct sshbuf *peer;
	struct sshbuf *client_version;
	struct sshbuf *server_version;
	struct sshbuf *session_id;
	sig_atomic_t done;
	u_int	flags;
	char	*failed_choice;
	int	(*verify_host_key)(struct sshkey *, struct ssh *);
	struct sshkey *(*find_host_public_key)(const char* pkalg, struct ssh *);
	struct sshkey *(*find_host_private_key)(const char* pkalg, struct ssh *);
	int	(*host_key_index)(struct sshkey *, int, struct ssh *);
	int	(*xsign)(struct ssh *ssh, ssh_sign_ctx *ctx, struct sshkey *pub,
	    u_char **sigp, size_t *lenp, const u_char *data, size_t datalen);
	/* kex specific state */
	EVP_PKEY	*pk;
	u_int	min, max, nbits;	/* GEX */
#ifndef USE_ECDH_X25519
	u_char c25519_key[CURVE25519_SIZE];
#endif
	u_char sntrup761_client_key[crypto_kem_sntrup761_SECRETKEYBYTES]; /* KEM */
	u_char mlkem768_client_key[crypto_kem_mlkem768_SECRETKEYBYTES]; /* KEM */
	struct sshbuf *client_pub;
};

struct kex_impl_funcs {
	int (*init)(struct ssh *);
	int (*keypair)(struct kex *);
	int (*enc)(struct kex *, const struct sshbuf *, struct sshbuf **,
	    struct sshbuf **);
	int (*dec)(struct kex *, const struct sshbuf *, struct sshbuf **);
};

struct kex_impl {
	const char *name;
	int hash_alg;
	int (*enabled)(void);
	const struct kex_impl_funcs *funcs;

	void *spec;
};

const struct kex_impl
	*kex_find_impl(const char *);
int	 kex_names_valid(const char *);
char	*kex_alg_list(char);
char	*kex_names_cat(const char *, const char *);
int	 kex_has_any_alg(const char *, const char *);
int	 kex_assemble_names(char **, const char *, const char *);
void	 kex_proposal_populate_entries(struct ssh *, char *prop[PROPOSAL_MAX],
    char *, const char *, const char *, const char *, const char *);
void	 kex_proposal_free_entries(char *prop[PROPOSAL_MAX]);

int	 kex_exchange_identification(struct ssh *, int);
int	 kex_init_gen(struct ssh *);

struct kex *kex_new(void);
int	 kex_ready(struct ssh *, char *[PROPOSAL_MAX]);
int	 kex_setup(struct ssh *, char *[PROPOSAL_MAX]);
void	 kex_free_newkeys(struct newkeys *);
void	 kex_reset_keys(struct kex *);
void	 kex_free(struct kex *);

int	 kex_buf2prop(struct sshbuf *, int *, char ***);
int	 kex_prop2buf(struct sshbuf *, char *proposal[PROPOSAL_MAX]);
void	 kex_prop_free(char **);

int	 kex_send_kexinit(struct ssh *);
int	 kex_input_kexinit(int, u_int32_t, struct ssh *);
int	 kex_input_ext_info(int, u_int32_t, struct ssh *);
int	 kex_protocol_error(int, u_int32_t, struct ssh *);
int	 kex_derive_keys(struct ssh *, u_char *, u_int, const struct sshbuf *);
int	 kex_send_newkeys(struct ssh *);
int	 kex_start_rekex(struct ssh *);

int	 kex_load_host_keys(struct ssh *ssh, struct sshkey **hostpub, struct sshkey **hostpriv);
int	 kex_verify_host_key(struct ssh *ssh, struct sshkey *key);


int	 kexgex_client(struct ssh *);
int	 kexgex_server(struct ssh *);

int	 kex_dh_key_gen(struct kex *);
int	 kex_dh_compute_key(struct kex *, BIGNUM *, struct sshbuf **);

int	 kexgex_hash(int, const struct sshbuf *, const struct sshbuf *,
    const struct sshbuf *, const struct sshbuf *, const struct sshbuf *,
    int, int, int,
    const BIGNUM *, const BIGNUM *, const BIGNUM *,
    const BIGNUM *, const u_char *, size_t,
    u_char *, size_t *);

int	kex_c25519_keygen_to_sshbuf(struct kex *kex, struct sshbuf **bufp);
int	kex_c25519_shared_secret_to_sshbuf(struct kex *kex,
    const u_char pub[CURVE25519_SIZE], int raw, struct sshbuf **bufp)
	__attribute__((__bounded__(__minbytes__, 2, CURVE25519_SIZE)));


EVP_PKEY*	kex_new_dh_group_bits(int min, int wantbits, int max);
EVP_PKEY*	kex_new_dh_group(BIGNUM *modulus, BIGNUM *gen);

int	kex_shared_secret_to_sshbuf(u_char *kbuf, size_t klen,
    int raw, struct sshbuf **bufp);
#ifdef USE_EVP_PKEY_KEYGEN
int	kex_ecx_keygen_to_sshbuf(struct kex *kex, int key_id, size_t pub_len,
    struct sshbuf **bufp);
int kex_ecx_shared_secret_to_sshbuf(struct kex *kex, int key_id,
    const u_char *kbuf, size_t klen, int raw, struct sshbuf **bufp);
int	kex_pkey_derive_shared_secret(struct kex *kex, EVP_PKEY *peerkey,
    int raw, struct sshbuf **bufp);
#endif /*def USE_EVP_PKEY_KEYGEN*/
int	kex_digest_buffer(int hash_alg, struct sshbuf *buf,
    struct sshbuf **bufp);

int	sshbuf_kex_write_dh_group(struct sshbuf *buf, EVP_PKEY *pk);
int	sshbuf_kex_write_dh_pub(struct sshbuf *buf, EVP_PKEY *pk);


void	dump_digest(const char *, const u_char *, size_t);
void	dump_digestb(const char *, const struct sshbuf *);

#endif
