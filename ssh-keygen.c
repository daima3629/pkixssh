/* $OpenBSD: ssh-keygen.c,v 1.481 2025/05/24 03:37:40 dtucker Exp $ */
/*
 * Author: Tatu Ylonen <ylo@cs.hut.fi>
 * Copyright (c) 1994 Tatu Ylonen <ylo@cs.hut.fi>, Espoo, Finland
 *                    All rights reserved
 * Identity and host key generation and maintenance.
 *
 * As far as I am concerned, the code I have written for this software
 * can be used freely for any purpose.  Any derived versions of this
 * software must be clearly marked as such, and if the derived work is
 * incompatible with the protocol description in the RFC file, it must be
 * called by a name other than "ssh" or "Secure Shell".
 *
 * Copyright (c) 2005-2025 Roumen Petrov.  All rights reserved.
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

#define SSHKEY_INTERNAL
#include "includes.h"

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>

#ifdef WITH_OPENSSL
#include <openssl/evp.h>
#include <openssl/pem.h>
#include "evp-compat.h"
#ifdef HAVE_FIPSCHECK_H
#  include <fipscheck.h>
#endif
#endif

#ifdef HAVE_STDINT_H
# include <stdint.h>
#endif
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#ifdef HAVE_PATHS_H
# include <paths.h>
#endif
#include <pwd.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <limits.h>
#include <locale.h>
#include <time.h>

#include "xmalloc.h"
#include "ssh-x509.h"
#include "key-eng.h"
#include "ssh-xkalg.h"
#include "compat.h"
#include "authfile.h"
#include "sshbuf.h"
#include "pathnames.h"
#include "log.h"
#include "misc.h"
#include "match.h"
#include "hostfile.h"
#include "dns.h"
#include "ssh.h"
#include "ssh2.h"
#include "ssherr.h"
#include "ssh-pkcs11.h"
#include "atomicio.h"
#include "krl.h"
#include "digest.h"
#include "utf8.h"
#include "authfd.h"
#include "cipher.h"

static char*
default_key_type_name(void) {
#ifdef OPENSSL_FIPS
	if (FIPS_mode())
		return "rsa";
#endif

	return "ed25519";
}

/*
 * Default number of bits in the RSA, DSA and ECDSA keys.  These value can be
 * overridden on the command line.
 *
 * These values, with the exception of DSA, provide security equivalent to at
 * least 128 bits of security according to NIST Special Publication 800-57:
 * Recommendation for Key Management Part 1 rev 4 section 5.6.1.
 * For DSA it (and FIPS-186-4 section 4.2) specifies that the only size for
 * which a 160bit hash is acceptable is 1kbit, and since ssh-dss specifies only
 * SHA1 we limit the DSA key size 1k bits.
 */
#define DEFAULT_BITS		3072
#define DEFAULT_BITS_DSA	1024
#define DEFAULT_BITS_ECDSA	256

static int quiet = 0;

/* Flag indicating that we just want to see the key fingerprint */
static int print_fingerprint = 0;
static int print_bubblebabble = 0;

/* Hash algorithm to use for fingerprints. */
static int fingerprint_hash = SSH_FP_HASH_DEFAULT;

/* The identity file name, given on the command line or entered by the user. */
static char identity_file[PATH_MAX];
static int have_identity = 0;

/* This is set to the passphrase if given on the command line. */
static char *identity_passphrase = NULL;

/* This is set to the new passphrase if given on the command line. */
static char *identity_new_passphrase = NULL;

/* Key type when certifying */
static u_int cert_key_type = SSH2_CERT_TYPE_USER;

/* "key ID" of signed key */
static char *cert_key_id = NULL;

/* Comma-separated list of principal names for certifying keys */
static char *cert_principals = NULL;

/* Validity period for certificates */
static u_int64_t cert_valid_from = 0;
static u_int64_t cert_valid_to = ~0ULL;

/* Certificate options */
#define CERTOPT_X_FWD	(1)
#define CERTOPT_AGENT_FWD	(1<<1)
#define CERTOPT_PORT_FWD	(1<<2)
#define CERTOPT_PTY		(1<<3)
#define CERTOPT_USER_RC	(1<<4)
#define CERTOPT_DEFAULT	(CERTOPT_X_FWD|CERTOPT_AGENT_FWD| \
			 CERTOPT_PORT_FWD|CERTOPT_PTY|CERTOPT_USER_RC)
static u_int32_t certflags_flags = CERTOPT_DEFAULT;
static char *certflags_command = NULL;
static char *certflags_src_addr = NULL;

/* Arbitrary extensions specified by user */
struct cert_ext {
	char *key;
	char *val;
	int crit;
};
static struct cert_ext *cert_ext;
static size_t ncert_ext;

/* Conversion to/from various formats */
enum {
	FMT_RFC4716,
	FMT_PKCS8,
	FMT_PEM
} convert_format = FMT_RFC4716;

static char *key_type_name = NULL;

/* Load key from this PKCS#11 provider */
static char *pkcs11provider = NULL;

/* Format for writing private keys */
static int private_key_format = SSHKEY_PRIVATE_PKCS8;

/* Cipher for private keys in OpenSSH proprietary format */
static char *openssh_format_cipher = NULL;

/* Number of KDF rounds to derive new format keys. */
static int rounds = 0;

/* argv0 */
extern char *__progname;

static char hostname[NI_MAXHOST];

#ifdef ENABLE_KEX_DH
/* moduli.c */
int gen_candidates(FILE *, u_int32_t, BIGNUM *);
int prime_test(FILE *, FILE *, u_int32_t, u_int32_t, char *, unsigned long,
    unsigned long);
#endif


typedef void (*fingerprint_format_f)(const struct sshkey *public,
    const char *comment, const char *fp, va_list ap);

static void
fingerprint_format(const struct sshkey *public, const char *comment,
    fingerprint_format_f format_f, ...);


static void
print_fingerprint_one_key(const struct sshkey *public,
    const char *comment, const char *fp, va_list ap)
{
	UNUSED(ap);
	mprintf("%u %s %s (%s)\n", sshkey_size(public), fp,
	    comment ? comment : "no comment", sshkey_type(public));
}

static inline void
fingerprint_one_key(const struct sshkey *public, const char *comment) {
	fingerprint_format(public, comment, print_fingerprint_one_key);
}


static void
type_bits_valid(int type, const char *name, u_int32_t *bitsp)
{
	if (type == KEY_UNSPEC)
		fatal("unknown key type %s", key_type_name);
	if (*bitsp == 0) {
#ifdef WITH_OPENSSL
		int nid;

		switch(type) {
	#ifdef WITH_DSA
		case KEY_DSA:
			*bitsp = DEFAULT_BITS_DSA;
			break;
	#endif
		case KEY_ECDSA:
			if (name != NULL &&
			    (nid = sshkey_ecdsa_nid_from_name(name)) > 0)
				*bitsp = sshkey_curve_nid_to_bits(nid);
			if (*bitsp == 0)
				*bitsp = DEFAULT_BITS_ECDSA;
			break;
		case KEY_RSA:
			*bitsp = DEFAULT_BITS;
			break;
		}
#endif
	}
#ifdef WITH_OPENSSL
	switch (type) {
#ifdef WITH_DSA
	case KEY_DSA:
		if (*bitsp != SSH_DSA_BITS)
			fatal("Invalid DSA key length: must be %d bits", SSH_DSA_BITS);
		break;
#endif
	case KEY_RSA:
		if (*bitsp < SSH_RSA_MINIMUM_MODULUS_SIZE)
			fatal("Invalid RSA key length: minimum is %d bits",
			    SSH_RSA_MINIMUM_MODULUS_SIZE);
		else if (*bitsp > OPENSSL_RSA_MAX_MODULUS_BITS)
			fatal("Invalid RSA key length: maximum is %d bits",
			    OPENSSL_RSA_MAX_MODULUS_BITS);
		break;
	case KEY_ECDSA:
		if (sshkey_ecdsa_bits_to_nid(*bitsp) == -1)
#ifdef OPENSSL_HAS_NISTP521
			fatal("Invalid ECDSA key length: valid lengths are "
			    "256, 384 or 521 bits");
#else
			fatal("Invalid ECDSA key length: valid lengths are "
			    "256 or 384 bits");
#endif
	}
#endif
}

/*
 * Checks whether a file exists and, if so, asks the user whether they wish
 * to overwrite it.
 * Returns nonzero if the file does not already exist or if the user agrees to
 * overwrite, or zero otherwise.
 */
static int
confirm_overwrite(const char *filename)
{
	char yesno[3];
	struct stat st;

	if (stat(filename, &st) == -1)
		return 1;

	fprintf(stderr, "%s already exists.\n", filename);
	fprintf(stderr, "Overwrite (y/n)? :");
	fflush(stderr); /*non-buffered but on some systems ...*/

	if (fgets(yesno, sizeof(yesno), stdin) == NULL)
		return 0;

	return yesno[0] == 'y' || yesno[0] == 'Y';
}

static void
ask_filename(const struct passwd *pw, const char *prompt)
{
	char buf[1024];
	char *name = NULL;

	if (key_type_name == NULL)
		key_type_name = default_key_type_name();

	/* NOTE: keep block to minimise code differences */
	{
		switch (sshkey_type_from_shortname(key_type_name)) {
#ifdef WITH_DSA
		case KEY_DSA_CERT:
		case KEY_DSA:
			name = _PATH_SSH_CLIENT_ID_DSA;
			break;
#endif
#ifdef OPENSSL_HAS_ECC
		case KEY_ECDSA_CERT:
		case KEY_ECDSA:
			name = _PATH_SSH_CLIENT_ID_ECDSA;
			break;
#endif
		case KEY_RSA_CERT:
		case KEY_RSA:
			name = _PATH_SSH_CLIENT_ID_RSA;
			break;
		case KEY_ED25519:
		case KEY_ED25519_CERT:
			name = _PATH_SSH_CLIENT_ID_ED25519;
			break;
#ifdef WITH_XMSS
		case KEY_XMSS:
		case KEY_XMSS_CERT:
			name = _PATH_SSH_CLIENT_ID_XMSS;
			break;
#endif
		default:
			fatal("bad key type");
		}
	}
	snprintf(identity_file, sizeof(identity_file),
	    "%s/%s", pw->pw_dir, name);
	printf("%s (%s): ", prompt, identity_file);
	fflush(stdout);
	if (fgets(buf, sizeof(buf), stdin) == NULL)
		exit(1);
	buf[strcspn(buf, "\n")] = '\0';
	if (strcmp(buf, "") != 0)
		strlcpy(identity_file, buf, sizeof(identity_file));
	have_identity = 1;
}

static char* asc_new_passphrase(const char *path, u_int retry_num);

static char*
private_key_new_passphrase(const char *path, u_int retry_num)
{
	if (identity_new_passphrase)
		return xstrdup(identity_new_passphrase);

	return asc_new_passphrase(path, retry_num);
}

static char*
private_key_passphrase(const char *path)
{
	char *prompt, *ret;

	if (identity_passphrase)
		return xstrdup(identity_passphrase);

	xasprintf(&prompt, "Enter passphrase for \"%s\": ", path);
	ret = read_passphrase(prompt, RP_ALLOW_STDIN);
	free(prompt);
	return ret;
}

static int
Xstat(char *filename)
{
#ifdef USE_OPENSSL_ENGINE
	if (strncmp(filename, "engine:", 7) == 0) return 0;
#endif
#ifdef USE_OPENSSL_STORE2
	if (strncmp(filename, "store:", 6) == 0) return 0;
#endif
{	struct stat st;
	return stat(filename, &st);
}
}

static struct sshkey *
load_identity(const char *filename, char **commentp)
{
	struct sshkey *prv;
	int r;

	/* NOTE: engine or store based keys use method provided
	 * by crypto-library to get passphrase if needed.
	 */
	r = sshkey_load_private(filename, "", &prv, commentp);
	if (r == 0) return prv;

	if (r != SSH_ERR_KEY_WRONG_PASSPHRASE)
		fatal_r(r, "Load key \"%s\"", filename);

{	/* try passphrase only for file based keys */
	char *pass = private_key_passphrase(filename);;
	r = sshkey_load_private(filename, pass, &prv, commentp);
	freezero(pass, strlen(pass));
}
	if (r != 0)
		fatal_r(r, "Load key \"%s\"", filename);

	return prv;
}

#define SSH_COM_PUBLIC_BEGIN		"---- BEGIN SSH2 PUBLIC KEY ----"
#define SSH_COM_PUBLIC_END		"---- END SSH2 PUBLIC KEY ----"
#define SSH_COM_PRIVATE_BEGIN		"---- BEGIN SSH2 ENCRYPTED PRIVATE KEY ----"
#define	SSH_COM_PRIVATE_KEY_MAGIC	0x3f6ff9eb

#ifdef WITH_OPENSSL
static void
do_convert_to_ssh2(const struct passwd *pw, struct sshkey *k)
{
	struct sshbuf *b;
	char comment[61], *b64;
	int r;

	if ((b = sshbuf_new()) == NULL)
		fatal_f("sshbuf_new failed");
	if ((r = sshkey_putb(k, b)) != 0)
		fatal_fr(r, "put key");
	if ((b64 = sshbuf_dtob64_string(b, 1)) == NULL)
		fatal_f("sshbuf_dtob64_string failed");

	/* Comment + surrounds must fit into 72 chars (RFC 4716 sec 3.3) */
	snprintf(comment, sizeof(comment),
	    "%u-bit %s, converted by %s@%s from " PACKAGE_NAME,
	    sshkey_size(k), sshkey_type(k),
	    pw->pw_name, hostname);

	sshkey_free(k);
	sshbuf_free(b);

	fprintf(stdout, "%s\n", SSH_COM_PUBLIC_BEGIN);
	fprintf(stdout, "Comment: \"%s\"\n%s", comment, b64);
	fprintf(stdout, "%s\n", SSH_COM_PUBLIC_END);
	free(b64);
	exit(0);
}


/* defined in sshkey-crypto.c but used only localy here */
extern int
sshkey_public_to_fp(struct sshkey *key, FILE *fp, int format);

static void
do_convert_to(const struct passwd *pw)
{
	struct sshkey *k;
	struct stat st;
	int r;

	if (!have_identity)
		ask_filename(pw, "Enter file in which the key is");
	if (stat(identity_file, &st) == -1)
		fatal("%s: %s: %s", __progname, identity_file, strerror(errno));
	if ((r = sshkey_load_public(identity_file, &k, NULL)) != 0)
		k = load_identity(identity_file, NULL);
	switch (convert_format) {
	case FMT_RFC4716:
		do_convert_to_ssh2(pw, k);
		break;
	case FMT_PKCS8:
		if (sshkey_public_to_fp(k, stdout, SSHKEY_PRIVATE_PKCS8) != 0)
			fatal_f("unsupported key type %s", sshkey_type(k));
		break;
	case FMT_PEM:
		if (sshkey_public_to_fp(k, stdout, SSHKEY_PRIVATE_PEM) != 0)
			fatal_f("unsupported key type %s", sshkey_type(k));
		break;
	default:
		fatal_f("unknown key format %d", convert_format);
	}
	exit(0);
}


/* defined in sshkey-crypto.c but used only localy here */
extern int
sshbuf_read_custom_rsa(struct sshbuf *buf, struct sshkey *key);
extern int
sshbuf_read_custom_dsa(struct sshbuf *buf, struct sshkey *key);

static struct sshkey *
do_convert_private_ssh2(struct sshbuf *b)
{
	struct sshkey *key = NULL;
	const char *alg = NULL;
	u_char *sig = NULL, data[] = "abcde12345";
	int r, rlen, ktype;
	u_int32_t magic;
	size_t slen;

	if ((r = sshbuf_get_u32(b, &magic)) != 0)
		fatal_fr(r, "parse magic");

	if (magic != SSH_COM_PRIVATE_KEY_MAGIC) {
		error("bad magic 0x%x != 0x%x", magic,
		    SSH_COM_PRIVATE_KEY_MAGIC);
		return NULL;
	}

{	char *type, *cipher;
	u_int32_t i1, i2, i3, i4;

	if ((r = sshbuf_get_u32(b, &i1)) != 0 ||
	    (r = sshbuf_get_cstring(b, &type, NULL)) != 0 ||
	    (r = sshbuf_get_cstring(b, &cipher, NULL)) != 0 ||
	    (r = sshbuf_get_u32(b, &i2)) != 0 ||
	    (r = sshbuf_get_u32(b, &i3)) != 0 ||
	    (r = sshbuf_get_u32(b, &i4)) != 0)
		fatal_fr(r, "parse");
	debug("ignore (%d %d %d %d)", i1, i2, i3, i4);
	if (strcmp(cipher, "none") != 0) {
		error("unsupported cipher %s", cipher);
		free(cipher);
		free(type);
		return NULL;
	}
	free(cipher);

	if (strstr(type, "rsa")) {
		ktype = KEY_RSA;
#ifdef WITH_DSA
	} else if (strstr(type, "dsa")) {
		ktype = KEY_DSA;
#endif
	} else {
		free(type);
		return NULL;
	}
	free(type);
}

	key = sshkey_new(KEY_UNSPEC);
	if (key == NULL)
		fatal("sshkey_new failed");
	switch (ktype) {
#ifdef WITH_DSA
	case KEY_DSA:
		r = sshbuf_read_custom_dsa(b, key);
		if (r != 0)
			fatal_fr(r, "custom dsa failed");
		break;
#endif
	case KEY_RSA:
		r = sshbuf_read_custom_rsa(b, key);
		if (r != 0)
			fatal_fr(r, "custom rsa failed");
	#ifdef HAVE_EVP_SHA256
		alg = "rsa-sha2-256";
	#endif
		break;
	}
	rlen = sshbuf_len(b);
	if (rlen != 0)
		error_f("remaining bytes in key blob %d", rlen);

	/* try the key */
{	ssh_compat ctx_compat = { 0, 0 };
	ssh_sign_ctx sctx = { alg, key, &ctx_compat, NULL, NULL };
	ssh_verify_ctx vctx = { alg, key, &ctx_compat };

	if ((r = sshkey_sign(&sctx, &sig, &slen, data, sizeof(data))) != 0)
		error_fr(r, "signing with converted key failed");
	else if ((r = sshkey_verify(&vctx, sig, slen, data, sizeof(data))) != 0)
		error_fr(r, "verification with converted key failed");
}
	if (r != 0) {
		sshkey_free(key);
		free(sig);
		return NULL;
	}
	free(sig);
	return key;
}

static int
get_line(FILE *fp, char *line, size_t len)
{
	int c;
	size_t pos = 0;

	line[0] = '\0';
	while ((c = fgetc(fp)) != EOF) {
		if (pos >= len - 1)
			fatal("input line too long.");
		switch (c) {
		case '\r':
			c = fgetc(fp);
			if (c != EOF && c != '\n' && ungetc(c, fp) == EOF)
				fatal("unget: %s", strerror(errno));
			return pos;
		case '\n':
			return pos;
		}
		line[pos++] = c;
		line[pos] = '\0';
	}
	/* We reached EOF */
	return -1;
}

static void
do_convert_from_ssh2(struct sshkey **k, int *private)
{
	int r, blen, escaped = 0;
	u_int len;
	char line[1024];
	struct sshbuf *buf;
	char encoded[8096];
	FILE *fp;

	if ((buf = sshbuf_new()) == NULL)
		fatal("sshbuf_new failed");
	if ((fp = fopen(identity_file, "r")) == NULL)
		fatal("%s: %s: %s", __progname, identity_file, strerror(errno));
	encoded[0] = '\0';
	while ((blen = get_line(fp, line, sizeof(line))) != -1) {
		if (blen > 0 && line[blen - 1] == '\\')
			escaped++;
		if (strncmp(line, "----", 4) == 0 ||
		    strstr(line, ": ") != NULL) {
			if (strstr(line, SSH_COM_PRIVATE_BEGIN) != NULL)
				*private = 1;
			if (strstr(line, " END ") != NULL) {
				break;
			}
			/* fprintf(stderr, "ignore: %s", line); */
			continue;
		}
		if (escaped) {
			escaped--;
			/* fprintf(stderr, "escaped: %s", line); */
			continue;
		}
		strlcat(encoded, line, sizeof(encoded));
	}
	len = strlen(encoded);
	if (((len % 4) == 3) &&
	    (encoded[len-1] == '=') &&
	    (encoded[len-2] == '=') &&
	    (encoded[len-3] == '='))
		encoded[len-3] = '\0';
	if ((r = sshbuf_b64tod(buf, encoded)) != 0)
		fatal_fr(r, "base64 decode");
	if (*private) {
		if ((*k = do_convert_private_ssh2(buf)) == NULL)
			fatal_f("private key conversion failed");
	} else if ((r = sshkey_fromb(buf, k)) != 0)
		fatal_fr(r, "parse key");
	sshbuf_free(buf);
	fclose(fp);
}

/* defined in sshkey-crypto.c but used only localy here */
extern int
sshkey_public_from_fp(FILE *fp, int format, struct sshkey **key);

static void
do_convert_from_file(struct sshkey **k, int format)
{
	int r;

{	FILE *fp = fopen(identity_file, "r");
	if (fp == NULL)
		fatal("%s: %s: %s", __progname, identity_file, strerror(errno));
	r = sshkey_public_from_fp(fp, format, k);
	fclose(fp);
}
	if (r == 0) return;

	fatal_r(r, "%s: unrecognised public key", identity_file);
}

static void
do_convert_from(const struct passwd *pw)
{
	struct sshkey *k = NULL;
	int r, private = 0, ok = 0;
	struct stat st;

	if (!have_identity)
		ask_filename(pw, "Enter file in which the key is");
	if (stat(identity_file, &st) == -1)
		fatal("%s: %s: %s", __progname, identity_file, strerror(errno));

	switch (convert_format) {
	case FMT_RFC4716:
		do_convert_from_ssh2(&k, &private);
		break;
	case FMT_PKCS8:
		do_convert_from_file(&k, SSHKEY_PRIVATE_PKCS8);
		break;
	case FMT_PEM:
		do_convert_from_file(&k, SSHKEY_PRIVATE_PEM);
		break;
	default:
		fatal_f("unknown key format %d", convert_format);
	}
	if (k == NULL) exit(1);

	if (!private) {
		if ((r = sshkey_write(k, stdout)) == 0)
			ok = 1;
		if (ok)
			fprintf(stdout, "\n");
	} else {
		BIO *out = BIO_new_fp(stdout, BIO_NOCLOSE);
		if (out == NULL) goto done;
#ifdef VMS
	{
		BIO *tmpbio = BIO_new(BIO_f_linebuffer());
		out = BIO_push(tmpbio, out);
	}
#endif
		r = sshkey_private_to_bio(k, out, "", private_key_format);
		if (r == 0)
			ok = 1;
		else if (r == SSH_ERR_INVALID_ARGUMENT)
			fatal_f("unsupported key type %s", sshkey_type(k));
		BIO_free_all(out);
	}

done:
	if (!ok)
		fatal("key write failed");
	sshkey_free(k);
	exit(0);
}
#endif

static void
do_print_public(const struct passwd *pw)
{
	struct sshkey *prv;
	int r;
	char *comment = NULL;

	if (!have_identity)
		ask_filename(pw, "Enter file in which the key is");
	if (Xstat(identity_file) == -1)
		fatal("%s: %s", identity_file, strerror(errno));

	prv = load_identity(identity_file, &comment);
	if ((r = sshkey_write(prv, stdout)) != 0)
		fatal_fr(r, "write key");
	if (comment != NULL && *comment != '\0')
		fprintf(stdout, " %s", comment);
	fprintf(stdout, "\n");

	sshkey_free(prv);
	free(comment);
	exit(0);
}

static void
do_download(void)
{
#ifdef ENABLE_PKCS11
	struct sshkey **keys;
	char **comments;
	int i, nkeys;

	pkcs11_init(1);
	nkeys = pkcs11_add_provider(pkcs11provider, NULL, &keys, &comments);
	if (nkeys <= 0)
		fatal("cannot read public key from pkcs11");
	for (i = 0; i < nkeys; i++) {
		if (print_fingerprint) {
			fingerprint_one_key(keys[i], "PKCS11 key");
		} else {
			(void) sshkey_write(keys[i], stdout); /* XXX check */
			/* let exclude "comment" for X.509 certificate
			 * as this is doubling information
			 */
			if (!sshkey_is_x509(keys[i]) && *(comments[i]) != '\0')
				fprintf(stdout, " %s", comments[i]);
			fprintf(stdout, "\n");
		}
		free(comments[i]);
		sshkey_free(keys[i]);
	}
	free(comments);
	free(keys);
	pkcs11_terminate();
	exit(0);
#else
	fatal("no pkcs11 support");
#endif /* ENABLE_PKCS11 */
}

static struct sshkey *
try_read_key(char **cpp)
{
	struct sshkey *ret;
	int r;

	if ((ret = sshkey_new(KEY_UNSPEC)) == NULL)
		fatal("sshkey_new failed");
	if ((r = sshkey_read(ret, cpp)) == 0)
		return ret;
	/* Not a key */
	sshkey_free(ret);
	return NULL;
}

static void
fingerprint_format(const struct sshkey *public, const char *comment,
    fingerprint_format_f format_f, ...)
{
	char *fp;
	enum sshkey_fp_rep rep;
	int fptype;

	fptype = print_bubblebabble ? SSH_DIGEST_SHA1 : fingerprint_hash;
	rep =    print_bubblebabble ? SSH_FP_BUBBLEBABBLE : SSH_FP_DEFAULT;

	fp = sshkey_fingerprint(public, fptype, rep);
	if (fp == NULL) {
		if (sshkey_is_x509(public))
			verbose("Key only with X.509 certificate distinguished name");
		else
			error("Cannot obtain key fingerprint");
		return;
	}
{
	va_list ap;
	va_start(ap, format_f);
	format_f(public, comment, fp, ap);
	va_end(ap);
}
	free(fp);

	if (get_log_level() < SYSLOG_LEVEL_VERBOSE)
		return;

	fp = sshkey_fingerprint(public, fingerprint_hash, SSH_FP_RANDOMART);
	if (fp == NULL) {
		error("Cannot obtain key random-art");
		return;
	}
	printf("%s\n", fp);
	free(fp);
}

static void
fingerprint_private(const char *path)
{
	struct stat st;
	char *comment = NULL;
	struct sshkey *pubkey = NULL, *privkey = NULL;
	int r;

	if (stat(identity_file, &st) == -1)
		fatal("%s: %s", path, strerror(errno));
	if ((r = sshkey_load_public(path, &pubkey, &comment)) != 0)
		debug_r(r, "load public \"%s\"", path);
	if (pubkey == NULL || comment == NULL || *comment == '\0') {
		free(comment);
		if ((r = sshkey_load_private(path, NULL,
		    &privkey, &comment)) != 0)
			debug_r(r, "load private \"%s\"", path);
	}
	if (pubkey == NULL && privkey == NULL)
		fatal("%s is not a key file.", path);

	fingerprint_one_key(pubkey == NULL ? privkey : pubkey, comment);
	sshkey_free(pubkey);
	sshkey_free(privkey);
	free(comment);
}

static void
do_fingerprint(const struct passwd *pw)
{
	FILE *f;
	struct sshkey *public = NULL;
	char *cp, *ep, *line = NULL;
	size_t linesize = 0;
	int i, invalid = 1;
	const char *path;
	u_long lnum = 0;

	if (!have_identity)
		ask_filename(pw, "Enter file in which the key is");
	path = identity_file;

	if (strcmp(identity_file, "-") == 0) {
		f = stdin;
		path = "(stdin)";
	} else if ((f = fopen(path, "r")) == NULL)
		fatal("%s: %s: %s", __progname, path, strerror(errno));

	while (getline(&line, &linesize, f) != -1) {
		char *comment = NULL;
		lnum++;
		cp = line;
		cp[strcspn(cp, "\r\n")] = '\0';
		/* Trim leading space and comments */
		cp = line + strspn(line, " \t");
		if (*cp == '#' || *cp == '\0')
			continue;

		/*
		 * Input may be plain keys, private keys, authorized_keys
		 * or known_hosts.
		 */

		/*
		 * Try private keys first. Assume a key is private if
		 * "SSH PRIVATE KEY" appears on the first line and we're
		 * not reading from stdin (XXX support private keys on stdin).
		 */
		if (lnum == 1 && strcmp(identity_file, "-") != 0 &&
		    strstr(cp, "PRIVATE KEY") != NULL) {
			free(line);
			fclose(f);
			fingerprint_private(path);
			exit(0);
		}

		/*
		 * If it's not a private key, then this must be prepared to
		 * accept a public key prefixed with a hostname or options.
		 * Try a bare key first, otherwise skip the leading stuff.
		 */
		if ((public = try_read_key(&cp)) == NULL) {
			i = strtol(cp, &ep, 10);
			if (i == 0 || ep == NULL ||
			    (*ep != ' ' && *ep != '\t')) {
				int quoted = 0;

				comment = cp;
				for (; *cp && (quoted || (*cp != ' ' &&
				    *cp != '\t')); cp++) {
					if (*cp == '\\' && cp[1] == '"')
						cp++;	/* Skip both */
					else if (*cp == '"')
						quoted = !quoted;
				}
				if (!*cp)
					continue;
				*cp++ = '\0';
			}
		}
		/* Retry after parsing leading hostname/key options */
		if (public == NULL && (public = try_read_key(&cp)) == NULL) {
			debug("%s:%lu: not a public key", path, lnum);
			continue;
		}

		/* Find trailing comment, if any */
		for (; *cp == ' ' || *cp == '\t'; cp++)
			;
		if (*cp != '\0' && *cp != '#')
			comment = cp;

		fingerprint_one_key(public, comment);
		sshkey_free(public);
		invalid = 0; /* One good key in the file is sufficient */
	}
	fclose(f);
	free(line);

	if (invalid)
		fatal("%s is not a public key file.", path);
	exit(0);
}

static void
do_gen_all_hostkeys(const struct passwd *pw)
{
	struct {
		char *key_type;
		char *key_type_display;
		char *path;
	} key_types[] = {
#ifdef WITH_OPENSSL
		{ "rsa", "RSA" ,_PATH_HOST_RSA_KEY_FILE },
#ifdef OPENSSL_HAS_ECC
		{ "ecdsa", "ECDSA",_PATH_HOST_ECDSA_KEY_FILE },
#endif /* OPENSSL_HAS_ECC */
#endif /* WITH_OPENSSL */
		{ "ed25519", "ED25519",_PATH_HOST_ED25519_KEY_FILE },
#ifdef WITH_XMSS
		{ "xmss", "XMSS",_PATH_HOST_XMSS_KEY_FILE },
#endif /* WITH_XMSS */
		{ NULL, NULL, NULL }
	};

	int first = 0;
	struct stat st;
	struct sshkey *private, *public;
	char comment[1024], *prv_tmp, *pub_tmp, *prv_file, *pub_file;
	int i, type, fd, r;

	for (i = 0; key_types[i].key_type; i++) {
		const char *key_path = key_types[i].path;
	#if defined(__ANDROID__)
		char r_key_path[PATH_MAX];
	#endif
		public = private = NULL;
		prv_tmp = pub_tmp = prv_file = pub_file = NULL;

	#if defined(__ANDROID__)
		if (relocate_etcdir(key_path, r_key_path, sizeof(r_key_path)))
			key_path = r_key_path;
	#endif

		xasprintf(&prv_file, "%s%s", identity_file, key_path);

		/* Check whether private key exists and is not zero-length */
		if (stat(prv_file, &st) != -1) {
			if (st.st_size != 0)
				goto next;
		} else if (errno != ENOENT) {
			error("Could not stat %s: %s", key_path, strerror(errno));
			goto failnext;
		}

		/*
		 * Private key doesn't exist or is invalid; proceed with
		 * key generation.
		 */
		xasprintf(&prv_tmp, "%s%s.XXXXXXXXXX", identity_file, key_path);
		xasprintf(&pub_tmp, "%s%s.pub.XXXXXXXXXX", identity_file, key_path);
		xasprintf(&pub_file, "%s%s.pub", identity_file, key_path);

		if (first == 0) {
			first = 1;
			printf("%s: generating new host keys: ", __progname);
		}
		printf("%s ", key_types[i].key_type_display);
		fflush(stdout);
		type = sshkey_type_from_shortname(key_types[i].key_type);
		if ((fd = mkstemp(prv_tmp)) == -1) {
			error("Could not save your private key in %s: %s",
			    prv_tmp, strerror(errno));
			goto failnext;
		}
		(void)close(fd); /* just using mkstemp() to reserve a name */
	{	u_int32_t bits = 0;
		type_bits_valid(type, NULL, &bits);
		if ((r = sshkey_generate(type, bits, &private)) != 0) {
			error_r(r, "sshkey_generate failed");
			goto failnext;
		}
	}
		if ((r = sshkey_from_private(private, &public)) != 0)
			fatal_fr(r, "sshkey_from_private");
		snprintf(comment, sizeof comment, "%s@%s", pw->pw_name,
		    hostname);
		if ((r = sshkey_save_private(private, prv_tmp, "",
		    comment, private_key_format, openssh_format_cipher,
		    rounds)) != 0) {
			error_r(r, "Saving key \"%s\" failed", prv_tmp);
			goto failnext;
		}
		if ((fd = mkstemp(pub_tmp)) == -1) {
			error("Could not save your public key in %s: %s",
			    pub_tmp, strerror(errno));
			goto failnext;
		}
		(void)close(fd); /* just using mkstemp() to reserve a name */
		if ((r = sshkey_save_public(public, pub_tmp, comment)) != 0) {
			error_r(r, "Unable to save public key to %s",
			    identity_file);
			goto failnext;
		}

		/* Rename temporary files to their permanent locations. */
		if (rename(pub_tmp, pub_file) == -1) {
			error("Unable to move %s into position: %s",
			    pub_file, strerror(errno));
			goto failnext;
		}
		if (rename(prv_tmp, prv_file) == -1) {
			error("Unable to move %s into position: %s",
			    key_path, strerror(errno));
 failnext:
			first = 0;
			goto next;
		}
 next:
		sshkey_free(private);
		sshkey_free(public);
		free(prv_tmp);
		free(pub_tmp);
		free(prv_file);
		free(pub_file);
	}
	if (first != 0)
		printf("\n");
}

struct known_hosts_ctx {
	const char *host;	/* Hostname searched for in find/delete case */
	FILE *out;		/* Output file, stdout for find_hosts case */
	int has_unhashed;	/* When hashing, original had unhashed hosts */
	int found_key;		/* For find/delete, host was found */
	int invalid;		/* File contained invalid items; don't delete */
	int hash_hosts;		/* Hash hostnames as we go */
	int find_host;		/* Search for specific hostname */
	int delete_host;	/* Delete host from known_hosts */
};

static int
known_hosts_hash(struct hostkey_foreach_line *l, void *_ctx)
{
	struct known_hosts_ctx *ctx = (struct known_hosts_ctx *)_ctx;
	char *hashed, *cp, *hosts, *ohosts;
	int has_wild = l->hosts && strcspn(l->hosts, "*?!") != strlen(l->hosts);
	int was_hashed = l->hosts && l->hosts[0] == HASH_DELIM;

	switch (l->status) {
	case HKF_STATUS_OK:
	case HKF_STATUS_MATCHED:
		/*
		 * Don't hash hosts already hashed, with wildcard
		 * characters or a CA/revocation marker.
		 */
		if (was_hashed || has_wild || l->marker != MRK_NONE) {
			fprintf(ctx->out, "%s\n", l->line);
			if (has_wild && !ctx->find_host) {
				logit("%s:%lu: ignoring host name "
				    "with wildcard: %.64s", l->path,
				    l->linenum, l->hosts);
			}
			return 0;
		}
		/*
		 * Split any comma-separated hostnames from the host list,
		 * hash and store separately.
		 */
		ohosts = hosts = xstrdup(l->hosts);
		while ((cp = strsep(&hosts, ",")) != NULL && *cp != '\0') {
			lowercase(cp);
			if ((hashed = host_hash(cp, NULL, 0)) == NULL)
				fatal("hash_host failed");
			fprintf(ctx->out, "%s %s\n", hashed, l->rawkey);
			free(hashed);
			ctx->has_unhashed = 1;
		}
		free(ohosts);
		return 0;
	case HKF_STATUS_INVALID:
		/* Retain invalid lines, but mark file as invalid. */
		ctx->invalid = 1;
		logit("%s:%lu: invalid line", l->path, l->linenum);
		/* FALLTHROUGH */
	default:
		fprintf(ctx->out, "%s\n", l->line);
		return 0;
	}
	/* NOTREACHED */
	return -1;
}

static void
print_fingerprint_known_hosts(
    const struct sshkey *public, const char *comment, const char *fp,
    va_list ap)
{
	char *host;
	host = va_arg(ap, char*);
	mprintf("%s %s %s%s%s\n", host,
	    sshkey_type(public), fp, *comment ? " ": "", comment);
}

static int
known_hosts_find_delete(struct hostkey_foreach_line *l, void *_ctx)
{
	struct known_hosts_ctx *ctx = (struct known_hosts_ctx *)_ctx;

	if (l->status == HKF_STATUS_MATCHED) {
		if (ctx->delete_host) {
			if (l->marker != MRK_NONE) {
				/* Don't remove CA and revocation lines */
				fprintf(ctx->out, "%s\n", l->line);
			} else {
				/*
				 * Hostname matches and has no CA/revoke
				 * marker, delete it by *not* writing the
				 * line to ctx->out.
				 */
				ctx->found_key = 1;
				if (!quiet)
					printf("# Host %s found: line %lu\n",
					    ctx->host, l->linenum);
			}
			return 0;
		} else if (ctx->find_host) {
			ctx->found_key = 1;
			if (!quiet) {
				printf("# Host %s found: line %lu %s\n",
				    ctx->host,
				    l->linenum, l->marker == MRK_CA ? "CA" :
				    (l->marker == MRK_REVOKE ? "REVOKED" : ""));
			}
			if (ctx->hash_hosts)
				known_hosts_hash(l, ctx);
			else if (print_fingerprint) {
				fingerprint_format(l->key, l->comment,
				    print_fingerprint_known_hosts, ctx->host);
			} else
				fprintf(ctx->out, "%s\n", l->line);
			return 0;
		}
	} else if (ctx->delete_host) {
		/* Retain non-matching hosts when deleting */
		if (l->status == HKF_STATUS_INVALID) {
			ctx->invalid = 1;
			logit("%s:%lu: invalid line", l->path, l->linenum);
		}
		fprintf(ctx->out, "%s\n", l->line);
	}
	return 0;
}

static void
do_known_hosts(const struct passwd *pw, const char *name, int find_host,
    int delete_host, int hash_hosts)
{
	char *cp, tmp[PATH_MAX], old[PATH_MAX];
	int r, fd, oerrno, inplace = 0;
	struct known_hosts_ctx ctx;
	u_int foreach_options;
	struct stat sb;

	if (!have_identity) {
		cp = tilde_expand_filename(_PATH_SSH_USER_HOSTFILE, pw->pw_uid);
		if (strlcpy(identity_file, cp, sizeof(identity_file)) >=
		    sizeof(identity_file))
			fatal("Specified known hosts path too long");
		free(cp);
		have_identity = 1;
	}
	if (stat(identity_file, &sb) != 0)
		fatal("Cannot stat %s: %s", identity_file, strerror(errno));

	memset(&ctx, 0, sizeof(ctx));
	ctx.out = stdout;
	ctx.host = name;
	ctx.hash_hosts = hash_hosts;
	ctx.find_host = find_host;
	ctx.delete_host = delete_host;

	/*
	 * Find hosts goes to stdout, hash and deletions happen in-place
	 * A corner case is ssh-keygen -HF foo, which should go to stdout
	 */
	if (!find_host && (hash_hosts || delete_host)) {
		if (strlcpy(tmp, identity_file, sizeof(tmp)) >= sizeof(tmp) ||
		    strlcat(tmp, ".XXXXXXXXXX", sizeof(tmp)) >= sizeof(tmp) ||
		    strlcpy(old, identity_file, sizeof(old)) >= sizeof(old) ||
		    strlcat(old, ".old", sizeof(old)) >= sizeof(old))
			fatal("known_hosts path too long");
		umask(077);
		if ((fd = mkstemp(tmp)) == -1)
			fatal("mkstemp: %s", strerror(errno));
		if ((ctx.out = fdopen(fd, "w")) == NULL) {
			oerrno = errno;
			unlink(tmp);
			fatal("fdopen: %s", strerror(oerrno));
		}
		(void)fchmod(fd, sb.st_mode & 0644);
		inplace = 1;
	}
	/* XXX support identity_file == "-" for stdin */
	foreach_options = find_host ? HKF_WANT_MATCH : 0;
	foreach_options |= print_fingerprint ? HKF_WANT_PARSE_KEY : 0;
{	hostkeys_foreach_fn *foreach_callback = (find_host || !hash_hosts)
	    ? known_hosts_find_delete
	    : known_hosts_hash;
	if ((r = hostkeys_foreach(identity_file, foreach_callback, &ctx,
	    name, NULL, foreach_options, 0)) != 0) {
		if (inplace)
			unlink(tmp);
		fatal_fr(r, "hostkeys_foreach");
	}
}

	if (inplace)
		fclose(ctx.out);

	if (ctx.invalid) {
		error("%s is not a valid known_hosts file.", identity_file);
		if (inplace) {
			error("Not replacing existing known_hosts "
			    "file because of errors");
			unlink(tmp);
		}
		exit(1);
	} else if (delete_host && !ctx.found_key) {
		logit("Host %s not found in %s", name, identity_file);
		if (inplace)
			unlink(tmp);
	} else if (inplace) {
		/* Backup existing file */
		if (unlink(old) == -1 && errno != ENOENT)
			fatal("unlink %.100s: %s", old, strerror(errno));
		if (xrename(identity_file, old) == -1)
			fatal("xrename %.100s to %.100s: %s", identity_file, old,
			    strerror(errno));
		/* Move new one into place */
		if (rename(tmp, identity_file) == -1) {
			error("rename\"%s\" to \"%s\": %s", tmp, identity_file,
			    strerror(errno));
			unlink(tmp);
			unlink(old);
			exit(1);
		}

		printf("%s updated.\n", identity_file);
		printf("Original contents retained as %s\n", old);
		if (ctx.has_unhashed) {
			logit("WARNING: %s contains unhashed entries", old);
			logit("Delete this file to ensure privacy "
			    "of hostnames");
		}
	}

	exit (find_host && !ctx.found_key);
}

/*
 * Perform changing a passphrase.  The argument is the passwd structure
 * for the current user.
 */
static void
do_change_passphrase(const struct passwd *pw)
{
	char *comment;
	char *old_passphrase, *passphrase;
	struct stat st;
	struct sshkey *private;
	int r;

	if (!have_identity)
		ask_filename(pw, "Enter file in which the key is");
	if (stat(identity_file, &st) == -1)
		fatal("%s: %s", identity_file, strerror(errno));
	/* Try to load the file with empty passphrase. */
	r = sshkey_load_private(identity_file, "", &private, &comment);
	if (r == SSH_ERR_KEY_WRONG_PASSPHRASE) {
		if (identity_passphrase)
			old_passphrase = xstrdup(identity_passphrase);
		else
			old_passphrase =
			    read_passphrase("Enter old passphrase: ",
			    RP_ALLOW_STDIN);
		r = sshkey_load_private(identity_file, old_passphrase,
		    &private, &comment);
		freezero(old_passphrase, strlen(old_passphrase));
		if (r != 0)
			goto badkey;
	} else if (r != 0) {
 badkey:
		fatal_r(r, "Failed to load key %s", identity_file);
	}
	if (comment)
		mprintf("Key has comment '%s'\n", comment);

	passphrase = private_key_new_passphrase(identity_file, 3);

	/* Save the file using the new passphrase. */
	r = sshkey_save_private(private, identity_file, passphrase,
	    comment, private_key_format, openssh_format_cipher, rounds);

	/* Destroy the passphrase and the copy of the key in memory. */
	freezero(passphrase, strlen(passphrase));
	sshkey_free(private);		 /* Destroys contents */
	free(comment);

	if (r != 0) {
		error_r(r, "Saving key \"%s\" failed", identity_file);
		exit(1);
	}
	printf("Your identification has been saved with the new passphrase.\n");
	exit(0);
}

/*
 * Print the SSHFP RR.
 */
static int
do_print_resource_record(char *fname, char *hname,
    int print_generic, char * const *opts, size_t nopts)
{
	struct sshkey *public;
	char *comment = NULL;
	struct stat st;
	int r, hash = -1;
	size_t i;

	for (i = 0; i < nopts; i++) {
		const char *p = strprefix(opts[i], "hashalg=", 1);
		if (p != NULL) {
			hash = ssh_digest_alg_by_name(p);
			if (hash == -1)
				fatal("Unsupported hash algorithm");
		} else {
			error("Invalid option \"%s\"", opts[i]);
			return SSH_ERR_INVALID_ARGUMENT;
		}
	}
	if (fname == NULL)
		fatal_f("no filename");
	if (stat(fname, &st) == -1) {
		if (errno == ENOENT)
			return 0;
		fatal("%s: %s", fname, strerror(errno));
	}
	if ((r = sshkey_load_public(fname, &public, &comment)) != 0)
		fatal_r(r, "Failed to read v2 public key from \"%s\"", fname);
	export_dns_rr(hname, public, stdout, print_generic, hash);
	sshkey_free(public);
	free(comment);
	return 1;
}

/*
 * Change the comment of a private key file.
 */
static void
do_change_comment(const struct passwd *pw, const char *identity_comment)
{
	char new_comment[1024], *comment, *passphrase;
	struct sshkey *private;
	struct sshkey *public;
	struct stat st;
	int r;

	if (!have_identity)
		ask_filename(pw, "Enter file in which the key is");
	if (stat(identity_file, &st) == -1)
		fatal("%s: %s", identity_file, strerror(errno));
	if ((r = sshkey_load_private(identity_file, "",
	    &private, &comment)) == 0)
		passphrase = xstrdup("");
	else if (r != SSH_ERR_KEY_WRONG_PASSPHRASE)
		fatal_r(r, "Cannot load private key \"%s\"", identity_file);
	else {
		passphrase = private_key_passphrase(identity_file);
		/* Try to load using the passphrase. */
		if ((r = sshkey_load_private(identity_file, passphrase,
		    &private, &comment)) != 0) {
			freezero(passphrase, strlen(passphrase));
			fatal_r(r, "Cannot load private key \"%s\"",
			    identity_file);
		}
	}

	if (private->type != KEY_ED25519 &&
#ifdef WITH_XMSS
	    private->type != KEY_XMSS &&
#endif
	    private_key_format != SSHKEY_PRIVATE_OPENSSH) {
		error("Comments are only supported for keys stored in "
		    "the OpenSSH proprietary format.");
		freezero(passphrase, strlen(passphrase));
		sshkey_free(private);
		exit(1);
	}
	if (comment)
		printf("Old comment: %s\n", comment);
	else
		printf("No existing comment\n");

	if (identity_comment) {
		strlcpy(new_comment, identity_comment, sizeof(new_comment));
	} else {
		printf("New comment: ");
		fflush(stdout);
		if (!fgets(new_comment, sizeof(new_comment), stdin)) {
			freezero(passphrase, strlen(passphrase));
			sshkey_free(private);
			exit(1);
		}
		new_comment[strcspn(new_comment, "\n")] = '\0';
	}
	if (comment != NULL && strcmp(comment, new_comment) == 0) {
		printf("No change to comment\n");
		free(passphrase);
		sshkey_free(private);
		free(comment);
		exit(0);
	}

	/* Save the file using the new passphrase. */
	if ((r = sshkey_save_private(private, identity_file, passphrase,
	    new_comment, private_key_format, openssh_format_cipher,
	    rounds)) != 0) {
		error_r(r, "Saving key \"%s\" failed", identity_file);
		freezero(passphrase, strlen(passphrase));
		sshkey_free(private);
		free(comment);
		exit(1);
	}
	freezero(passphrase, strlen(passphrase));
	if ((r = sshkey_from_private(private, &public)) != 0)
		fatal_fr(r, "sshkey_from_private");
	sshkey_free(private);

	strlcat(identity_file, ".pub", sizeof(identity_file));
	if ((r = sshkey_save_public(public, identity_file, new_comment)) != 0)
		fatal_r(r, "Unable to save public key to %s", identity_file);
	sshkey_free(public);
	free(comment);

	if (strlen(new_comment) > 0)
		printf("Comment '%s' applied\n", new_comment);
	else
		printf("Comment removed\n");

	exit(0);
}

static void
cert_ext_add(const char *key, const char *value, int iscrit)
{
	cert_ext = xreallocarray(cert_ext, ncert_ext + 1, sizeof(*cert_ext));
	cert_ext[ncert_ext].key = xstrdup(key);
	cert_ext[ncert_ext].val = value == NULL ? NULL : xstrdup(value);
	cert_ext[ncert_ext].crit = iscrit;
	ncert_ext++;
}

/* qsort(3) comparison function for certificate extensions */
static int
cert_ext_cmp(const void *_a, const void *_b)
{
	const struct cert_ext *a = (const struct cert_ext *)_a;
	const struct cert_ext *b = (const struct cert_ext *)_b;
	int r;

	if (a->crit != b->crit)
		return (a->crit < b->crit) ? -1 : 1;
	if ((r = strcmp(a->key, b->key)) != 0)
		return r;
	if (a->val == NULL) return -1;
	if (b->val == NULL) return 1;
	return strcmp(a->val, b->val);
}

#define OPTIONS_CRITICAL	1
#define OPTIONS_EXTENSIONS	2
static void
prepare_options_buf(struct sshbuf *c, int which)
{
	struct sshbuf *b;
	size_t i;

	if ((b = sshbuf_new()) == NULL)
		fatal_f("sshbuf_new failed");
	sshbuf_reset(c);
	for (i = 0; i < ncert_ext; i++) {
		const struct cert_ext *ext = &cert_ext[i];
		int r;

		if ((ext->crit && (which & OPTIONS_EXTENSIONS)) ||
		    (!ext->crit && (which & OPTIONS_CRITICAL)))
			continue;
		if (ext->val == NULL) {
			/* flag option */
			debug3_f("%s", ext->key);
			if ((r = sshbuf_put_cstring(c, ext->key)) != 0 ||
			    (r = sshbuf_put_string(c, NULL, 0)) != 0)
				fatal_fr(r, "prepare flag");
		} else {
			/* key/value option */
			debug3_f("%s=%s", ext->key, ext->val);
			sshbuf_reset(b);
			if ((r = sshbuf_put_cstring(c, ext->key)) != 0 ||
			    (r = sshbuf_put_cstring(b, ext->val)) != 0 ||
			    (r = sshbuf_put_stringb(c, b)) != 0)
				fatal_fr(r, "prepare k/v");
		}
	}
	sshbuf_free(b);
}

static void
finalise_cert_exts(void)
{
	/* critical options */
	if (certflags_command != NULL)
		cert_ext_add("force-command", certflags_command, 1);
	if (certflags_src_addr != NULL)
		cert_ext_add("source-address", certflags_src_addr, 1);
	/* extensions */
	if ((certflags_flags & CERTOPT_X_FWD) != 0)
		cert_ext_add("permit-X11-forwarding", NULL, 0);
	if ((certflags_flags & CERTOPT_AGENT_FWD) != 0)
		cert_ext_add("permit-agent-forwarding", NULL, 0);
	if ((certflags_flags & CERTOPT_PORT_FWD) != 0)
		cert_ext_add("permit-port-forwarding", NULL, 0);
	if ((certflags_flags & CERTOPT_PTY) != 0)
		cert_ext_add("permit-pty", NULL, 0);
	if ((certflags_flags & CERTOPT_USER_RC) != 0)
		cert_ext_add("permit-user-rc", NULL, 0);
	/* order lexically by key */
	if (ncert_ext > 0)
		qsort(cert_ext, ncert_ext, sizeof(*cert_ext), cert_ext_cmp);
}

static struct sshkey *
load_pkcs11_key(char *path)
{
#ifdef ENABLE_PKCS11
	struct sshkey **keys = NULL, *public, *private = NULL;
	int r, i, nkeys;

	if ((r = sshkey_load_public(path, &public, NULL)) != 0)
		fatal_r(r, "Couldn't load CA public key \"%s\"", path);

	nkeys = pkcs11_add_provider(pkcs11provider, identity_passphrase,
	    &keys, NULL);
	debug3_f("%d keys", nkeys);
	if (nkeys <= 0)
		fatal("cannot read public key from pkcs11");
	for (i = 0; i < nkeys; i++) {
		if (sshkey_equal_public(public, keys[i])) {
			private = keys[i];
			continue;
		}
		sshkey_free(keys[i]);
	}
	free(keys);
	sshkey_free(public);
	return private;
#else
	UNUSED(path);
	fatal("no pkcs11 support");
#endif /* ENABLE_PKCS11 */
}

/* Signer for sshkey_certify_custom that uses the agent */
static int
agent_signer(struct sshkey *key, u_char **sigp, size_t *lenp,
    const u_char *data, size_t datalen,
    const char *alg, const char *provider, const char *pin,
    u_int compat, void *v_sock)
{
	int *sock = (int *)v_sock;
	ssh_compat ctx_compat = { compat, 0 }; /* TODO-Xkey_sign compat */
	ssh_sign_ctx ctx = { alg, key, &ctx_compat, provider, pin };

	return Xssh_agent_sign(*sock, &ctx, sigp, lenp, data, datalen);
}

static void
do_ca_sign(const struct passwd *pw, const char *ca_key_path, int prefer_agent,
    unsigned long long cert_serial, int cert_serial_autoinc,
    int argc, char **argv)
{
	int r, i, found, agent_fd = -1;
	u_int n;
	struct sshkey *ca, *public;
	char valid[64], *otmp, *tmp, *cp, *out, *comment, **plist = NULL;
	struct ssh_identitylist *agent_ids;
	size_t j;

#ifdef ENABLE_PKCS11
	pkcs11_init(1);
#endif
	tmp = tilde_expand_filename(ca_key_path, pw->pw_uid);

	/* NOTE X.509 certificate support contradict with ca_sing
	 * => set pkcs11provider to  NULL to minimize incompatibility.
	 */
	pkcs11provider = NULL;

	if (pkcs11provider != NULL) {
		/* If a PKCS#11 token was specified then try to use it */
		if ((ca = load_pkcs11_key(tmp)) == NULL)
			fatal("No PKCS#11 key matching %s found", ca_key_path);
	} else if (prefer_agent) {
		/*
		 * Agent signature requested. Try to use agent after making
		 * sure the public key specified is actually present in the
		 * agent.
		 */
		if ((r = sshkey_load_public(tmp, &ca, NULL)) != 0)
			fatal_r(r, "Cannot load CA public key %s", tmp);
		if ((r = ssh_get_authentication_socket(&agent_fd)) != 0)
			fatal_r(r, "Cannot use public key for CA signature");
		if ((r = ssh_fetch_identitylist(agent_fd, &agent_ids)) != 0)
			fatal_r(r, "Retrieve agent key list");
		found = 0;
		for (j = 0; j < agent_ids->nkeys; j++) {
			if (sshkey_equal(ca, agent_ids->keys[j])) {
				found = 1;
				break;
			}
		}
		if (!found)
			fatal("CA key %s not found in agent", tmp);
		ssh_free_identitylist(agent_ids);
		ca->flags |= SSHKEY_FLAG_EXT;
	} else {
		/* CA key is assumed to be a private key on the filesystem */
		ca = load_identity(tmp, NULL);
	}
	free(tmp);

	if (key_type_name != NULL &&
	    sshkey_type_from_shortname(key_type_name) != ca->type)  {
		fatal("CA key type %s doesn't match specified %s",
		    sshkey_ssh_name(ca), key_type_name);
	}

	finalise_cert_exts();
	for (i = 0; i < argc; i++) {
		/* Split list of principals */
		n = 0;
		if (cert_principals != NULL) {
			otmp = tmp = xstrdup(cert_principals);
			plist = NULL;
			for (; (cp = strsep(&tmp, ",")) != NULL; n++) {
				plist = xreallocarray(plist, n + 1, sizeof(*plist));
				if (*(plist[n] = xstrdup(cp)) == '\0')
					fatal("Empty principal name");
			}
			free(otmp);
		}
		if (n > SSHKEY_CERT_MAX_PRINCIPALS)
			fatal("Too many certificate principals specified");

		tmp = tilde_expand_filename(argv[i], pw->pw_uid);
		if ((r = sshkey_load_public(tmp, &public, &comment)) != 0)
			fatal_fr(r, "load pubkey \"%s\"", tmp);
		if (sshkey_is_cert(public) || sshkey_is_x509(public))
			fatal_f("key \"%s\" type %s cannot be certified",
			    tmp, sshkey_type(public));

		/* Prepare certificate to sign */
		if ((r = sshkey_to_certified(public)) != 0)
			fatal_r(r, "Could not upgrade key %s to certificate", tmp);
		public->cert->type = cert_key_type;
		public->cert->serial = (u_int64_t)cert_serial;
		public->cert->key_id = xstrdup(cert_key_id);
		public->cert->nprincipals = n;
		public->cert->principals = plist;
		public->cert->valid_after = cert_valid_from;
		public->cert->valid_before = cert_valid_to;
		prepare_options_buf(public->cert->critical, OPTIONS_CRITICAL);
		prepare_options_buf(public->cert->extensions,
		    OPTIONS_EXTENSIONS);
		if ((r = sshkey_from_private(ca,
		    &public->cert->signature_key)) != 0)
			fatal_r(r, "sshkey_from_private (ca key)");

		if (agent_fd != -1 && (ca->flags & SSHKEY_FLAG_EXT) != 0) {
			r = sshkey_certify_custom(public, ca, key_type_name,
			    NULL, NULL, agent_signer, &agent_fd);
			if (r != 0)
				fatal_r(r, "Couldn't certify %s via agent", tmp);
		} else {
			r = sshkey_certify(public, ca, key_type_name,
			    NULL, NULL);
			if (r != 0)
				fatal_r(r, "Couldn't certify %s", tmp);
		}

		if ((cp = strrchr(tmp, '.')) != NULL && strcmp(cp, ".pub") == 0)
			*cp = '\0';
		xasprintf(&out, "%s-cert.pub", tmp);
		free(tmp);

		if ((r = sshkey_save_public(public, out, comment)) != 0) {
			fatal_r(r, "Unable to save certified key to %s",
			    identity_file);
		}

		if (!quiet) {
			sshkey_format_cert_validity(public->cert,
			    valid, sizeof(valid));
			logit("Signed %s key %s: id \"%s\" serial %llu%s%s "
			    "valid %s", sshkey_cert_type(public),
			    out, public->cert->key_id,
			    (unsigned long long)public->cert->serial,
			    cert_principals != NULL ? " for " : "",
			    cert_principals != NULL ? cert_principals : "",
			    valid);
		}

		sshkey_free(public);
		free(out);
		if (cert_serial_autoinc)
			cert_serial++;
	}
#ifdef ENABLE_PKCS11
	pkcs11_terminate();
#endif
	exit(0);
}

static u_int64_t
parse_relative_time(const char *s, time_t now)
{
	int64_t mul, secs;

	mul = *s == '-' ? -1 : 1;

	if ((secs = convtime(s + 1)) == -1)
		fatal("Invalid relative certificate time %s", s);
	if (mul == -1 && secs > now)
		fatal("Certificate time %s cannot be represented", s);
	return now + (u_int64_t)(secs * mul);
}

static void
parse_hex_u64(const char *s, uint64_t *up)
{
	char *ep;
	unsigned long long ull;

	errno = 0;
	ull = strtoull(s, &ep, 16);
	if (*s == '\0' || *ep != '\0')
		fatal("Invalid certificate time: not a number");
	if (errno == ERANGE && ull == ULONG_MAX)
		fatal_fr(SSH_ERR_SYSTEM_ERROR, "Invalid certificate time");
	*up = (uint64_t)ull;
}

static void
parse_cert_times(char *timespec)
{
	char *from, *to;
	time_t now = time(NULL);
	int64_t secs;

	/* +timespec relative to now */
	if (*timespec == '+' && strchr(timespec, ':') == NULL) {
		if ((secs = convtime(timespec + 1)) == -1)
			fatal("Invalid relative certificate life %s", timespec);
		cert_valid_to = now + secs;
		/*
		 * Backdate certificate one minute to avoid problems on hosts
		 * with poorly-synchronised clocks.
		 */
		cert_valid_from = ((now - 59)/ 60) * 60;
		return;
	}

	/*
	 * from:to, where
	 * from := [+-]timespec | YYYYMMDD | YYYYMMDDHHMMSS | 0x... | "always"
	 *   to := [+-]timespec | YYYYMMDD | YYYYMMDDHHMMSS | 0x... | "forever"
	 */
	from = xstrdup(timespec);
	to = strchr(from, ':');
	if (to == NULL || from == to || *(to + 1) == '\0')
		fatal("Invalid certificate life specification %s", timespec);
	*to++ = '\0';

	if (*from == '-' || *from == '+')
		cert_valid_from = parse_relative_time(from, now);
	else if (strcmp(from, "always") == 0)
		cert_valid_from = 0;
	else if (strncmp(from, "0x", 2) == 0)
		parse_hex_u64(from, &cert_valid_from);
	else if (parse_absolute_time(from, &cert_valid_from) != 0)
		fatal("Invalid from time \"%s\"", from);

	if (*to == '-' || *to == '+')
		cert_valid_to = parse_relative_time(to, now);
	else if (strcmp(to, "forever") == 0)
		cert_valid_to = ~(u_int64_t)0;
	else if (strncmp(to, "0x", 2) == 0)
		parse_hex_u64(to, &cert_valid_to);
	else if (parse_absolute_time(to, &cert_valid_to) != 0)
		fatal("Invalid to time \"%s\"", to);

	if (cert_valid_to <= cert_valid_from)
		fatal("Empty certificate validity interval");
	free(from);
}

static void
add_cert_option(char *opt)
{
	char *val, *cp;
	const char *p;
	int iscrit = 0;

	if (strcasecmp(opt, "clear") == 0)
		certflags_flags = 0;
	else if (strcasecmp(opt, "no-x11-forwarding") == 0)
		certflags_flags &= ~CERTOPT_X_FWD;
	else if (strcasecmp(opt, "permit-x11-forwarding") == 0)
		certflags_flags |= CERTOPT_X_FWD;
	else if (strcasecmp(opt, "no-agent-forwarding") == 0)
		certflags_flags &= ~CERTOPT_AGENT_FWD;
	else if (strcasecmp(opt, "permit-agent-forwarding") == 0)
		certflags_flags |= CERTOPT_AGENT_FWD;
	else if (strcasecmp(opt, "no-port-forwarding") == 0)
		certflags_flags &= ~CERTOPT_PORT_FWD;
	else if (strcasecmp(opt, "permit-port-forwarding") == 0)
		certflags_flags |= CERTOPT_PORT_FWD;
	else if (strcasecmp(opt, "no-pty") == 0)
		certflags_flags &= ~CERTOPT_PTY;
	else if (strcasecmp(opt, "permit-pty") == 0)
		certflags_flags |= CERTOPT_PTY;
	else if (strcasecmp(opt, "no-user-rc") == 0)
		certflags_flags &= ~CERTOPT_USER_RC;
	else if (strcasecmp(opt, "permit-user-rc") == 0)
		certflags_flags |= CERTOPT_USER_RC;
	else if ((p = strprefix(opt, "force-command=", 1)) != NULL) {
		if (*p == '\0')
			fatal("Empty force-command option");
		if (certflags_command != NULL)
			fatal("force-command already specified");
		certflags_command = xstrdup(p);
	} else if ((p = strprefix(opt, "source-address=", 1)) != NULL) {
		if (*p == '\0')
			fatal("Empty source-address option");
		if (certflags_src_addr != NULL)
			fatal("source-address already specified");
		if (addr_match_cidr_list(NULL, p) != 0)
			fatal("Invalid source-address list");
		certflags_src_addr = xstrdup(p);
	} else if (strprefix(opt, "extension:", 1) != NULL ||
		    (iscrit = (strprefix(opt, "critical:", 1) != NULL))) {
		val = xstrdup(strchr(opt, ':') + 1);
		if ((cp = strchr(val, '=')) != NULL)
			*cp++ = '\0';
		cert_ext_add(val, cp, iscrit);
		free(val);
	} else
		fatal("Unsupported certificate option \"%s\"", opt);
}

static void
show_options(struct sshbuf *optbuf, int in_critical)
{
	char *name, *arg;
	struct sshbuf *options, *option = NULL;
	int r;

	if ((options = sshbuf_fromb(optbuf)) == NULL)
		fatal_f("sshbuf_fromb failed");
	while (sshbuf_len(options) != 0) {
		sshbuf_free(option);
		option = NULL;
		if ((r = sshbuf_get_cstring(options, &name, NULL)) != 0 ||
		    (r = sshbuf_froms(options, &option)) != 0)
			fatal_fr(r, "parse option");
		printf("                %s", name);
		if (!in_critical &&
		    (strcmp(name, "permit-X11-forwarding") == 0 ||
		    strcmp(name, "permit-agent-forwarding") == 0 ||
		    strcmp(name, "permit-port-forwarding") == 0 ||
		    strcmp(name, "permit-pty") == 0 ||
		    strcmp(name, "permit-user-rc") == 0))
			printf("\n");
		else if (in_critical &&
		    (strcmp(name, "force-command") == 0 ||
		    strcmp(name, "source-address") == 0)) {
			if ((r = sshbuf_get_cstring(option, &arg, NULL)) != 0)
				fatal_fr(r, "parse critical");
			printf(" %s\n", arg);
			free(arg);
		} else if (sshbuf_len(option) > 0) {
			char *hex = sshbuf_dtob16(option);
			printf(" UNKNOWN OPTION: %s (len %zu)\n",
			    hex, sshbuf_len(option));
			sshbuf_reset(option);
			free(hex);
		} else
			printf(" UNKNOWN FLAG OPTION\n");
		free(name);
		if (sshbuf_len(option) != 0)
			fatal("Option corrupt: extra data at end");
	}
	sshbuf_free(option);
	sshbuf_free(options);
}

static void
print_cert(struct sshkey *key)
{
	char valid[64], *key_fp, *ca_fp;
	u_int i;

	key_fp = sshkey_fingerprint(key, fingerprint_hash, SSH_FP_DEFAULT);
	ca_fp = sshkey_fingerprint(key->cert->signature_key,
	    fingerprint_hash, SSH_FP_DEFAULT);
	if (key_fp == NULL || ca_fp == NULL)
		fatal_f("sshkey_fingerprint fail");
	sshkey_format_cert_validity(key->cert, valid, sizeof(valid));

	printf("        Type: %s %s certificate\n", sshkey_ssh_name(key),
	    sshkey_cert_type(key));
	printf("        Public key: %s %s\n", sshkey_type(key), key_fp);
	printf("        Signing CA: %s %s (using %s)\n",
	    sshkey_type(key->cert->signature_key), ca_fp,
	    key->cert->signature_type);
	printf("        Key ID: \"%s\"\n", key->cert->key_id);
	printf("        Serial: %llu\n", (unsigned long long)key->cert->serial);
	printf("        Valid: %s\n", valid);
	printf("        Principals: ");
	if (key->cert->nprincipals == 0)
		printf("(none)\n");
	else {
		for (i = 0; i < key->cert->nprincipals; i++)
			printf("\n                %s",
			    key->cert->principals[i]);
		printf("\n");
	}
	printf("        Critical Options: ");
	if (sshbuf_len(key->cert->critical) == 0)
		printf("(none)\n");
	else {
		printf("\n");
		show_options(key->cert->critical, 1);
	}
	printf("        Extensions: ");
	if (sshbuf_len(key->cert->extensions) == 0)
		printf("(none)\n");
	else {
		printf("\n");
		show_options(key->cert->extensions, 0);
	}
}

static void
do_show_cert(const struct passwd *pw)
{
	struct sshkey *key = NULL;
	struct stat st;
	int r, is_stdin = 0, ok = 0;
	FILE *f;
	char *cp, *line = NULL;
	const char *path;
	size_t linesize = 0;
	u_long lnum = 0;

	if (!have_identity)
		ask_filename(pw, "Enter file in which the key is");
	if (strcmp(identity_file, "-") != 0 && stat(identity_file, &st) == -1)
		fatal("%s: %s: %s", __progname, identity_file, strerror(errno));

	path = identity_file;
	if (strcmp(path, "-") == 0) {
		f = stdin;
		path = "(stdin)";
		is_stdin = 1;
	} else if ((f = fopen(identity_file, "r")) == NULL)
		fatal("fopen %s: %s", identity_file, strerror(errno));

	while (getline(&line, &linesize, f) != -1) {
		lnum++;
		sshkey_free(key);
		key = NULL;
		/* Trim leading space and comments */
		cp = line + strspn(line, " \t");
		if (*cp == '#' || *cp == '\0')
			continue;
		if ((key = sshkey_new(KEY_UNSPEC)) == NULL)
			fatal("sshkey_new");
		if ((r = sshkey_read(key, &cp)) != 0) {
			error_r(r, "%s:%lu: invalid key", path, lnum);
			continue;
		}
		if (!sshkey_is_cert(key)) {
			error("%s:%lu is not a certificate", path, lnum);
			continue;
		}
		ok = 1;
		if (!is_stdin && lnum == 1)
			printf("%s:\n", path);
		else
			printf("%s:%lu:\n", path, lnum);
		print_cert(key);
	}
	free(line);
	sshkey_free(key);
	fclose(f);
	exit(ok ? 0 : 1);
}

static void
load_krl(const char *path, struct ssh_krl **krlp)
{
	struct sshbuf *krlbuf;
	int r;

	if ((r = sshbuf_load_file(path, &krlbuf)) != 0)
		fatal_r(r, "Unable to load KRL %s", path);
	/* XXX check sigs */
	if ((r = ssh_krl_from_blob(krlbuf, krlp)) != 0 ||
	    *krlp == NULL)
		fatal_r(r, "Invalid KRL file %s", path);
	sshbuf_free(krlbuf);
}

static void
hash_to_blob(const char *cp, u_char **blobp, size_t *lenp,
    const char *file, u_long lnum)
{
	char *tmp;
	size_t tlen;
	struct sshbuf *b;
	int r;

	/*
	 * OpenSSH base64 hashes omit trailing '='
	 * characters; put them back for decode.
	 */
	tlen = strlen(cp);
	if (tlen >= SIZE_MAX - 4)
		fatal_f("hash too long: %zu bytes", tlen);
	tmp = xmalloc(tlen + 4 + 1);
	strlcpy(tmp, cp, tlen + 1);
	while ((tlen % 4) != 0) {
		tmp[tlen++] = '=';
		tmp[tlen] = '\0';
	}
	if ((b = sshbuf_new()) == NULL)
		fatal_f("sshbuf_new failed");
	if ((r = sshbuf_b64tod(b, tmp)) != 0)
		fatal_r(r, "%s:%lu: decode hash failed", file, lnum);
	free(tmp);
	*lenp = sshbuf_len(b);
	*blobp = xmalloc(*lenp);
	memcpy(*blobp, sshbuf_ptr(b), *lenp);
	sshbuf_free(b);
}

static inline int
strprefixtrim(char **s, const char *prefix, int ignorecase) {
	const char *p = strprefix(*s, prefix, ignorecase);
	if (p == NULL) return 0;

	p += strspn(p, " \t");
	*s = (char*)p;
	return 1;
}

static void
update_krl_from_file(const struct passwd *pw, const char *file, int wild_ca,
    const struct sshkey *ca, struct ssh_krl *krl)
{
	struct sshkey *key = NULL;
	u_long lnum = 0;
	char *path, *cp, *ep, *line = NULL;
	u_char *blob = NULL;
	size_t blen = 0, linesize = 0;
	unsigned long long serial, serial2;
	int i, was_explicit_key, was_sha1, was_sha256, was_hash, r;
	FILE *krl_spec;

	path = tilde_expand_filename(file, pw->pw_uid);
	if (strcmp(path, "-") == 0) {
		krl_spec = stdin;
		free(path);
		path = xstrdup("(standard input)");
	} else if ((krl_spec = fopen(path, "r")) == NULL)
		fatal("fopen %s: %s", path, strerror(errno));

	if (!quiet)
		printf("Revoking from %s\n", path);
	while (getline(&line, &linesize, krl_spec) != -1) {
		if (linesize >= INT_MAX) {
			fatal_f("%s contains unparsable line, len=%zu",
			    path, linesize);
		}
		lnum++;
		was_explicit_key = was_sha1 = was_sha256 = was_hash = 0;
		cp = line + strspn(line, " \t");
		/* Trim trailing space, comments and strip \n */
		for (i = 0, r = -1; cp[i] != '\0'; i++) {
			if (cp[i] == '#' || cp[i] == '\n') {
				cp[i] = '\0';
				break;
			}
			if (cp[i] == ' ' || cp[i] == '\t') {
				/* Remember the start of a span of whitespace */
				if (r == -1)
					r = i;
			} else
				r = -1;
		}
		if (r != -1)
			cp[r] = '\0';
		if (*cp == '\0')
			continue;
		if (strprefixtrim(&cp, "serial:", 1)) {
			if (ca == NULL && !wild_ca) {
				fatal("revoking certificates by serial number "
				    "requires specification of a CA key");
			}
			errno = 0;
			serial = strtoull(cp, &ep, 0);
			if (*cp == '\0' || (*ep != '\0' && *ep != '-'))
				fatal("%s:%lu: invalid serial \"%s\"",
				    path, lnum, cp);
			if (errno == ERANGE && serial == ULLONG_MAX)
				fatal("%s:%lu: serial out of range",
				    path, lnum);
			serial2 = serial;
			if (*ep == '-') {
				cp = ep + 1;
				errno = 0;
				serial2 = strtoull(cp, &ep, 0);
				if (*cp == '\0' || *ep != '\0')
					fatal("%s:%lu: invalid serial \"%s\"",
					    path, lnum, cp);
				if (errno == ERANGE && serial2 == ULLONG_MAX)
					fatal("%s:%lu: serial out of range",
					    path, lnum);
				if (serial2 <= serial)
					fatal("%s:%lu: invalid serial range "
					    "%llu:%llu", path, lnum,
					    (unsigned long long)serial,
					    (unsigned long long)serial2);
			}
			if (ssh_krl_revoke_cert_by_serial_range(krl,
			    ca, serial, serial2) != 0) {
				fatal_f("revoke serial failed");
			}
		} else if (strprefixtrim(&cp, "id:", 1)) {
			if (ca == NULL && !wild_ca) {
				fatal("revoking certificates by key ID "
				    "requires specification of a CA key");
			}
			if (ssh_krl_revoke_cert_by_key_id(krl, ca, cp) != 0)
				fatal_f("revoke key ID failed");
		} else if (strprefixtrim(&cp, "hash:", 1)) {
			const char *p;
			if ((p = strprefix(cp, "SHA1:", 0)) != NULL) {
				hash_to_blob(p, &blob, &blen, file, lnum);
				r = ssh_krl_revoke_key_sha1(krl, blob, blen);
#ifdef HAVE_EVP_SHA256
			} else if ((p = strprefix(cp, "SHA256:", 0)) != NULL) {
				hash_to_blob(p, &blob, &blen, file, lnum);
				r = ssh_krl_revoke_key_sha256(krl, blob, blen);
#endif /*def HAVE_EVP_SHA256*/
			} else
				fatal("%s:%lu: unsupported hash algorithm", file, lnum);
			if (r != 0)
				fatal_fr(r, "revoke key failed");
		} else {
			if (strprefixtrim(&cp, "key:", 1)) {
				was_explicit_key = 1;
			} else if (strprefixtrim(&cp, "sha1:", 1)) {
				was_sha1 = 1;
#ifdef HAVE_EVP_SHA256
			} else if (strprefixtrim(&cp, "sha256:", 1)) {
				was_sha256 = 1;
				/*
				 * Just try to process the line as a key.
				 * Parsing will fail if it isn't.
				 */
#endif /*def HAVE_EVP_SHA256*/
			}
			if ((key = sshkey_new(KEY_UNSPEC)) == NULL)
				fatal("sshkey_new");
			if ((r = sshkey_read(key, &cp)) != 0)
				fatal_r(r, "%s:%lu: invalid key", path, lnum);
			if (was_explicit_key)
				r = ssh_krl_revoke_key_explicit(krl, key);
			else if (was_sha1) {
				if (sshkey_fingerprint_raw(key,
				    SSH_DIGEST_SHA1, &blob, &blen) != 0) {
					fatal("%s:%lu: fingerprint failed",
					    file, lnum);
				}
				r = ssh_krl_revoke_key_sha1(krl, blob, blen);
#ifdef HAVE_EVP_SHA256
			} else if (was_sha256) {
				if (sshkey_fingerprint_raw(key,
				    SSH_DIGEST_SHA256, &blob, &blen) != 0) {
					fatal("%s:%lu: fingerprint failed",
					    file, lnum);
				}
				r = ssh_krl_revoke_key_sha256(krl, blob, blen);
#endif /*def HAVE_EVP_SHA256*/
			} else
				r = ssh_krl_revoke_key(krl, key);
			if (r != 0)
				fatal_fr(r, "revoke key failed");
			freezero(blob, blen);
			blob = NULL;
			blen = 0;
			sshkey_free(key);
		}
	}
	if (strcmp(path, "-") != 0)
		fclose(krl_spec);
	free(line);
	free(path);
}

static void
do_gen_krl(const struct passwd *pw, int updating, const char *ca_key_path,
    unsigned long long krl_version, const char *krl_comment,
    int argc, char **argv)
{
	struct ssh_krl *krl;
	struct stat sb;
	struct sshkey *ca = NULL;
	int i, r, wild_ca = 0;
	char *tmp;
	struct sshbuf *kbuf;

	if (*identity_file == '\0')
		fatal("KRL generation requires an output file");
	if (stat(identity_file, &sb) == -1) {
		if (errno != ENOENT)
			fatal("Cannot access KRL \"%s\": %s",
			    identity_file, strerror(errno));
		if (updating)
			fatal("KRL \"%s\" does not exist", identity_file);
	}
	if (ca_key_path != NULL) {
		if (strcasecmp(ca_key_path, "none") == 0)
			wild_ca = 1;
		else {
			tmp = tilde_expand_filename(ca_key_path, pw->pw_uid);
			if ((r = sshkey_load_public(tmp, &ca, NULL)) != 0)
				fatal_r(r, "Cannot load CA public key %s", tmp);
			free(tmp);
		}
	}

	if (updating)
		load_krl(identity_file, &krl);
	else if ((krl = ssh_krl_init()) == NULL)
		fatal("couldn't create KRL");

	if (krl_version != 0)
		ssh_krl_set_version(krl, krl_version);
	if (krl_comment != NULL)
		ssh_krl_set_comment(krl, krl_comment);

	for (i = 0; i < argc; i++)
		update_krl_from_file(pw, argv[i], wild_ca, ca, krl);

	if ((kbuf = sshbuf_new()) == NULL)
		fatal("sshbuf_new failed");
	if (ssh_krl_to_blob(krl, kbuf) != 0)
		fatal("Couldn't generate KRL");
	if ((r = sshbuf_write_file(identity_file, kbuf)) != 0)
		fatal("write %s: %s", identity_file, strerror(errno));
	sshbuf_free(kbuf);
	ssh_krl_free(krl);
	sshkey_free(ca);
}

static void
do_check_krl(int print_krl, int argc, char **argv)
{
	int i, r, ret = 0;
	char *comment;
	struct ssh_krl *krl;
	struct sshkey *k;

	if (*identity_file == '\0')
		fatal("KRL checking requires an input file");
	load_krl(identity_file, &krl);
	if (print_krl)
		krl_dump(krl, stdout);
	for (i = 0; i < argc; i++) {
		if ((r = sshkey_load_public(argv[i], &k, &comment)) != 0)
			fatal_r(r, "Cannot load public key %s", argv[i]);
		r = ssh_krl_check_key(krl, k);
		printf("%s%s%s%s: %s\n", argv[i],
		    *comment ? " (" : "", comment, *comment ? ")" : "",
		    r == 0 ? "ok" : "REVOKED");
		if (r != 0)
			ret = 1;
		sshkey_free(k);
		free(comment);
	}
	ssh_krl_free(krl);
	exit(ret);
}

static void
do_moduli_gen(const char *out_file, char **opts, size_t nopts)
{
#ifdef ENABLE_KEX_DH
	/* Moduli generation/screening */
	BIGNUM *start = NULL;
	int moduli_bits = 0;
	FILE *out;
	size_t i;

	/* Parse options */
	for (i = 0; i < nopts; i++) {
		const char *p, *errstr;
		if ((p = strprefix(opts[i], "start=", 0)) != NULL) {
			/* XXX - also compare length against bits */
			if (BN_hex2bn(&start, p) == 0)
				fatal("Invalid start point.");
		} else if ((p = strprefix(opts[i], "bits=", 0)) != NULL) {
			moduli_bits = (int)strtonum(p, 1, INT_MAX, &errstr);
			if (errstr) {
				fatal("Invalid number: %s (%s)", p, errstr);
			}
		} else {
			fatal("Option \"%s\" is unsupported for moduli "
			    "generation", opts[i]);
		}
	}

	if (strcmp(out_file, "-") == 0)
		out = stdout;
	else if ((out = fopen(out_file, "w")) == NULL) {
		fatal("Couldn't open modulus candidate file \"%s\": %s",
		    out_file, strerror(errno));
	}
	setvbuf(out, NULL, _IOLBF, 0);

	if (moduli_bits == 0)
		moduli_bits = DEFAULT_BITS;
	if (gen_candidates(out, moduli_bits, start) != 0)
		fatal("modulus candidate generation failed");
#else /*ndef ENABLE_KEX_DH*/
	UNUSED(out_file); UNUSED(opts); UNUSED(nopts);
	fatal("Moduli generation is not supported");
#endif /*ndef ENABLE_KEX_DH*/
}

static void
do_moduli_screen(const char *out_file, char **opts, size_t nopts)
{
#ifdef ENABLE_KEX_DH
	/* Moduli generation/screening */
	char *checkpoint = NULL;
	u_int32_t generator_wanted = 0;
	unsigned long start_lineno = 0, lines_to_process = 0;
	int prime_tests = 0;
	FILE *out, *in = stdin;
	size_t i;

	/* Parse options */
	for (i = 0; i < nopts; i++) {
		const char *p, *errstr;
		if ((p = strprefix(opts[i], "lines=", 0)) != NULL) {
			lines_to_process = strtoul(p, NULL, 10);
		} else if ((p = strprefix(opts[i], "start-line=", 0)) != NULL) {
			start_lineno = strtoul(p, NULL, 10);
		} else if ((p = strprefix(opts[i], "checkpoint=", 0)) != NULL) {
			free(checkpoint);
			checkpoint = xstrdup(p);
		} else if ((p = strprefix(opts[i], "generator=", 0)) != NULL) {
			generator_wanted = (u_int32_t)strtonum(p, 1, UINT_MAX,
			    &errstr);
			if (errstr != NULL) {
				fatal("Generator invalid: %s (%s)", p, errstr);
			}
		} else if ((p = strprefix(opts[i], "prime-tests=", 0)) != NULL) {
			prime_tests = (int)strtonum(p, 1, INT_MAX, &errstr);
			if (errstr) {
				fatal("Invalid number: %s (%s)", p, errstr);
			}
		} else {
			fatal("Option \"%s\" is unsupported for moduli "
			    "screening", opts[i]);
		}
	}

	if (have_identity && strcmp(identity_file, "-") != 0) {
		if ((in = fopen(identity_file, "r")) == NULL) {
			fatal("Couldn't open modulus candidate "
			    "file \"%s\": %s", identity_file,
			    strerror(errno));
		}
	}

	if (strcmp(out_file, "-") == 0)
		out = stdout;
	else if ((out = fopen(out_file, "a")) == NULL) {
		fatal("Couldn't open moduli file \"%s\": %s",
		    out_file, strerror(errno));
	}
	setvbuf(out, NULL, _IOLBF, 0);
	if (prime_test(in, out, prime_tests == 0 ? 100 : prime_tests,
	    generator_wanted, checkpoint,
	    start_lineno, lines_to_process) != 0)
		fatal("modulus screening failed");
	if (in != stdin)
		(void)fclose(in);
	if (out != stdout)
		(void)fclose(out);
	free(checkpoint);
#else /*ndef ENABLE_KEX_DH*/
	UNUSED(out_file); UNUSED(opts); UNUSED(nopts);
	fatal("Moduli screening is not supported");
#endif /*ndef ENABLE_KEX_DH*/
}

/* Read and confirm a passphrase */
static char *
read_check_passphrase(const char *prompt1, const char *prompt2,
    const char *retry_prompt, u_int retry_num)
{
	u_int k;
	char *passphrase1, *passphrase2;

	for (k = 0; k < retry_num; k++) {
		passphrase1 = read_passphrase(prompt1, RP_ALLOW_STDIN);
		passphrase2 = read_passphrase(prompt2, RP_ALLOW_STDIN);
		if (strcmp(passphrase1, passphrase2) == 0) {
			freezero(passphrase2, strlen(passphrase2));
			return passphrase1;
		}
		/* The passphrases do not match. Clear them and retry. */
		freezero(passphrase1, strlen(passphrase1));
		freezero(passphrase2, strlen(passphrase2));
		/* NOTE readpassphrase uses /dev/tty or stderr for writes */
		fputs(retry_prompt, stderr);
		fputc('\n', stderr);
	}
	fatal("Too many passphrase attempts.");
	/* NOTREACHED */
	return NULL;
}

static char*
asc_new_passphrase(const char *path, u_int retry_num)
{
	char *prompt, *ret;

	xasprintf(&prompt, "Enter passphrase for \"%s\" "
	    "(empty for no passphrase): ", path);
	ret = read_check_passphrase(prompt,
	    "Enter same passphrase again: ",
	    "Passphrases do not match.  Try again.", retry_num);
	free(prompt);

	return ret;
}

static void
usage(void)
{
	fprintf(stderr,
	    "usage: ssh-keygen [-q] [-a rounds] [-b bits] [-C comment] [-f output_keyfile]\n"
	    "                  [-m format] [-N new_passphrase]\n"
	    "                  [-t dsa | ecdsa | ed25519 | rsa]\n"
	    "                  [-Z cipher]\n"
	    "       ssh-keygen -p [-a rounds] [-f keyfile] [-m format]\n"
	    "                   [-N new_passphrase] [-P old_passphrase] [-Z cipher]\n"
	    "       ssh-keygen -i [-f input_keyfile] [-m format]\n"
	    "       ssh-keygen -e [-f input_keyfile] [-m format]\n"
	    "       ssh-keygen -y [-f input_keyfile]\n"
	    "       ssh-keygen -c [-a rounds] [-C comment] [-f keyfile] [-P passphrase]\n"
	    "       ssh-keygen -l [-v] [-E fingerprint_hash] [-f input_keyfile]\n"
	    "       ssh-keygen -B [-f input_keyfile]\n");
#ifdef ENABLE_PKCS11
	fprintf(stderr,
	    "       ssh-keygen -D pkcs11 [-l] [-v]\n");
#endif
	fprintf(stderr,
	    "       ssh-keygen -F hostname [-lv] [-f known_hosts_file]\n"
	    "       ssh-keygen -H [-f known_hosts_file]\n"
	    "       ssh-keygen -R hostname [-f known_hosts_file]\n"
	    "       ssh-keygen -r hostname [-g] [-f input_keyfile] [-O option]\n");
#ifdef WITH_OPENSSL
	fprintf(stderr,
	    "       ssh-keygen -M generate [-O option] output_file\n"
	    "       ssh-keygen -M screen [-f input_file] [-O option] output_file\n");
#endif
	fprintf(stderr,
	    "       ssh-keygen -I certificate_identity -s ca_key [-hU] [-D pkcs11_provider]\n"
	    "                  [-n principals] [-O option] [-V validity_interval]\n"
	    "                  [-z serial_number] file ...\n"
	    "       ssh-keygen -L [-f input_keyfile]\n"
	    "       ssh-keygen -A [-a rounds] [-f prefix_path]\n"
	    "       ssh-keygen -k -f krl_file [-u] [-s ca_public] [-z version_number]\n"
	    "                  file ...\n"
	    "       ssh-keygen -Q [-l] -f krl_file [file ...]\n");
	exit(1);
}

/*
 * Main program for key management.
 */
int
main(int argc, char **argv)
{
	char comment[1024], *passphrase;
	char *rr_hostname = NULL, *ep, *fp, *ra;
	struct sshkey *private, *public;
	const struct passwd *pw;
	int r, opt, type;
	int change_passphrase = 0, change_comment = 0, show_cert = 0;
	int find_host = 0, delete_host = 0, hash_hosts = 0;
	int gen_all_hostkeys = 0, gen_krl = 0, update_krl = 0, check_krl = 0;
	int prefer_agent = 0, convert_to = 0, convert_from = 0;
	int print_public = 0, print_generic = 0, cert_serial_autoinc = 0;
	int do_gen_candidates = 0, do_screen_candidates = 0;
	unsigned long long cert_serial = 0;
	char *identity_comment = NULL, *ca_key_path = NULL, **opts = NULL;
	size_t nopts = 0;
	u_int32_t bits = 0;
	const char *errstr;
	int log_level = SYSLOG_LEVEL_INFO;

	extern int optind;
	extern char *optarg;

	ssh_malloc_init();	/* must be called before any mallocs */
	/* Ensure that fds 0, 1 and 2 are open or directed to /dev/null */
	sanitise_stdfd();

	__progname = ssh_get_progname(argv[0]);

	ssh_OpenSSL_startup();
#ifdef OPENSSL_FIPS
	if (FIPS_mode()) {
	#ifdef HAVE_FIPSCHECK_H
		if (!FIPSCHECK_verify(NULL, NULL))
			fatal("FIPS integrity verification test failed.");
	#endif
		fprintf(stderr, "%s runs in FIPS mode\n", __progname);
	}
#endif /*def OPENSSL_FIPS*/
	ssh_module_startup();
	fill_default_xkalg();

	seed_rng();

	log_init(__progname, SYSLOG_LEVEL_INFO, SYSLOG_FACILITY_USER, 1);

	msetlocale();

	/* we need this for the home * directory.  */
	pw = getpwuid(getuid());
	if (!pw)
		fatal("No user exists for uid %lu", (u_long)getuid());
	/* take a copy of the returned structure! */
	pw = pwcopy(pw);

	if (gethostname(hostname, sizeof(hostname)) == -1)
		fatal("gethostname: %s", strerror(errno));

	/* Remaining characters: dGjJKSTwWY */
	while ((opt = getopt(argc, argv, "ABHLQUXceghiklopquvxy"
	    "C:D:E:F:I:M:N:O:P:R:V:Z:"
	    "a:b:f:g:m:n:r:s:t:z:")) != -1) {
		switch (opt) {
		case 'A':
			gen_all_hostkeys = 1;
			break;
		case 'b':
			bits = (u_int32_t)strtonum(optarg, 1, UINT32_MAX,
			    &errstr);
			if (errstr)
				fatal("Bits has bad value %s (%s)",
					optarg, errstr);
			break;
		case 'E':
			fingerprint_hash = ssh_digest_alg_by_name(optarg);
			if (fingerprint_hash == -1)
				fatal("Invalid hash algorithm \"%s\"", optarg);
			break;
		case 'F':
			find_host = 1;
			rr_hostname = optarg;
			break;
		case 'H':
			hash_hosts = 1;
			break;
		case 'I':
			cert_key_id = optarg;
			break;
		case 'R':
			delete_host = 1;
			rr_hostname = optarg;
			break;
		case 'L':
			show_cert = 1;
			break;
		case 'l':
			print_fingerprint = 1;
			break;
		case 'B':
			print_bubblebabble = 1;
			break;
		case 'm':
			if (strcasecmp(optarg, "RFC4716") == 0 ||
			    strcasecmp(optarg, "ssh2") == 0) {
				convert_format = FMT_RFC4716;
				/*explicitly preset default key format*/
				private_key_format = SSHKEY_PRIVATE_PKCS8;
				break;
			}
			if (strcasecmp(optarg, "PKCS8") == 0) {
				convert_format = FMT_PKCS8;
				/*explicitly preset default key format*/
				private_key_format = SSHKEY_PRIVATE_PKCS8;
				break;
			}
			if (strcasecmp(optarg, "PEM") == 0) {
				convert_format = FMT_PEM;
				private_key_format = SSHKEY_PRIVATE_PEM;
				break;
			}
			if (strcasecmp(optarg, "OpenSSH") == 0) {
				/*explicitly preset default conversion format*/
				convert_format = FMT_RFC4716;
				private_key_format = SSHKEY_PRIVATE_OPENSSH;
				break;
			}
			fatal("Unsupported conversion format \"%s\"", optarg);
		case 'n':
			cert_principals = optarg;
			break;
		case 'o':
			private_key_format = SSHKEY_PRIVATE_OPENSSH;
			break;
		case 'p':
			change_passphrase = 1;
			break;
		case 'c':
			change_comment = 1;
			break;
		case 'f':
			if (strlcpy(identity_file, optarg,
			    sizeof(identity_file)) >= sizeof(identity_file))
				fatal("Identity filename too long");
			have_identity = 1;
			break;
		case 'g':
			print_generic = 1;
			break;
		case 'P':
			identity_passphrase = optarg;
			break;
		case 'N':
			identity_new_passphrase = optarg;
			break;
		case 'Q':
			check_krl = 1;
			break;
		case 'O':
			opts = xrecallocarray(opts, nopts, nopts + 1,
			    sizeof(*opts));
			opts[nopts++] = xstrdup(optarg);
			break;
		case 'Z':
			openssh_format_cipher = optarg;
			if (cipher_by_name(openssh_format_cipher) == NULL)
				fatal("invalid cipher '%s'",
				    openssh_format_cipher);
			break;
		case 'C':
			identity_comment = optarg;
			break;
		case 'q':
			quiet = 1;
			break;
		case 'e':
		case 'x':
			/* export key */
			convert_to = 1;
			break;
		case 'h':
			cert_key_type = SSH2_CERT_TYPE_HOST;
			certflags_flags = 0;
			break;
		case 'k':
			gen_krl = 1;
			break;
		case 'i':
		case 'X':
			/* import key */
			convert_from = 1;
			break;
		case 'y':
			print_public = 1;
			break;
		case 's':
			ca_key_path = optarg;
			break;
		case 't':
			key_type_name = optarg;
			break;
		case 'D':
			pkcs11provider = optarg;
			break;
		case 'U':
			prefer_agent = 1;
			break;
		case 'u':
			update_krl = 1;
			break;
		case 'v':
			if (log_level < SYSLOG_LEVEL_DEBUG3)
				log_level++;
			break;
		case 'r':
			rr_hostname = optarg;
			break;
		case 'a':
			rounds = (int)strtonum(optarg, 1, INT_MAX, &errstr);
			if (errstr)
				fatal("Invalid number: %s (%s)",
					optarg, errstr);
			break;
		case 'V':
			parse_cert_times(optarg);
			break;
		case 'z':
			errno = 0;
			if (*optarg == '+') {
				cert_serial_autoinc = 1;
				optarg++;
			}
			cert_serial = strtoull(optarg, &ep, 10);
			if (*optarg < '0' || *optarg > '9' || *ep != '\0' ||
			    (errno == ERANGE && cert_serial == ULLONG_MAX))
				fatal("Invalid serial number \"%s\"", optarg);
			break;
		case 'M':
			if (strcmp(optarg, "generate") == 0)
				do_gen_candidates = 1;
			else if (strcmp(optarg, "screen") == 0)
				do_screen_candidates = 1;
			else
				fatal("Unsupported moduli option %s", optarg);
			break;
		default:
			usage();
		}
	}

#ifdef OPENSSL_FIPS
	if (FIPS_mode()) {
		if (private_key_format == SSHKEY_PRIVATE_OPENSSH)
			fatal("OpenSSH proprietary key format is not allowed in FIPS mode");
		if (private_key_format == SSHKEY_PRIVATE_PEM) {
			private_key_format = SSHKEY_PRIVATE_PKCS8;
			error("In FIPS mode is used only PKCS#8 format");
		}
	}
#endif

	/* reinit */
	log_init(__progname, log_level, SYSLOG_FACILITY_USER, 1);

#ifdef USE_OPENSSL_ENGINE
{	char *filename = NULL, *engconfig;

	engconfig = getenv(SSH_ENGINE_CONF_ENV);
	if (engconfig == NULL)
		xasprintf(&filename, "%s/%s", pw->pw_dir,
		    _PATH_SSH_ENGINE_CONFFILE); /*fatal on error*/
	else
		filename = engconfig;

	(void)process_engconfig_file(filename);
	if (filename != engconfig)
		free(filename);
}
#endif

	argv += optind;
	argc -= optind;

	if (ca_key_path != NULL) {
		if (argc < 1 && !gen_krl) {
			error("Too few arguments.");
			usage();
		}
	} else if (argc > 0 && !gen_krl && !check_krl &&
	    !do_gen_candidates && !do_screen_candidates) {
		error("Too many arguments.");
		usage();
	}
	if (change_passphrase && change_comment) {
		error("Can only have one of -p and -c.");
		usage();
	}
	if (print_fingerprint && (delete_host || hash_hosts)) {
		error("Cannot use -l with -H or -R.");
		usage();
	}
	if (gen_krl) {
		do_gen_krl(pw, update_krl, ca_key_path,
		    cert_serial, identity_comment, argc, argv);
		return (0);
	}
	if (check_krl) {
		do_check_krl(print_fingerprint, argc, argv);
		return (0);
	}
	if (ca_key_path != NULL) {
		size_t i;
		if (cert_key_id == NULL)
			fatal("Must specify key id (-I) when certifying");
		for (i = 0; i < nopts; i++)
			add_cert_option(opts[i]);
		do_ca_sign(pw, ca_key_path, prefer_agent,
		    cert_serial, cert_serial_autoinc, argc, argv);
	}
	if (show_cert)
		do_show_cert(pw);
	if (delete_host || hash_hosts || find_host) {
		do_known_hosts(pw, rr_hostname, find_host,
		    delete_host, hash_hosts);
	}
	if (pkcs11provider != NULL)
		do_download();
	if (print_fingerprint || print_bubblebabble)
		do_fingerprint(pw);
	if (change_passphrase)
		do_change_passphrase(pw);
	if (change_comment)
		do_change_comment(pw, identity_comment);
#ifdef WITH_OPENSSL
	if (convert_to)
		do_convert_to(pw);
	if (convert_from)
		do_convert_from(pw);
#else /* WITH_OPENSSL */
	if (convert_to || convert_from)
		fatal("key conversion disabled at compile time");
#endif /* WITH_OPENSSL */
	if (print_public)
		do_print_public(pw);
	if (rr_hostname != NULL) {
		unsigned int n = 0;

		if (have_identity) {
			n = do_print_resource_record(identity_file,
			    rr_hostname, print_generic, opts, nopts);
			if (n == 0)
				fatal("%s: %s", identity_file, strerror(errno));
			exit(0);
		} else {

			n += do_print_resource_record(
			    _PATH_HOST_RSA_KEY_FILE, rr_hostname,
			    print_generic, opts, nopts);
			n += do_print_resource_record(
			    _PATH_HOST_ECDSA_KEY_FILE, rr_hostname,
			    print_generic, opts, nopts);
			n += do_print_resource_record(
			    _PATH_HOST_ED25519_KEY_FILE, rr_hostname,
			    print_generic, opts, nopts);
#ifdef WITH_DSA
			n += do_print_resource_record(
			    _PATH_HOST_DSA_KEY_FILE, rr_hostname,
			    print_generic, opts, nopts);
#endif
#ifdef WITH_XMSS
			n += do_print_resource_record(
			    _PATH_HOST_XMSS_KEY_FILE, rr_hostname,
			    print_generic, opts, nopts);
#endif
			if (n == 0)
				fatal("no keys found.");
			exit(0);
		}
	}

	if (do_gen_candidates || do_screen_candidates) {
		if (argc <= 0)
			fatal("No output file specified");
		else if (argc > 1)
			fatal("Too many output files specified");
	}
	if (do_gen_candidates) {
		do_moduli_gen(argv[0], opts, nopts);
		return 0;
	}
	if (do_screen_candidates) {
		do_moduli_screen(argv[0], opts, nopts);
		return 0;
	}

	if (gen_all_hostkeys) {
		do_gen_all_hostkeys(pw);
		return (0);
	}

	if (key_type_name == NULL)
		key_type_name = default_key_type_name();

	type = sshkey_type_from_shortname(key_type_name);
	type_bits_valid(type, key_type_name, &bits);

	if (!quiet)
		printf("Generating public/private %s key pair.\n",
		    key_type_name);
	if ((r = sshkey_generate(type, bits, &private)) != 0)
		fatal_r(r, "sshkey_generate failed");
	if ((r = sshkey_from_private(private, &public)) != 0)
		fatal_r(r, "sshkey_from_private");

	if (!have_identity)
		ask_filename(pw, "Enter file in which to save the key");

	/* Create ~/.ssh directory if it doesn't already exist. */
	hostfile_create_user_ssh_dir(identity_file, !quiet);

	/* If the file already exists, ask the user to confirm. */
	if (!confirm_overwrite(identity_file))
		exit(1);

	/* Determine the passphrase for the private key */
	passphrase = private_key_new_passphrase(identity_file,
	    (u_int)-1/*practically unlimited*/);

	if (identity_comment) {
		strlcpy(comment, identity_comment, sizeof(comment));
	} else {
		/* Create default comment field for the passphrase. */
		snprintf(comment, sizeof comment, "%s@%s", pw->pw_name, hostname);
	}

	/* Save the key with the given passphrase and comment. */
	if ((r = sshkey_save_private(private, identity_file, passphrase,
	    comment, private_key_format, openssh_format_cipher, rounds)) != 0) {
		error_r(r, "Saving key \"%s\" failed", identity_file);
		freezero(passphrase, strlen(passphrase));
		exit(1);
	}

	freezero(passphrase, strlen(passphrase));
	sshkey_free(private);

	if (!quiet)
		printf("Your identification has been saved in '%s'.\n",
		    identity_file);

	strlcat(identity_file, ".pub", sizeof(identity_file));
	if ((r = sshkey_save_public(public, identity_file, comment)) != 0)
		fatal_r(r, "Unable to save public key to %s", identity_file);

	if (!quiet) {
		fp = sshkey_fingerprint(public, fingerprint_hash,
		    SSH_FP_DEFAULT);
		ra = sshkey_fingerprint(public, fingerprint_hash,
		    SSH_FP_RANDOMART);
		if (fp == NULL || ra == NULL)
			fatal("sshkey_fingerprint failed");
		printf("Your public key has been saved in '%s'\n",
		    identity_file);
		printf("The key fingerprint is:\n");
		printf("%s %s\n", fp, comment);
		printf("The key's randomart image is:\n");
		printf("%s\n", ra);
		free(ra);
		free(fp);
	}

	sshkey_free(public);
	exit(0);
}
