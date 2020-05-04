/* $OpenBSD: authfile.c,v 1.140 2020/04/17 07:15:11 djm Exp $ */
/*
 * Copyright (c) 2000, 2013 Markus Friedl.  All rights reserved.
 * Copyright (c) 2002-2020 Roumen Petrov.  All rights reserved.
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
#include <sys/stat.h>
#include <sys/uio.h>

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <limits.h>

#include "cipher.h"
#include "ssh.h"
#include "log.h"
#include "authfile.h"
#include "misc.h"
#include "atomicio.h"
#include "sshxkey.h"
#include "ssh-x509.h"
#include "key-eng.h"
#include "ssherr.h"
#include "krl.h"

#define MAX_KEY_FILE_SIZE	(1024 * 1024)

/* Save a key blob to a file */
static int
sshkey_save_private_blob(struct sshbuf *keybuf, const char *filename)
{
	int r;
	mode_t omask;

	omask = umask(077);
	r = sshbuf_write_file(filename, keybuf);
	umask(omask);
	return r;
}

int
sshkey_save_private(struct sshkey *key, const char *filename,
    const char *passphrase, const char *comment,
    int force_new_format, const char *new_format_cipher, int new_format_rounds)
{
	struct sshbuf *keyblob = NULL;
	int r;

	if ((keyblob = sshbuf_new()) == NULL)
		return SSH_ERR_ALLOC_FAIL;
	if ((r = sshkey_private_to_fileblob(key, keyblob, passphrase, comment,
	    force_new_format, new_format_cipher, new_format_rounds)) != 0)
		goto out;
	if ((r = sshkey_save_private_blob(keyblob, filename)) != 0)
		goto out;
	r = 0;
 out:
	sshbuf_free(keyblob);
	return r;
}

/* XXX remove error() calls from here? */
int
sshkey_perm_ok(int fd, const char *filename)
{
	struct stat st;

	if (fstat(fd, &st) == -1)
		return SSH_ERR_SYSTEM_ERROR;
	/*
	 * if a key owned by the user is accessed, then we check the
	 * permissions of the file. if the key owned by a different user,
	 * then we don't care.
	 */
#ifdef HAVE_CYGWIN
	if (check_ntsec(filename))
#endif
	if ((st.st_uid == getuid()) && (st.st_mode & 077) != 0) {
		error("@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@");
		error("@         WARNING: UNPROTECTED PRIVATE KEY FILE!          @");
		error("@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@");
		error("Permissions 0%3.3o for '%s' are too open.",
		    (u_int)st.st_mode & 0777, filename);
		error("It is required that your private key files are NOT accessible by others.");
		error("This private key will be ignored.");
		return SSH_ERR_KEY_BAD_PERMISSIONS;
	}
	return 0;
}


static int
sshkey_load_private_type_file(int type, const char *filename,
    const char *passphrase, struct sshkey **keyp, char **commentp)
{
	int fd, r;

	if (keyp != NULL) *keyp = NULL;
	if (commentp != NULL) *commentp = NULL;

	if ((fd = open(filename, O_RDONLY)) == -1)
		return SSH_ERR_SYSTEM_ERROR;

	r = sshkey_perm_ok(fd, filename);
	if (r != 0) goto out;

	r = sshkey_load_private_type_fd(fd, type, passphrase, keyp, commentp);
	if (r != 0) goto out;

	if (keyp && *keyp)
		r = sshkey_set_filename(*keyp, filename);

out:
	close(fd);
	return r;
}

int
sshkey_load_private_type(int type, const char *filename, const char *passphrase,
    struct sshkey **keyp, char **commentp)
{
	debug3("%s() type=%d, filename=%s", __func__, type, (filename ? filename : "?!?"));

#ifdef USE_OPENSSL_STORE2
	if (strncmp(filename, "store:", 6) == 0)
		return store_load_private_type(type, filename + 6,
			passphrase, keyp, commentp);
#endif
#ifdef USE_OPENSSL_ENGINE
	if (strncmp(filename, "engine:", 7) == 0)
		return engine_load_private_type(type, filename + 7,
			passphrase, keyp, commentp);
#endif

	return sshkey_load_private_type_file(type, filename, passphrase,
	    keyp, commentp);
}

int
sshkey_load_private_type_fd(int fd, int type, const char *passphrase,
    struct sshkey **keyp, char **commentp)
{
	struct sshbuf *buffer = NULL;
	int r;

	if (keyp != NULL)
		*keyp = NULL;
	if ((r = sshbuf_load_fd(fd, &buffer)) != 0 ||
	    (r = sshkey_parse_private_fileblob_type(buffer, type,
	    passphrase, keyp, commentp)) != 0)
		goto out;

	/* success */
	r = 0;
 out:
	sshbuf_free(buffer);
	return r;
}

int
sshkey_load_private(const char *filename, const char *passphrase,
    struct sshkey **keyp, char **commentp)
{
	debug3("%s() filename=%s", __func__, (filename ? filename : "?!?"));
	
	return sshkey_load_private_type_file(KEY_UNSPEC, filename, passphrase, 
	    keyp, commentp);
}

static int
sshkey_try_load_public(const char *filename, struct sshkey **keyp,
    char **commentp)
{
	FILE *f;
	char *line = NULL, *cp;
	size_t linesize = 0;
	int r;
	struct sshkey *k = NULL;

	if (keyp != NULL)
		*keyp = NULL;
	if (commentp != NULL)
		*commentp = NULL;

/* NOTE: For external keys simulate "missing" file.
 * This suppress extra messages due to faulty load control in ssh.c
 */
#ifdef USE_OPENSSL_STORE2
	if (strncmp(filename, "store:", 6) == 0) {
		errno = ENOENT;
		return SSH_ERR_SYSTEM_ERROR;
	}
#endif
#ifdef USE_OPENSSL_ENGINE
	if (strncmp(filename, "engine:", 7) == 0) {
		errno = ENOENT;
		return SSH_ERR_SYSTEM_ERROR;
	}
#endif

	if ((f = fopen(filename, "r")) == NULL)
		return SSH_ERR_SYSTEM_ERROR;
	if ((k = sshkey_new(KEY_UNSPEC)) == NULL) {
		fclose(f);
		return SSH_ERR_ALLOC_FAIL;
	}
	while (getline(&line, &linesize, f) != -1) {
		cp = line;
		switch (*cp) {
		case '#':
		case '\n':
		case '\0':
			continue;
		}
		/* Abort loading if this looks like a private key */
		if (strncmp(cp, "-----BEGIN", 10) == 0 ||
		    strcmp(cp, "SSH PRIVATE KEY FILE") == 0)
			break;
		/* Skip leading whitespace. */
		for (; *cp && (*cp == ' ' || *cp == '\t'); cp++)
			;
		if (*cp) {
			char *pkalg = NULL;
			if ((r = sshkey_read_pkalg(k, &cp, &pkalg)) == 0) {
				cp[strcspn(cp, "\r\n")] = '\0';
				if (commentp) {
					*commentp = strdup(*cp ?
					    cp : filename);
					if (*commentp == NULL)
						r = SSH_ERR_ALLOC_FAIL;
				}
				free(line);
				fclose(f);
				if (pkalg) {
					/* load extra certificates for RFC6187 keys */
					x509key_load_certs(pkalg, k, filename);
					free(pkalg);
				}
				/* success */
				if (keyp != NULL)
					*keyp = k;
				return r;
			}
		}
	}
	sshkey_free(k);
	free(line);
	fclose(f);
	return SSH_ERR_INVALID_FORMAT;
}

/* load public key from any pubkey file */
int
sshkey_load_public(const char *filename, struct sshkey **keyp, char **commentp)
{
	int r;

	debug3("%s() filename=%s", __func__, (filename ? filename : "?!?"));
#ifdef USE_OPENSSL_STORE2
	if (strncmp(filename, "store:", 6) == 0) {
		return store_try_load_public(filename + 6, keyp, commentp);
	}
#endif
#ifdef USE_OPENSSL_ENGINE
	if (strncmp(filename, "engine:", 7) == 0) {
		return engine_try_load_public(filename + 7, keyp, commentp);
	}
#endif

	r = sshkey_try_load_public(filename, keyp, commentp);
	if (r == 0) return 0;

	/* try .pub suffix */
{	char *pubfile = NULL;
	if (asprintf(&pubfile, "%s.pub", filename) < 0)
		return SSH_ERR_ALLOC_FAIL;
	debug3("%s() pubfile=%s", __func__, pubfile);

	r = sshkey_try_load_public(pubfile, keyp, commentp);

	free(pubfile);
}
	return r;
}

/* Load the certificate associated with the named private key */
int
sshkey_load_cert(const char *filename, struct sshkey **keyp)
{
	char *file = NULL;
	int r;

	debug3("%s() filename=%s", __func__, (filename ? filename : "?!?"));
	if (keyp != NULL)
		*keyp = NULL;

	if (asprintf(&file, "%s-cert.pub", filename) < 0)
		return SSH_ERR_ALLOC_FAIL;

	r = sshkey_try_load_public(file, keyp, NULL);

	free(file);
	return r;
}

/* Load private key and certificate */
int
sshkey_load_private_cert(int type, const char *filename, const char *passphrase,
    struct sshkey **keyp)
{
	struct sshkey *key = NULL, *cert = NULL;
	int r;

	debug3("%s() type=%d, filename=%s", __func__, type, (filename ? filename : "?!?"));
	if (keyp != NULL)
		*keyp = NULL;

	switch (type) {
#ifdef WITH_OPENSSL
	case KEY_RSA:
	case KEY_DSA:
	case KEY_ECDSA:
#endif /* WITH_OPENSSL */
	case KEY_ED25519:
	case KEY_XMSS:
	case KEY_UNSPEC:
		break;
	default:
		return SSH_ERR_KEY_TYPE_UNKNOWN;
	}

	if ((r = sshkey_load_private_type(type, filename,
	    passphrase, &key, NULL)) != 0 ||
	    (r = sshkey_load_cert(filename, &cert)) != 0)
		goto out;

	/* Make sure the private key matches the certificate */
	if (sshkey_equal_public(key, cert) == 0) {
		r = SSH_ERR_KEY_CERT_MISMATCH;
		goto out;
	}

	if ((r = sshkey_to_certified(key)) != 0 ||
	    (r = sshkey_cert_copy(cert, key)) != 0)
		goto out;
	r = 0;
	if (keyp != NULL) {
		*keyp = key;
		key = NULL;
	}
 out:
	sshkey_free(key);
	sshkey_free(cert);
	return r;
}

/*
 * Returns success if the specified "key" is listed in the file "filename",
 * SSH_ERR_KEY_NOT_FOUND: if the key is not listed or another error.
 * If "strict_type" is set then the key type must match exactly,
 * otherwise a comparison that ignores certficiate data is performed.
 * If "check_ca" is set and "key" is a certificate, then its CA key is
 * also checked and sshkey_in_file() will return success if either is found.
 */
int
sshkey_in_file(struct sshkey *key, const char *filename, int strict_type,
    int check_ca)
{
	FILE *f;
	char *line = NULL, *cp;
	size_t linesize = 0;
	int r = 0;
	struct sshkey *pub = NULL;

	int (*sshkey_compare)(const struct sshkey *, const struct sshkey *) =
	    strict_type ?  sshkey_equal : sshkey_equal_public;

	if ((f = fopen(filename, "r")) == NULL)
		return SSH_ERR_SYSTEM_ERROR;

	while (getline(&line, &linesize, f) != -1) {
		sshkey_free(pub);
		pub = NULL;
		cp = line;

		/* Skip leading whitespace. */
		for (; *cp && (*cp == ' ' || *cp == '\t'); cp++)
			;

		/* Skip comments and empty lines */
		switch (*cp) {
		case '#':
		case '\n':
		case '\0':
			continue;
		}

		if ((pub = sshkey_new(KEY_UNSPEC)) == NULL) {
			r = SSH_ERR_ALLOC_FAIL;
			goto out;
		}
		switch (r = sshkey_read(pub, &cp)) {
		case 0:
			break;
		case SSH_ERR_KEY_LENGTH:
			continue;
		default:
			goto out;
		}
		if (sshkey_compare(key, pub) ||
		    (check_ca && sshkey_is_cert(key) &&
		    sshkey_compare(key->cert->signature_key, pub))) {
			r = 0;
			goto out;
		}
	}
	r = SSH_ERR_KEY_NOT_FOUND;
 out:
	free(line);
	sshkey_free(pub);
	fclose(f);
	return r;
}

/*
 * Checks whether the specified key is revoked, returning 0 if not,
 * SSH_ERR_KEY_REVOKED if it is or another error code if something
 * unexpected happened.
 * This will check both the key and, if it is a certificate, its CA key too.
 * "revoked_keys_file" may be a KRL or a one-per-line list of public keys.
 */
int
sshkey_check_revoked(struct sshkey *key, const char *revoked_keys_file)
{
	int r;

	r = ssh_krl_file_contains_key(revoked_keys_file, key);
	/* If this was not a KRL to begin with then continue below */
	if (r != SSH_ERR_KRL_BAD_MAGIC)
		return r;

	/*
	 * If the file is not a KRL or we can't handle KRLs then attempt to
	 * parse the file as a flat list of keys.
	 */
	switch ((r = sshkey_in_file(key, revoked_keys_file, 0, 1))) {
	case 0:
		/* Key found => revoked */
		return SSH_ERR_KEY_REVOKED;
	case SSH_ERR_KEY_NOT_FOUND:
		/* Key not found => not revoked */
		return 0;
	default:
		/* Some other error occurred */
		return r;
	}
}

/*
 * Advanced *cpp past the end of key options, defined as the first unquoted
 * whitespace character. Returns 0 on success or -1 on failure (e.g.
 * unterminated quotes).
 */
int
sshkey_advance_past_options(char **cpp)
{
	char *cp = *cpp;
	int quoted = 0;

	for (; *cp && (quoted || (*cp != ' ' && *cp != '\t')); cp++) {
		if (*cp == '\\' && cp[1] == '"')
			cp++;	/* Skip both */
		else if (*cp == '"')
			quoted = !quoted;
	}
	*cpp = cp;
	/* return failure for unterminated quotes */
	return (*cp == '\0' && quoted) ? -1 : 0;
}

/* Save a public key */
int
sshkey_save_public(const struct sshkey *key, const char *path,
    const char *comment)
{
	int fd;
	FILE *f = NULL;
	int r = SSH_ERR_INTERNAL_ERROR;

	if ((fd = open(path, O_WRONLY|O_CREAT|O_TRUNC, 0644)) == -1) {
		debug3("%s: open: %s", __func__, strerror(errno));
		return SSH_ERR_SYSTEM_ERROR;
	}
	if ((f = fdopen(fd, "w")) == NULL) {
		debug3("%s: fdopen: %s", __func__, strerror(errno));
		r = SSH_ERR_SYSTEM_ERROR;
		goto fail;
	}

	if ((r = sshkey_write(key, f)) != 0)
		goto fail;
	fprintf(f, " %s\n", comment);

	if (ferror(f)) {
		debug3("write key failed: %s", strerror(errno));
		r = SSH_ERR_SYSTEM_ERROR;
		goto fail;
	}
	(void)fclose(f);

	return 0;
fail:
{	int oerrno = errno;
	if (f != NULL)
		fclose(f);
	else
		close(fd);
	errno = oerrno;
}
	return r;
}
