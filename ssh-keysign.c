/* $OpenBSD: ssh-keysign.c,v 1.66 2020/12/17 23:10:27 djm Exp $ */
/*
 * Copyright (c) 2002 Markus Friedl.  All rights reserved.
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

#include "includes.h"

#include <fcntl.h>
#ifdef HAVE_PATHS_H
#include <paths.h>
#endif
#include <pwd.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>

#include "xmalloc.h"
#include "log.h"
#include "compat.h"
#include "ssh-x509.h"
#include "ssh-xkalg.h"
#include "ssh.h"
#include "ssh2.h"
#include "misc.h"
#include "sshbuf.h"
#include "authfile.h"
#include "msg.h"
#include "canohost.h"
#include "pathnames.h"
#include "readconf.h"
#include "uidswap.h"

extern char *__progname;

/* used in ssh-x509.c */
extern STACK_OF(X509)* (*pssh_x509store_build_certchain)(X509 *cert, STACK_OF(X509) *untrusted);

/* minimize OCSP dependencies */
#ifdef SSH_OCSP_ENABLED

#if 1	/* used in readconf.c */

void
ssh_set_validator(const VAOptions *_va) {
	(void)_va;
	return;
}

int
ssh_get_default_vatype(void) {
	return(SSHVA_NONE);
}

int
ssh_get_vatype_s(const char* type) {
	(void)type;
	return(-1);
}

const char*
ssh_get_vatype_i(int id) {
	(void)id;
	return(NULL);
}

#endif	/* end of used in readconf.c */
#endif /*def SSH_OCSP_ENABLED*/


#if 1	/* used in x509store.c */
int
ssh_ocsp_validate(X509 *cert, X509_STORE *x509store) {
	UNUSED(cert);
	UNUSED(x509store);
	return -1;
}

#ifdef LDAP_ENABLED
#ifdef USE_LDAP_STORE	 /* OpenSSL >= 1.1.1 */
int/*bool*/ set_ldap_version(const char *ver);
int/*bool*/
set_ldap_version(const char *ver) {
	UNUSED(ver);
	return 0;
}
#endif /*def USE_LDAP_STORE*/

#ifndef USE_X509_LOOKUP_STORE /* OpenSSL < 3.0 */
X509_LOOKUP_METHOD* X509_LOOKUP_ldap(void);
X509_LOOKUP_METHOD*
X509_LOOKUP_ldap(void) {
	return NULL;
}
#endif /*ndef USE_X509_LOOKUP_STORE*/
#endif /*def LDAP_ENABLED*/
#endif	/* end of used in x509store.c */


static int
valid_request(struct passwd *pw, char *host, struct sshkey **retkey, char **retalg,
    u_char *data, size_t datalen)
{
	struct sshbuf *b;
	struct sshkey *key = NULL;
	u_char type, *pkblob;
	char *p;
	size_t blen, len;
	char *pkalg = NULL, *luser;
	int r, pktype, fail;

	if (retkey != NULL)
		*retkey = NULL;
	if (retalg != NULL)
		*retalg = NULL;
	fail = 0;

	if ((b = sshbuf_from(data, datalen)) == NULL)
		fatal_f("sshbuf_from failed");

	/* session id, currently limited to SHA1 (20 bytes) or SHA256 (32) */
	if ((r = sshbuf_get_string(b, NULL, &len)) != 0)
		fatal_fr(r, "parse session ID");
	if (len != 20 && len != 32)
		fail++;

	if ((r = sshbuf_get_u8(b, &type)) != 0)
		fatal_fr(r, "parse type");
	if (type != SSH2_MSG_USERAUTH_REQUEST)
		fail++;

	/* server user */
	if ((r = sshbuf_skip_string(b)) != 0)
		fatal_fr(r, "parse user");

	/* service */
	if ((r = sshbuf_get_cstring(b, &p, NULL)) != 0)
		fatal_fr(r, "parse service");
	if (strcmp("ssh-connection", p) != 0)
		fail++;
	free(p);

	/* method */
	if ((r = sshbuf_get_cstring(b, &p, NULL)) != 0)
		fatal_fr(r, "parse method");
	if (strcmp("hostbased", p) != 0)
		fail++;
	free(p);

	/* pubkey */
	if ((r = sshbuf_get_cstring(b, &pkalg, NULL)) != 0 ||
	    (r = sshbuf_get_string(b, &pkblob, &blen)) != 0)
		fatal_fr(r, "parse pk");

	pktype = sshkey_type_from_name(pkalg);
	if (pktype == KEY_UNSPEC)
		fail++;
	else if ((r = Xkey_from_blob(pkalg, pkblob, blen, &key)) != 0) {
		error_fr(r, "decode key");
		fail++;
	} else if (key->type != pktype)
		fail++;
	free(pkblob);

	/* client host name, handle trailing dot */
	if ((r = sshbuf_get_cstring(b, &p, &len)) != 0)
		fatal_fr(r, "parse hostname");
	debug2_f("check expect chost %s got %s", host, p);
	if (strlen(host) != len - 1)
		fail++;
	else if (p[len - 1] != '.')
		fail++;
	else if (strncasecmp(host, p, len - 1) != 0)
		fail++;
	free(p);

	/* local user */
	if ((r = sshbuf_get_cstring(b, &luser, NULL)) != 0)
		fatal_fr(r, "parse luser");

	if (strcmp(pw->pw_name, luser) != 0)
		fail++;
	free(luser);

	/* end of message */
	if (sshbuf_len(b) != 0)
		fail++;
	sshbuf_free(b);

	debug3_f("fail %d", fail);

	if (fail == 0) {
		if (retkey != NULL) {
			*retkey = key;
			key = NULL;
		}
		if (retalg != NULL) {
			*retalg = pkalg;
			pkalg= NULL;
		}
	}

	sshkey_free(key);
	free(pkalg);

	return (fail ? -1 : 0);
}

int
main(int argc, char **argv)
{
	struct sshbuf *b;
	Options options;
#define NUM_KEYTYPES 5
	struct sshkey *keys[NUM_KEYTYPES], *key = NULL;
	struct passwd *pw;
	int r, key_fd[NUM_KEYTYPES], i, found, version = 2, fd;
	u_char *signature, *data, rver;
	char *host, *fp, *alg = NULL;
	size_t slen, dlen;

	UNUSED(argc);
	ssh_malloc_init();	/* must be called before any mallocs */
	__progname = ssh_get_progname(argv[0]);
	if (pledge("stdio rpath getpw dns id", NULL) != 0)
		fatal("%s: pledge: %s", __progname, strerror(errno));

	/* Ensure that stdin and stdout are connected */
	if ((fd = open(_PATH_DEVNULL, O_RDWR)) < 2)
		exit(1);
	/* Leave /dev/null fd iff it is attached to stderr */
	if (fd > 2)
		close(fd);

	ssh_OpenSSL_startup();
	fill_default_xkalg();
{
	X509StoreOptions ca;

	X509StoreOptions_init(&ca);
	X509StoreOptions_system_defaults(&ca);
	ssh_x509store_addlocations(&ca);
	X509StoreOptions_reset(&ca);
}
	pssh_x509store_build_certchain = ssh_x509store_build_certchain;

	i = 0;
	/* XXX This really needs to read sshd_config for the paths */
	key_fd[i++] = open(_PATH_HOST_ED25519_KEY_FILE, O_RDONLY);
#ifdef OPENSSL_HAS_ECC
	key_fd[i++] = open(_PATH_HOST_ECDSA_KEY_FILE, O_RDONLY);
#endif
	key_fd[i++] = open(_PATH_HOST_RSA_KEY_FILE, O_RDONLY);
	key_fd[i++] = open(_PATH_HOST_DSA_KEY_FILE, O_RDONLY);
#ifdef WITH_XMSS
	key_fd[i++] = open(_PATH_HOST_XMSS_KEY_FILE, O_RDONLY);
#else
	key_fd[i++] = -1;
#endif

	if ((pw = getpwuid(getuid())) == NULL)
		fatal("%s: getpwuid failed", __progname);
	pw = pwcopy(pw);

	permanently_set_uid(pw);

	seed_rng();

#ifdef DEBUG_SSH_KEYSIGN
	log_init(__progname, SYSLOG_LEVEL_DEBUG3, SYSLOG_FACILITY_AUTH, 0);
#endif

	/* verify that ssh-keysign is enabled by the admin */
	initialize_options(&options);
	(void)read_config_file(_PATH_HOST_CONFIG_FILE, pw, "", "",
	    &options, 0, NULL);
	(void)fill_default_options(&options);
	if (options.enable_ssh_keysign != 1)
		fatal("%s: ssh-keysign not enabled in %s", __progname,
		    _PATH_HOST_CONFIG_FILE);

	for (i = found = 0; i < NUM_KEYTYPES; i++) {
		if (key_fd[i] != -1)
			found = 1;
	}
	if (found == 0)
		fatal("%s: could not open any host key", __progname);

	found = 0;
	for (i = 0; i < NUM_KEYTYPES; i++) {
		keys[i] = NULL;
		if (key_fd[i] == -1)
			continue;
		r = sshkey_load_private_fd(key_fd[i], NULL, &key, NULL);
		close(key_fd[i]);
		if (r != 0)
			debug_r(r, "parse key %d", i);
		else if (key != NULL) {
			keys[i] = key;
			found = 1;
		}
	}
	if (!found)
		fatal("%s: no hostkey found", __progname);

	if (pledge("stdio dns", NULL) != 0)
		fatal("%s: pledge: %s", __progname, strerror(errno));

	if ((b = sshbuf_new()) == NULL)
		fatal("%s: sshbuf_new failed", __progname);
	if (ssh_msg_recv(STDIN_FILENO, b) < 0)
		fatal("%s: ssh_msg_recv failed", __progname);
	if ((r = sshbuf_get_u8(b, &rver)) != 0)
		fatal_r(r, "%s: buffer error", __progname);
	if (rver != version)
		fatal("%s: bad version: received %d, expected %d",
		    __progname, rver, version);
	if ((r = sshbuf_get_u32(b, (u_int *)&fd)) != 0)
		fatal_r(r, "%s: buffer error", __progname);
	if (fd < 0 || fd == STDIN_FILENO || fd == STDOUT_FILENO)
		fatal("%s: bad fd = %d", __progname, fd);
	if ((host = get_local_name(fd)) == NULL)
		fatal("%s: cannot get local name for fd", __progname);

	if ((r = sshbuf_get_string(b, &data, &dlen)) != 0)
		fatal_r(r, "%s: buffer error", __progname);
	if (valid_request(pw, host, &key, &alg, data, dlen) < 0)
		fatal("%s: not a valid request", __progname);
	free(host);

	found = 0;
	for (i = 0; i < NUM_KEYTYPES; i++) {
		if (keys[i] != NULL &&
		    sshkey_equal_public(key, keys[i])) {
			found = 1;
			break;
		}
	}
	if (!found) {
		if ((fp = sshkey_fingerprint(key, options.fingerprint_hash,
		    SSH_FP_DEFAULT)) == NULL)
			fatal("%s: sshkey_fingerprint failed", __progname);
		fatal("%s: no matching hostkey found for key %s %s", __progname,
		    sshkey_type(key), fp ? fp : "");
	}

{	ssh_compat ctx_compat = { 0, 0 }; /* TODO-Xkey_sign compat */
	ssh_sign_ctx ctx = { alg, keys[i], &ctx_compat, NULL, NULL };

	if ((r = Xkey_sign(&ctx, &signature, &slen, data, dlen)) != 0)
		fatal_r(r, "%s: Xkey_sign failed", __progname);
}
	free(data);

	/* send reply */
	sshbuf_reset(b);
	if ((r = sshbuf_put_string(b, signature, slen)) != 0)
		fatal_r(r, "%s: buffer error", __progname);
	if (ssh_msg_send(STDOUT_FILENO, version, b) == -1)
		fatal("%s: ssh_msg_send failed", __progname);

	return (0);
}
