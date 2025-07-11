/* $OpenBSD: ssh-add.c,v 1.172 2024/01/11 01:45:36 djm Exp $ */
/*
 * Author: Tatu Ylonen <ylo@cs.hut.fi>
 * Copyright (c) 1995 Tatu Ylonen <ylo@cs.hut.fi>, Espoo, Finland
 *                    All rights reserved
 * Adds an identity to the authentication server, or removes an identity.
 *
 * As far as I am concerned, the code I have written for this software
 * can be used freely for any purpose.  Any derived versions of this
 * software must be clearly marked as such, and if the derived work is
 * incompatible with the protocol description in the RFC file, it must be
 * called by a name other than "ssh" or "Secure Shell".
 *
 * SSH2 implementation,
 * Copyright (c) 2000, 2001 Markus Friedl.  All rights reserved.
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
#include <sys/stat.h>

#include <errno.h>
#include <fcntl.h>
#include <pwd.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <limits.h>

#include "xmalloc.h"
#include "ssh.h"
#include "log.h"
#include "ssh-x509.h"
#include "ssh-xkalg.h"
#ifdef WITH_XMSS
# include "sshkey-xmss.h"
#endif
#include "compat.h"
#include "sshbuf.h"
#include "authfd.h"
#include "authfile.h"
#include "pathnames.h"
#include "misc.h"
#include "ssherr.h"
#include "digest.h"

/* argv0 */
extern char *__progname;

/* Default files to add */
static char *default_files[] = {
#ifdef WITH_OPENSSL
	_PATH_SSH_CLIENT_ID_RSA,
#ifdef OPENSSL_HAS_ECC
	_PATH_SSH_CLIENT_ID_ECDSA,
#endif
#endif /* WITH_OPENSSL */
	_PATH_SSH_CLIENT_ID_ED25519,
#ifdef WITH_OPENSSL
#ifdef WITH_DSA
	_PATH_SSH_CLIENT_ID_DSA,
#endif
#endif /* WITH_OPENSSL */
#ifdef WITH_XMSS
	_PATH_SSH_CLIENT_ID_XMSS,
#endif
	NULL
};

static int fingerprint_hash = SSH_FP_HASH_DEFAULT;

/* Default lifetime (0 == forever) */
static u_int lifetime = 0;
static int/*bool*/
set_lifetime(const char *val)
{	long t = convtime(val);
	if (t == -1) {
		fprintf(stderr, "Invalid lifetime\n");
		return 0;
	}
/* Note u_int32_t is size used in communication to agent
 * (see SSH_AGENT_CONSTRAIN_LIFETIME). */
#if SIZEOF_LONG_INT > SIZEOF_INT
	if (t > UINT32_MAX) {
		fprintf(stderr, "Lifetime too high\n");
		return 0;
	}
#endif
	lifetime = (u_int)t; /*safe cast*/
	return 1;
}

/* User has to confirm key use */
static int confirm = 0;

#ifdef WITH_XMSS
/* Maximum number of signatures (XMSS) */
static u_int maxsign = 0;
static u_int minleft = 0;
#else

# define maxsign	0
#endif

static inline u_int32_t
sshkey_signatures_left(const struct sshkey *k)
{
#ifdef WITH_XMSS
	if (sshkey_type_plain(k->type) == KEY_XMSS)
		return sshkey_xmss_signatures_left(k);
#else
	UNUSED(k);
#endif
	return 0;
}

/* we keep a cache of one passphrase */
static char *pass = NULL;
static void
clear_pass(void)
{
	if (pass) {
		freezero(pass, strlen(pass));
		pass = NULL;
	}
}

static int
delete_one(int agent_fd, const struct sshkey *key, const char *comment,
    const char *path, int qflag)
{
	int r;

	if ((r = ssh_remove_identity(agent_fd, key)) != 0) {
		fprintf(stderr, "Could not remove identity \"%s\": %s\n",
		    path, ssh_err(r));
		return r;
	}
	if (!qflag) {
		fprintf(stderr, "Identity removed: %s %s (%s)\n", path,
		    sshkey_type(key), comment ? comment : "no comment");
	}
	return 0;
}

static int
delete_stdin(int agent_fd, int qflag)
{
	char *line = NULL, *cp;
	size_t linesize = 0;
	struct sshkey *key = NULL;
	int lnum = 0, r, ret = -1;

	while (getline(&line, &linesize, stdin) != -1) {
		lnum++;
		line[strcspn(line, "\n")] = '\0';
		cp = line + strspn(line, " \t");
		if (*cp == '#' || *cp == '\0')
			continue;
		sshkey_free(key);
		if ((key = sshkey_new(KEY_UNSPEC)) == NULL)
			fatal_f("sshkey_new");
		if ((r = sshkey_read(key, &cp)) != 0) {
			error_r(r, "(stdin):%d: invalid key", lnum);
			continue;
		}
		if (delete_one(agent_fd, key, cp, "(stdin)", qflag) == 0)
			ret = 0;
	}
	sshkey_free(key);
	free(line);
	return ret;
}

static int
delete_file(int agent_fd, const char *filename, int key_only, int qflag)
{
	struct sshkey *public, *cert = NULL;
	char *certpath = NULL, *comment = NULL;
	int r, ret = -1;

	if (strcmp(filename, "-") == 0)
		return delete_stdin(agent_fd, qflag);

	if ((r = sshkey_load_public(filename, &public,  &comment)) != 0) {
		printf("Bad key file %s: %s\n", filename, ssh_err(r));
		return -1;
	}
	if (delete_one(agent_fd, public, comment, filename, qflag) == 0)
		ret = 0;

	if (key_only)
		goto out;

	/* Now try to delete the corresponding certificate too */
	free(comment);
	comment = NULL;
	xasprintf(&certpath, "%s-cert.pub", filename);
	if ((r = sshkey_load_public(certpath, &cert, &comment)) != 0) {
		if (r != SSH_ERR_SYSTEM_ERROR || errno != ENOENT)
			error_r(r, "Failed to load certificate \"%s\"", certpath);
		goto out;
	}

	if (!sshkey_equal_public(cert, public))
		fatal("Certificate %s does not match private key %s",
		    certpath, filename);

	if (delete_one(agent_fd, cert, comment, certpath, qflag) == 0)
		ret = 0;

 out:
	sshkey_free(cert);
	sshkey_free(public);
	free(certpath);
	free(comment);

	return ret;
}

/* Send a request to remove all identities. */
static int
delete_all(int agent_fd, int qflag)
{
	int ret = -1;

	/*
	 * Since the agent might be forwarded, old or non-OpenSSH, when asked
	 * to remove all keys, attempt to remove both protocol v.1 and v.2
	 * keys.
	 */
	if (ssh_remove_all_identities(agent_fd, 2) == 0)
		ret = 0;
	/* ignore error-code for ssh1 */
	ssh_remove_all_identities(agent_fd, 1);

	if (ret != 0)
		fprintf(stderr, "Failed to remove all identities.\n");
	else if (!qflag)
		fprintf(stderr, "All identities removed.\n");

	return ret;
}

static int
add_file(int agent_fd, const char *filename, int key_only, int qflag,
    const char *skprovider)
{
	struct sshkey *private, *cert;
	char *comment = NULL;
	char msg[1024], *certpath = NULL;
	int r, fd, ret = -1;
	struct sshbuf *keyblob;

	if (strcmp(filename, "-") == 0) {
		fd = STDIN_FILENO;
		filename = "(stdin)";
	} else if ((fd = open(filename, O_RDONLY)) == -1) {
		perror(filename);
		return -1;
	}

	/*
	 * Since we'll try to load a keyfile multiple times, permission errors
	 * will occur multiple times, so check perms first and bail if wrong.
	 */
	if (fd != STDIN_FILENO) {
		if (sshkey_perm_ok(fd, filename) != 0) {
			close(fd);
			return -1;
		}
	}
	if ((r = sshbuf_load_fd(fd, &keyblob)) != 0) {
		fprintf(stderr, "Error loading key \"%s\": %s\n",
		    filename, ssh_err(r));
		sshbuf_free(keyblob);
		close(fd);
		return -1;
	}
	close(fd);

	/* At first, try empty passphrase */
	if ((r = sshkey_parse_private_fileblob(keyblob, "", &private,
	    &comment)) != 0 && r != SSH_ERR_KEY_WRONG_PASSPHRASE) {
		fprintf(stderr, "Error loading key \"%s\": %s\n",
		    filename, ssh_err(r));
		goto fail_load;
	}
	/* try last */
	if (private == NULL && pass != NULL) {
		if ((r = sshkey_parse_private_fileblob(keyblob, pass, &private,
		    &comment)) != 0 && r != SSH_ERR_KEY_WRONG_PASSPHRASE) {
			fprintf(stderr, "Error loading key \"%s\": %s\n",
			    filename, ssh_err(r));
			goto fail_load;
		}
	}
	if (private == NULL) {
		/* clear passphrase since it did not work */
		clear_pass();
		snprintf(msg, sizeof msg, "Enter passphrase for %s%s: ",
		    filename, confirm ? " (will confirm each use)" : "");
		for (;;) {
			pass = read_passphrase(msg, RP_ALLOW_STDIN);
			if (strcmp(pass, "") == 0)
				goto fail_load;
			if ((r = sshkey_parse_private_fileblob(keyblob, pass,
			    &private, &comment)) == 0)
				break;
			else if (r != SSH_ERR_KEY_WRONG_PASSPHRASE) {
				fprintf(stderr,
				    "Error loading key \"%s\": %s\n",
				    filename, ssh_err(r));
 fail_load:
				clear_pass();
				sshbuf_free(keyblob);
				return -1;
			}
			clear_pass();
			snprintf(msg, sizeof msg,
			    "Bad passphrase, try again for %s%s: ", filename,
			    confirm ? " (will confirm each use)" : "");
		}
	}
	if (comment == NULL || *comment == '\0')
		comment = xstrdup(filename);
	sshbuf_free(keyblob);

	/* For XMSS */
	if ((r = sshkey_set_filename(private, filename)) != 0) {
		fprintf(stderr, "Could not add filename to private key: %s (%s)\n",
		    filename, comment);
		goto out;
	}
#ifdef WITH_XMSS
{
	struct ssh_identitylist *idlist;

	if (maxsign && minleft &&
	    (r = ssh_fetch_identitylist(agent_fd, &idlist)) == 0) {
		size_t i;
		for (i = 0; i < idlist->nkeys; i++) {
			u_int left;
			if (!sshkey_equal_public(idlist->keys[i], private))
				continue;
			left = sshkey_signatures_left(idlist->keys[i]);
			if (left < minleft) {
				fprintf(stderr,
				    "Only %u signatures left.\n", left);
				break;
			}
			fprintf(stderr, "Skipping update: ");
			if (left == minleft) {
				fprintf(stderr,
				    "required signatures left (%u).\n", left);
			} else {
				fprintf(stderr,
				    "more signatures left (%u) than"
				    " required (%u).\n", left, minleft);
			}
			ssh_free_identitylist(idlist);
			goto out;
		}
		ssh_free_identitylist(idlist);
	}
}
#endif /*def WITH_XMSS*/

	if ((r = ssh_add_identity_constrained(agent_fd, private, comment,
	    lifetime, confirm, maxsign, skprovider)) == 0) {
		ret = 0;
		if (!qflag) {
			fprintf(stderr, "Identity added: %s (%s)\n",
			    filename, comment);
			if (lifetime != 0) {
				fprintf(stderr,
				    "Lifetime set to %u seconds\n", lifetime);
			}
			if (confirm != 0) {
				fprintf(stderr, "The user must confirm "
				    "each use of the key\n");
			}
		}
	} else {
		fprintf(stderr, "Could not add identity \"%s\": %s\n",
		    filename, ssh_err(r));
	}

	/* Skip trying to load the cert if requested */
	if (key_only)
		goto out;

	/* Now try to add the certificate flavour too */
	xasprintf(&certpath, "%s-cert.pub", filename);
	if ((r = sshkey_load_public(certpath, &cert, NULL)) != 0) {
		if (r != SSH_ERR_SYSTEM_ERROR || errno != ENOENT)
			error_r(r, "Failed to load certificate \"%s\"", certpath);
		goto out;
	}

	if (!sshkey_equal_public(cert, private)) {
		error("Certificate %s does not match private key %s",
		    certpath, filename);
		sshkey_free(cert);
		goto out;
	}

	/* Graft with private bits */
	if ((r = sshkey_to_certified(private)) != 0) {
		error_fr(r, "sshkey_to_certified");
		sshkey_free(cert);
		goto out;
	}
	if ((r = sshkey_cert_copy(cert, private)) != 0) {
		error_fr(r, "sshkey_cert_copy");
		sshkey_free(cert);
		goto out;
	}
	sshkey_free(cert);

	if ((r = ssh_add_identity_constrained(agent_fd, private, comment,
	    lifetime, confirm, maxsign, skprovider)) != 0) {
		error_r(r, "Certificate %s (%s) add failed", certpath,
		    private->cert->key_id);
		goto out;
	}
	/* success */
	if (!qflag) {
		fprintf(stderr, "Certificate added: %s (%s)\n", certpath,
		    private->cert->key_id);
		if (lifetime != 0) {
			fprintf(stderr, "Lifetime set to %u seconds\n",
			    lifetime);
		}
		if (confirm != 0) {
			fprintf(stderr, "The user must confirm each use "
			    "of the key\n");
		}
	}

 out:
	free(certpath);
	free(comment);
	sshkey_free(private);

	return ret;
}

static int
update_card(int agent_fd, int add, const char *id, int qflag)
{
	char *pin = NULL;
	int r, ret = -1;

	if (add) {
		if ((pin = read_passphrase("Enter passphrase for PKCS#11: ",
		    RP_ALLOW_STDIN)) == NULL)
			return -1;
	}

	if ((r = ssh_update_card(agent_fd, add, id, pin == NULL ? "" : pin,
	    lifetime, confirm)) == 0) {
		ret = 0;
		if (!qflag) {
			fprintf(stderr, "Card %s: %s\n",
			    add ? "added" : "removed", id);
		}
	} else {
		fprintf(stderr, "Could not %s card \"%s\": %s\n",
		    add ? "add" : "remove", id, ssh_err(r));
		ret = -1;
	}
	free(pin);
	return ret;
}

static int
test_key(int agent_fd, const char *filename)
{
	struct sshkey *key = NULL;
	u_char *sig = NULL;
	size_t slen = 0;
	int r, ret = -1;
	char data[1024];
	const char *alg;
	ssh_compat ctx_compat = { 0, 0 };

	if ((r = sshkey_load_public(filename, &key, NULL)) != 0) {
		error_r(r, "Couldn't read public key %s", filename);
		return -1;
	}
	arc4random_buf(data, sizeof(data));

	alg = sshkey_ssh_name(key);
#ifdef HAVE_EVP_SHA256
	if (sshkey_type_plain(key->type) == KEY_RSA)
		alg = "rsa-sha2-256";
#endif

{	ssh_sign_ctx ctx = { alg, key, &ctx_compat, NULL, NULL };

	r = Xssh_agent_sign(agent_fd, &ctx, &sig, &slen, data, sizeof(data));
	if (r != 0) {
		error_r(r, "Agent signature failed for %s", filename);
		goto done;
	}
}
{	ssh_verify_ctx ctx = { alg, key, &ctx_compat };

	r = Xkey_verify(&ctx, sig, slen, data, sizeof(data));
	if (r != 0) {
		error_r(r, "Signature verification failed for %s", filename);
		goto done;
	}
}
	/* success */
	ret = 0;
 done:
	free(sig);
	sshkey_free(key);
	return ret;
}

static int
list_identities(int agent_fd, int do_fp, int key_only)
{
	char *fp;
	int r;
	struct ssh_identitylist *idlist;
	u_int32_t left;
	size_t i;

	if ((r = ssh_fetch_identitylist(agent_fd, &idlist)) != 0) {
		if (r != SSH_ERR_AGENT_NO_IDENTITIES)
			fprintf(stderr, "error fetching identities: %s\n",
			    ssh_err(r));
		else
			printf("The agent has no identities.\n");
		return -1;
	}
	for (i = 0; i < idlist->nkeys; i++) {
		if (do_fp) {
			fp = sshkey_fingerprint(idlist->keys[i],
			    fingerprint_hash, SSH_FP_DEFAULT);
			printf("%u %s %s (%s)\n", sshkey_size(idlist->keys[i]),
			    fp == NULL ? "(null)" : fp, idlist->comments[i],
			    sshkey_type(idlist->keys[i]));
			free(fp);
		} else {
			int print_dn = !key_only && sshkey_is_x509(idlist->keys[i]);
			if (print_dn) {
				if(!Xkey_write_subject(NULL,
				    idlist->keys[i], stdout)) {
					fprintf(stderr,
					    "Xkey_write_subject failed\n");
					continue;
				}
			} else
			if ((r = sshkey_write(idlist->keys[i], stdout)) != 0) {
				fprintf(stderr, "sshkey_write: %s\n",
				    ssh_err(r));
				continue;
			}
			if (!print_dn)
				fprintf(stdout, " %s", idlist->comments[i]);
			left = sshkey_signatures_left(idlist->keys[i]);
			if (left > 0)
				fprintf(stdout,
				    " [signatures left %d]", left);
			fprintf(stdout, "\n");
		}
	}
	ssh_free_identitylist(idlist);
	return 0;
}

static int
lock_agent(int agent_fd, int lock)
{
	char prompt[100], *p1, *p2;
	int r, passok = 1, ret = -1;

	strlcpy(prompt, "Enter lock password: ", sizeof(prompt));
	p1 = read_passphrase(prompt, RP_ALLOW_STDIN);
	if (lock) {
		strlcpy(prompt, "Again: ", sizeof prompt);
		p2 = read_passphrase(prompt, RP_ALLOW_STDIN);
		if (strcmp(p1, p2) != 0) {
			fprintf(stderr, "Passwords do not match.\n");
			passok = 0;
		}
		freezero(p2, strlen(p2));
	}
	if (passok) {
		if ((r = ssh_lock_agent(agent_fd, lock, p1)) == 0) {
			fprintf(stderr, "Agent %slocked.\n", lock ? "" : "un");
			ret = 0;
		} else {
			fprintf(stderr, "Failed to %slock agent: %s\n",
			    lock ? "" : "un", ssh_err(r));
		}
	}
	freezero(p1, strlen(p1));
	return (ret);
}

static int
do_file(int agent_fd, int deleting, int key_only, char *file, int qflag,
    const char *skprovider)
{
	if (deleting) {
		if (delete_file(agent_fd, file, key_only, qflag) == -1)
			return -1;
	} else {
		if (add_file(agent_fd, file, key_only, qflag, skprovider) == -1)
			return -1;
	}
	return 0;
}

static void
usage(void)
{
	fprintf(stderr,
"usage: ssh-add [-cDdkLlqvXx] [-E fingerprint_hash] [-t life]\n");
#ifdef WITH_XMSS
	fprintf(stderr,
"               [-M maxsign] [-m minleft]\n");
#endif
	fprintf(stderr,
"               [file ...]\n"
"       ssh-add -s pkcs11 -v\n"
"       ssh-add -e pkcs11 -v\n"
"       ssh-add -Tv pubkey ...\n"
	);
}

int
main(int argc, char **argv)
{
	extern char *optarg;
	extern int optind;
	int agent_fd;
	char *pkcs11provider = NULL, *skprovider = NULL;
	int r, i, ch, deleting = 0, ret = 0, key_only = 0;
	int xflag = 0, lflag = 0, Dflag = 0, qflag = 0, Tflag = 0;
	SyslogFacility log_facility = SYSLOG_FACILITY_AUTH;
	LogLevel log_level = SYSLOG_LEVEL_INFO;

	ssh_malloc_init();	/* must be called before any mallocs */
	/* Ensure that fds 0, 1 and 2 are open or directed to /dev/null */
	sanitise_stdfd();

	__progname = ssh_get_progname(argv[0]);
	ssh_OpenSSL_startup();
	fill_default_xkalg();

	log_init(__progname, SYSLOG_LEVEL_INFO, SYSLOG_FACILITY_USER, 1);

	seed_rng();

	log_init(__progname, log_level, log_facility, 1);

	setvbuf(stdout, NULL, _IOLBF, 0);

	/* First, get a connection to the authentication agent. */
	switch (r = ssh_get_authentication_socket(&agent_fd)) {
	case 0:
		break;
	case SSH_ERR_AGENT_NOT_PRESENT:
		fprintf(stderr, "Could not open a connection to your "
		    "authentication agent.\n");
		exit(2);
	default:
		fprintf(stderr, "Error connecting to agent: %s\n", ssh_err(r));
		exit(2);
	}

	while ((ch = getopt(argc, argv, "vklLcdDTxXE:e:M:m:qs:S:t:")) != -1) {
		switch (ch) {
		case 'v':
			if (log_level < SYSLOG_LEVEL_DEBUG1)
				log_level = SYSLOG_LEVEL_DEBUG1;
			else if (log_level < SYSLOG_LEVEL_DEBUG3)
				log_level++;
			break;
		case 'E':
			fingerprint_hash = ssh_digest_alg_by_name(optarg);
			if (fingerprint_hash == -1)
				fatal("Invalid hash algorithm \"%s\"", optarg);
			break;
		case 'k':
			key_only = 1;
			break;
		case 'l':
		case 'L':
			if (lflag != 0)
				fatal("-%c flag already specified", lflag);
			lflag = ch;
			break;
		case 'x':
		case 'X':
			if (xflag != 0)
				fatal("-%c flag already specified", xflag);
			xflag = ch;
			break;
		case 'c':
			confirm = 1;
			break;
	#ifdef WITH_XMSS
		case 'm':
			minleft = (u_int)strtonum(optarg, 1, UINT_MAX, NULL);
			if (minleft == 0) {
				usage();
				ret = 1;
				goto done;
			}
			break;
		case 'M':
			maxsign = (u_int)strtonum(optarg, 1, UINT_MAX, NULL);
			if (maxsign == 0) {
				usage();
				ret = 1;
				goto done;
			}
			break;
	#endif /*def WITH_XMSS*/
		case 'd':
			deleting = 1;
			break;
		case 'D':
			Dflag = 1;
			break;
		case 's':
			pkcs11provider = optarg;
			break;
		case 'e':
			deleting = 1;
			pkcs11provider = optarg;
			break;
		case 't':
			if (!set_lifetime(optarg)) {
				ret = 1;
				goto done;
			}
			break;
		case 'T':
			Tflag = 1;
			break;
		case 'q':
			qflag = 1;
			break;
		default:
			usage();
			ret = 1;
			goto done;
		}
	}
	log_init(__progname, log_level, log_facility, 1);

	if ((xflag != 0) + (lflag != 0) + (Dflag != 0) > 1)
		fatal("Invalid combination of actions");
	else if (xflag) {
		if (lock_agent(agent_fd, xflag == 'x' ? 1 : 0) == -1)
			ret = 1;
		goto done;
	} else if (lflag) {
		if (list_identities(agent_fd, lflag == 'l' ? 1 : 0, key_only) == -1)
			ret = 1;
		goto done;
	} else if (Dflag) {
		if (delete_all(agent_fd, qflag) == -1)
			ret = 1;
		goto done;
	}

	argc -= optind;
	argv += optind;
	if (Tflag) {
		if (argc <= 0)
			fatal("no keys to test");
		for (r = i = 0; i < argc; i++)
			r |= test_key(agent_fd, argv[i]);
		ret = r == 0 ? 0 : 1;
		goto done;
	}
	if (pkcs11provider != NULL) {
		if (update_card(agent_fd, !deleting, pkcs11provider,
		    qflag) == -1)
			ret = 1;
		goto done;
	}
	if (argc == 0) {
		char buf[PATH_MAX];
		struct passwd *pw;
		struct stat st;
		int count = 0;

		if ((pw = getpwuid(getuid())) == NULL) {
			fprintf(stderr, "No user found with uid %u\n",
			    (u_int)getuid());
			ret = 1;
			goto done;
		}

		for (i = 0; default_files[i]; i++) {
			snprintf(buf, sizeof(buf), "%s/%s", pw->pw_dir,
			    default_files[i]);
			if (stat(buf, &st) == -1)
				continue;
			if (do_file(agent_fd, deleting, key_only, buf,
			    qflag, skprovider) == -1)
				ret = 1;
			else
				count++;
		}
		if (count == 0)
			ret = 1;
	} else {
		for (i = 0; i < argc; i++) {
			if (do_file(agent_fd, deleting, key_only,
			    argv[i], qflag, skprovider) == -1)
				ret = 1;
		}
	}
	clear_pass();

done:
	ssh_close_authentication_socket(agent_fd);
	return ret;
}
