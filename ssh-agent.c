/* $OpenBSD: ssh-agent.c,v 1.308 2024/10/24 03:15:47 djm Exp $ */
/*
 * Author: Tatu Ylonen <ylo@cs.hut.fi>
 * Copyright (c) 1995 Tatu Ylonen <ylo@cs.hut.fi>, Espoo, Finland
 *                    All rights reserved
 * The authentication agent program.
 *
 * As far as I am concerned, the code I have written for this software
 * can be used freely for any purpose.  Any derived versions of this
 * software must be clearly marked as such, and if the derived work is
 * incompatible with the protocol description in the RFC file, it must be
 * called by a name other than "ssh" or "Secure Shell".
 *
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

#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/socket.h>
#ifdef HAVE_SYS_TIME_H
# include <sys/time.h>
#endif
#ifdef HAVE_SYS_UN_H
# include <sys/un.h>
#endif
#include "openbsd-compat/sys-queue.h"

#ifdef WITH_OPENSSL
#include <openssl/evp.h>
#include "evp-compat.h"
#ifdef HAVE_FIPSCHECK_H
#  include <fipscheck.h>
#endif
#endif

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#ifdef HAVE_PATHS_H
# include <paths.h>
#endif
#ifdef HAVE_POLL_H
# include <poll.h>
#else
# ifdef HAVE_SYS_POLL_H
#  include <sys/poll.h>
# endif
#endif
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>
#include <unistd.h>
#ifdef HAVE_UTIL_H
# include <util.h>
#endif

#include "xmalloc.h"
#include "ssh.h"
#include "sshbuf.h"
#include "ssh-x509.h"
#include "ssh-xkalg.h"
#ifdef WITH_XMSS
# include "sshkey-xmss.h"
#endif
#include "authfd.h"
#include "compat.h"
#include "log.h"
#include "misc.h"
#include "digest.h"
#include "ssherr.h"
#include "match.h"
#include "ssh-pkcs11.h"

#ifndef DEFAULT_ALLOWED_PROVIDERS
# define DEFAULT_ALLOWED_PROVIDERS "!*"
#endif

/* Maximum accepted message length */
#define AGENT_MAX_LEN	(256*1024)
/* Maximum bytes to read from client socket */
#define AGENT_RBUF_LEN	(4096)

typedef enum {
	AUTH_UNUSED = 0,
	AUTH_SOCKET = 1,
	AUTH_CONNECTION = 2,
} sock_type;

typedef struct socket_entry {
	int fd;
	sock_type type;
	struct sshbuf *input;
	struct sshbuf *output;
	struct sshbuf *request;
} SocketEntry;

u_int sockets_alloc = 0;
SocketEntry *sockets = NULL;

typedef struct identity {
	TAILQ_ENTRY(identity) next;
	struct sshkey *key;
	char *comment;
	char *provider;
	time_t death;
	u_int confirm;
} Identity;

struct idtable {
	int nentries;
	TAILQ_HEAD(idqueue, identity) idlist;
};

/* private key table */
struct idtable *idtab;

int max_fd = 0;

/* pid of shell == parent of agent */
pid_t parent_pid = -1;
time_t parent_alive_interval = 0;

static volatile sig_atomic_t signalled_exit = 0;
static volatile sig_atomic_t signalled_keydrop = 0;

/* pid of process for which cleanup_socket is applicable */
pid_t cleanup_pid = 0;

/* pathname and directory for AUTH_SOCKET */
char socket_name[PATH_MAX];
char socket_dir[PATH_MAX];

/* Pattern-list of allowed PKCS#11 paths */
static char *allowed_providers = NULL;

/* locking */
#define LOCK_SIZE	32
#define LOCK_SALT_SIZE	16
#define LOCK_ROUNDS	1
int locked = 0;
u_char lock_pwhash[LOCK_SIZE];
u_char lock_salt[LOCK_SALT_SIZE];

extern char *__progname;

/* Default lifetime in seconds (0 == forever) */
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

static int fingerprint_hash = SSH_FP_HASH_DEFAULT;

static inline int
sshkey_enable_maxsign(struct sshkey *k, u_int32_t maxsign)
{
#ifdef WITH_XMSS
	if (sshkey_type_plain(k->type) == KEY_XMSS)
		return sshkey_xmss_enable_maxsign(k, maxsign);
#else
	UNUSED(k);
	UNUSED(maxsign);
#endif
	return SSH_ERR_INVALID_ARGUMENT;
}

static void
close_socket(SocketEntry *e)
{
	close(e->fd);
	sshbuf_free(e->input);
	sshbuf_free(e->output);
	sshbuf_free(e->request);
	memset(e, '\0', sizeof(*e));
	e->fd = -1;
	e->type = AUTH_UNUSED;
}

static void
idtab_init(void)
{
	idtab = xcalloc(1, sizeof(*idtab));
	TAILQ_INIT(&idtab->idlist);
	idtab->nentries = 0;
}

static void
free_identity(Identity *id)
{
	sshkey_free(id->key);
	free(id->provider);
	free(id->comment);
	free(id);
}

static int/*bool*/
key_match(const struct sshkey *key, struct sshkey *found) {
	return sshkey_is_x509(found)
		? sshkey_equal_public(key, found)
		: sshkey_equal(key, found);
}

/* return matching private key for given public key */
static Identity *
lookup_identity(struct sshkey *key)
{
	Identity *id;

	TAILQ_FOREACH(id, &idtab->idlist, next) {
		if (key_match(key, id->key))
			return (id);
	}
	return (NULL);
}

/* Check confirmation of keysign request */
static int
confirm_key(Identity *id, const char *extra)
{
	char *p;
	int ret = -1;

	p = sshkey_fingerprint(id->key, fingerprint_hash, SSH_FP_DEFAULT);
	if (p != NULL &&
	    ask_permission("Allow use of key %s?\nKey fingerprint %s.%s%s",
	    id->comment, p,
	    extra == NULL ? "" : "\n", extra == NULL ? "" : extra))
		ret = 0;
	free(p);

	return (ret);
}

static void
send_status(SocketEntry *e, int success)
{
	int r;

	if ((r = sshbuf_put_u32(e->output, 1)) != 0 ||
	    (r = sshbuf_put_u8(e->output, success ?
	    SSH_AGENT_SUCCESS : SSH_AGENT_FAILURE)) != 0)
		fatal_fr(r, "compose");
}

/* send list of supported public keys to 'client' */
static void
process_request_identities(SocketEntry *e)
{
	Identity *id;
	struct sshbuf *msg;
	int r;

	if ((msg = sshbuf_new()) == NULL)
		fatal_f("sshbuf_new failed");
	if ((r = sshbuf_put_u8(msg, SSH2_AGENT_IDENTITIES_ANSWER)) != 0 ||
	    (r = sshbuf_put_u32(msg, idtab->nentries)) != 0)
		fatal_fr(r, "compose");
	TAILQ_FOREACH(id, &idtab->idlist, next) {
		if ((r = Akey_puts_opts(id->key, msg, SSHKEY_SERIALIZE_INFO)) != 0 ||
		    (r = sshbuf_put_cstring(msg, id->comment)) != 0) {
			error_fr(r, "compose key/comment");
			continue;
		}
	}
	if ((r = sshbuf_put_stringb(e->output, msg)) != 0)
		fatal_fr(r, "enqueue");
	sshbuf_free(msg);
}


static const char*
agent_recode_alg(const char *pkalg, u_int flags)
{
#ifdef HAVE_EVP_SHA256
	if (strcmp(pkalg, "ssh-rsa") == 0) {
		if (flags & SSH_AGENT_RSA_SHA2_256)
			return "rsa-sha2-256";
		if (flags & SSH_AGENT_RSA_SHA2_512)
			return "rsa-sha2-512";
	}
#else
	UNUSED(flags);
#endif /*def HAVE_EVP_SHA256*/
	return pkalg;
}

/* ssh2 only */
static void
process_sign_request2(SocketEntry *e)
{
	const u_char *data;
	u_char *signature = NULL;
	size_t dlen, slen = 0;
	ssh_compat ctx_compat = { 0, 0 };
	u_int flags;
	int r, ok = -1;
	struct sshbuf *msg;
	struct sshkey *key = NULL;
	char *pkalg = NULL;
	struct identity *id;

	if ((msg = sshbuf_new()) == NULL)
		fatal_f("sshbuf_new failed");

{	u_char *blob = NULL;
	size_t blen;

	if ((r = sshbuf_get_string(e->request, &blob, &blen)) != 0 ||
	    (r = parse_key_from_blob(blob, blen, &key, &pkalg)) != 0) {
		free(blob);
		error_fr(r, "parse key");
		goto send;
	}
	free(blob);
}
	if (
	    (r = sshbuf_get_string_direct(e->request, &data, &dlen)) != 0 ||
	    (r = sshbuf_get_u32(e->request, &flags)) != 0) {
		error_fr(r, "parse");
		goto send;
	}

	if (flags & SSH_AGENT_RFC6187_OPAQUE_ECDSA_SIGNATURE)
		ctx_compat.extra = SSHX_RFC6187_ASN1_OPAQUE_ECDSA_SIGNATURE;
	if ((id = lookup_identity(key)) == NULL) {
		error_f("%s key not found", sshkey_type(key));
		goto send;
	}
	if (id->confirm && confirm_key(id, NULL) != 0) {
		debug_f("user refused key");
		goto send;
	}
{	const char *alg = agent_recode_alg(pkalg, flags);
	ssh_sign_ctx ctx = { alg, id->key, &ctx_compat, NULL, NULL };

	r = Xkey_sign(&ctx, &signature, &slen, data, dlen);
}
	if (r != 0) {
		error_fr(r, "Xkey_sign");
		goto send;
	}
	/* Success */
	ok = 0;
 send:
	free(pkalg);
	sshkey_free(key);
	if (ok == 0) {
		if ((r = sshbuf_put_u8(msg, SSH2_AGENT_SIGN_RESPONSE)) != 0 ||
		    (r = sshbuf_put_string(msg, signature, slen)) != 0)
			fatal_fr(r, "compose");
	} else if ((r = sshbuf_put_u8(msg, SSH_AGENT_FAILURE)) != 0)
		fatal_fr(r, "compose failure");

	if ((r = sshbuf_put_stringb(e->output, msg)) != 0)
		fatal_fr(r, "enqueue");

	sshbuf_free(msg);
	free(signature);
}

/* shared */
static void
process_remove_identity(SocketEntry *e)
{
	int r, success = 0;
	struct sshkey *key = NULL;
	Identity *id;

	if ((r = Akey_gets(e->request, &key)) != 0) {
		error_fr(r, "get key");
		goto done;
	}
	if ((id = lookup_identity(key)) == NULL) {
		debug_f("key not found");
		goto done;
	}
	/* We have this key, free it. */
	if (idtab->nentries < 1)
		fatal_f("internal error: nentries %d", idtab->nentries);
	TAILQ_REMOVE(&idtab->idlist, id, next);
	free_identity(id);
	idtab->nentries--;
	success = 1;
 done:
	sshkey_free(key);
	send_status(e, success);
}

static void
remove_all_identities(void)
{
	Identity *id;

	/* Loop over all identities and clear the keys. */
	for (id = TAILQ_FIRST(&idtab->idlist); id;
	    id = TAILQ_FIRST(&idtab->idlist)) {
		TAILQ_REMOVE(&idtab->idlist, id, next);
		free_identity(id);
	}

	/* Mark that there are no identities. */
	idtab->nentries = 0;
}

static void
process_remove_all_identities(SocketEntry *e)
{
	remove_all_identities();

	/* Send success. */
	send_status(e, 1);
}

/* removes expired keys and returns number of seconds until the next expiry */
static time_t
reaper(void)
{
	time_t deadline = 0, now = monotime();
	Identity *id, *nxt;

	for (id = TAILQ_FIRST(&idtab->idlist); id; id = nxt) {
		nxt = TAILQ_NEXT(id, next);
		if (id->death == 0)
			continue;
		if (now >= id->death) {
			debug("expiring key '%s'", id->comment);
			TAILQ_REMOVE(&idtab->idlist, id, next);
			free_identity(id);
			idtab->nentries--;
		} else
			deadline = (deadline == 0) ? id->death :
			    MINIMUM(deadline, id->death);
	}
	if (deadline == 0 || deadline <= now)
		return 0;
	else
		return (deadline - now);
}

static int
parse_key_constraint_sk_provider(struct sshbuf *m, char *ext_name,
    int *sk_provider_set, char **sk_providerp)
{
	int r;

	if (strcmp(ext_name, "sk-provider@openssh.com") != 0)
		return SSH_ERR_FEATURE_UNSUPPORTED;

	if (sk_providerp == NULL) {
		error_f("%s not valid here", ext_name);
		return SSH_ERR_INVALID_ARGUMENT;
	}
	if (*sk_provider_set) {
		error_f("%s already set", ext_name);
		return SSH_ERR_INVALID_ARGUMENT;
	}

	r = sshbuf_get_cstring(m, sk_providerp, NULL);
	if (r != 0) {
		error_fr(r, "parse %s", ext_name);
		return r;
	}

	*sk_provider_set = 1;
	return 0;
}

static int
parse_key_constraints(struct sshbuf *m, struct sshkey *k,
    u_int *secondsp, int *confirmp, char **sk_providerp)
{
	int r;
	int lifetime_set = 0, confirm_set = 0;
	int maxsign_set = 0, sk_provider_set = 0;

	while (sshbuf_len(m)) {
		u_char ctype;
		if ((r = sshbuf_get_u8(m, &ctype)) != 0) {
			error_fr(r, "parse constraint type");
			goto out;
		}
		switch (ctype) {
		case SSH_AGENT_CONSTRAIN_LIFETIME: {
			u_int32_t seconds;

			if (secondsp == NULL) {
				error_f("lifetime not valid here");
				r = SSH_ERR_INVALID_ARGUMENT;
				goto out;
			}
			if (lifetime_set) {
				error_f("lifetime already set");
				r = SSH_ERR_INVALID_ARGUMENT;
				goto out;
			}
			if ((r = sshbuf_get_u32(m, &seconds)) != 0) {
				error_fr(r, "parse lifetime constraint");
				goto out;
			}
			lifetime_set = 1;
			*secondsp = seconds;
			} break;
		case SSH_AGENT_CONSTRAIN_CONFIRM:
			if (confirm_set) {
				error_f("confirm already set");
				r = SSH_ERR_INVALID_ARGUMENT;
				goto out;
			}
			confirm_set = 1;
			*confirmp = 1;
			break;
		case SSH_AGENT_CONSTRAIN_MAXSIGN: {
			u_int32_t maxsign;

			if (k == NULL) {
				error_f("maxsign not valid here");
				r = SSH_ERR_INVALID_ARGUMENT;
				goto out;
			}
			if (maxsign_set) {
				error_f("maxsign already set");
				r = SSH_ERR_INVALID_ARGUMENT;
				goto out;
			}
			if ((r = sshbuf_get_u32(m, &maxsign)) != 0) {
				error_fr(r, "parse maxsign constraint");
				goto out;
			}
			maxsign_set = 1;
			/* same as ssh-add */
			if (maxsign == 0) {
				error_f("non alloved maxsign value");
				r = SSH_ERR_INVALID_ARGUMENT;
				goto out;
			}
			if ((r = sshkey_enable_maxsign(k, maxsign)) != 0) {
				error_fr(r, "enable maxsign");
				goto out;
			}
			} break;
		case SSH_AGENT_CONSTRAIN_EXTENSION: {
			char *ext_name;

			if ((r = sshbuf_get_cstring(m, &ext_name, NULL)) != 0) {
				error_fr(r, "parse constraint extension");
				goto out;
			}
			debug_f("constraint ext %s", ext_name);

			r = parse_key_constraint_sk_provider(m, ext_name,
			    &sk_provider_set, sk_providerp);

			if (r == SSH_ERR_FEATURE_UNSUPPORTED)
				error_f("unsupported constraint \"%s\"", ext_name);
			free(ext_name);
			if (r != 0) goto out;
			} break;
		default:
			error_f("unknown constraint %d", ctype);
			r = SSH_ERR_FEATURE_UNSUPPORTED;
			goto out;
		}
	}
	/* success */
	r = 0;
 out:
	return r;
}

static void
process_add_identity(SocketEntry *e)
{
	int success = 0, confirm = 0;
	char *comment = NULL, *sk_provider = NULL;
	u_int seconds = 0;
	time_t death = 0;
	struct sshkey *k = NULL;
	int r;

	if ((r = sshkey_private_deserialize(e->request, &k)) != 0 ||
	    k == NULL ||
	    (r = sshbuf_get_cstring(e->request, &comment, NULL)) != 0) {
		error_fr(r, "parse");
		goto out;
	}
	if (parse_key_constraints(e->request, k, &seconds, &confirm,
	    &sk_provider) != 0) {
		/* error already logged */
		sshbuf_reset(e->request);
		goto out;
	}
	if ((r = sshkey_shield_private(k)) != 0) {
		error_fr(r, "shield private");
		goto out;
	}
	if (lifetime != 0 || seconds != 0) {
		u_int timeoffset = seconds != 0 ? seconds : lifetime;
		death = monotime();
		if (death > (time_t)(death + timeoffset)) {
			debug3_f("now lifetime is too high");
			/* forever */
			death = 0;
		} else
			death += timeoffset;
	}
{	Identity *id = lookup_identity(k);
	if (id == NULL) {
		id = xcalloc(1, sizeof(Identity));
		TAILQ_INSERT_TAIL(&idtab->idlist, id, next);
		/* Increment the number of identities. */
		idtab->nentries++;
	} else {
		/* key state might have been updated */
		sshkey_free(id->key);
		free(id->comment);
	}
	/* success */
	id->key = k;
	id->comment = comment;
	id->death = death;
	id->confirm = confirm;
	free(sk_provider); /*TODO*/
}
	/* transferred */
	k = NULL;
	comment = NULL;
	sk_provider = NULL;
	success = 1;
 out:
	free(sk_provider);
	free(comment);
	sshkey_free(k);
	send_status(e, success);
}

/* XXX todo: encrypt sensitive data with passphrase */
static void
process_lock_agent(SocketEntry *e, int lock)
{
	int r, success = 0, delay;
	char *passwd;
	u_char passwdhash[LOCK_SIZE];
	static u_int fail_count = 0;
	size_t pwlen;

	/*
	 * This is deliberately fatal: the user has requested that we lock,
	 * but we can't parse their request properly. The only safe thing to
	 * do is abort.
	 */
	if ((r = sshbuf_get_cstring(e->request, &passwd, &pwlen)) != 0)
		fatal_fr(r, "parse");
	if (pwlen == 0) {
		debug("empty password not supported");
	} else if (locked && !lock) {
		if (bcrypt_pbkdf(passwd, pwlen, lock_salt, sizeof(lock_salt),
		    passwdhash, sizeof(passwdhash), LOCK_ROUNDS) < 0)
			fatal("bcrypt_pbkdf");
		if (timingsafe_bcmp(passwdhash, lock_pwhash, LOCK_SIZE) == 0) {
			debug("agent unlocked");
			locked = 0;
			fail_count = 0;
			explicit_bzero(lock_pwhash, sizeof(lock_pwhash));
			success = 1;
		} else {
			/* delay in 0.1s increments up to 10s */
			if (fail_count < 100)
				fail_count++;
			delay = 100000 * fail_count;
			debug("unlock failed, delaying %0.1lf seconds",
			    (double)delay/1000000);
			usleep(delay);
		}
		explicit_bzero(passwdhash, sizeof(passwdhash));
	} else if (!locked && lock) {
		debug("agent locked");
		locked = 1;
		arc4random_buf(lock_salt, sizeof(lock_salt));
		if (bcrypt_pbkdf(passwd, pwlen, lock_salt, sizeof(lock_salt),
		    lock_pwhash, sizeof(lock_pwhash), LOCK_ROUNDS) < 0)
			fatal("bcrypt_pbkdf");
		success = 1;
	}
	freezero(passwd, pwlen);
	send_status(e, success);
}

static void
no_identities(SocketEntry *e)
{
	struct sshbuf *msg;
	int r;

	if ((msg = sshbuf_new()) == NULL)
		fatal_f("sshbuf_new failed");
	if ((r = sshbuf_put_u8(msg, SSH2_AGENT_IDENTITIES_ANSWER)) != 0 ||
	    (r = sshbuf_put_u32(msg, 0)) != 0 ||
	    (r = sshbuf_put_stringb(e->output, msg)) != 0)
		fatal_fr(r, "compose");
	sshbuf_free(msg);
}

#ifdef ENABLE_PKCS11
static void
process_add_smartcard_key(SocketEntry *e)
{
	char *provider = NULL, *pin = NULL, canonical_provider[PATH_MAX];
	int r, success = 0, confirm = 0;
	time_t death = 0;

	if ((r = sshbuf_get_cstring(e->request, &provider, NULL)) != 0 ||
	    (r = sshbuf_get_cstring(e->request, &pin, NULL)) != 0) {
		error_fr(r, "parse");
		goto send;
	}
	if (parse_key_constraints(e->request, NULL, NULL, &confirm,
	    NULL) != 0) {
		/* error already logged */
		sshbuf_reset(e->request);
		goto send;
	}
	if (realpath(provider, canonical_provider) == NULL) {
		verbose("failed PKCS#11 add of \"%.100s\": realpath: %s",
		    provider, strerror(errno));
		goto send;
	}
	if (match_pattern_list(canonical_provider, allowed_providers, 0) != 1) {
		verbose("refusing PKCS#11 add of \"%.100s\": "
		    "provider not allowed", canonical_provider);
		goto send;
	}
	debug_f("add %.100s", canonical_provider);
	if (lifetime != 0) {
		death = monotime();
		if (death > (time_t)(death + lifetime)) {
			debug3_f("now lifetime is too high");
			/* forever */
			death = 0;
		} else
			death += lifetime;
	}

{
	int i, count;
	struct sshkey **keys;
	char **comments;

	count = pkcs11_add_provider(canonical_provider, pin, &keys, &comments);
	for (i = 0; i < count; i++) {
		struct sshkey *k = keys[i];
		Identity *id;

		if (lookup_identity(k) != NULL) {
			sshkey_free(keys[i]);
			free(comments[i]);
			continue;
		}

		id = xcalloc(1, sizeof(Identity));
		id->key = k;
		id->provider = xstrdup(canonical_provider);
		id->comment = comments[i];
		id->death = death;
		id->confirm = confirm;
		TAILQ_INSERT_TAIL(&idtab->idlist, id, next);
		idtab->nentries++;
		success = 1;
	}
	free(keys);
	free(comments);
}
send:
	if (pin != NULL)
		freezero(pin, strlen(pin));
	free(provider);
	send_status(e, success);
}

static void
process_remove_smartcard_key(SocketEntry *e)
{
	char *provider = NULL, *pin = NULL, canonical_provider[PATH_MAX];
	int r, success = 0;
	Identity *id, *nxt;

	if ((r = sshbuf_get_cstring(e->request, &provider, NULL)) != 0 ||
	    (r = sshbuf_get_cstring(e->request, &pin, NULL)) != 0) {
		error_fr(r, "parse");
		goto send;
	}
	free(pin);

	if (realpath(provider, canonical_provider) == NULL) {
		verbose("failed PKCS#11 add of \"%.100s\": realpath: %s",
		    provider, strerror(errno));
		goto send;
	}

	debug_f("remove %.100s", canonical_provider);
	for (id = TAILQ_FIRST(&idtab->idlist); id; id = nxt) {
		nxt = TAILQ_NEXT(id, next);
		/* Skip file--based keys */
		if (id->provider == NULL)
			continue;
		if (!strcmp(canonical_provider, id->provider)) {
			TAILQ_REMOVE(&idtab->idlist, id, next);
			free_identity(id);
			idtab->nentries--;
		}
	}
	if (pkcs11_del_provider(canonical_provider) == 0)
		success = 1;
	else
		error_f("pkcs11_del_provider failed");
send:
	free(provider);
	send_status(e, success);
}
#endif /* ENABLE_PKCS11 */

/*
 * dispatch incoming message.
 * returns 1 on success, 0 for incomplete messages or -1 on error.
 */
static int
process_message(u_int socknum)
{
	u_int msg_len;
	u_char type;
	const u_char *cp;
	int r;
	SocketEntry *e;

	if (socknum >= sockets_alloc)
		fatal_f("sock %u >= allocated %u", socknum, sockets_alloc);
	e = &sockets[socknum];

	if (sshbuf_len(e->input) < 5)
		return 0;		/* Incomplete message header. */
	cp = sshbuf_ptr(e->input);
	msg_len = PEEK_U32(cp);
	if (msg_len > AGENT_MAX_LEN) {
		debug_f("socket %u (fd=%d) message too long %u > %u",
		    socknum, e->fd, msg_len, AGENT_MAX_LEN);
		return -1;
	}
	if (sshbuf_len(e->input) < msg_len + 4)
		return 0;		/* Incomplete message body. */

	/* move the current input to e->request */
	sshbuf_reset(e->request);
	if ((r = sshbuf_get_stringb(e->input, e->request)) != 0 ||
	    (r = sshbuf_get_u8(e->request, &type)) != 0) {
		if (r == SSH_ERR_MESSAGE_INCOMPLETE ||
		    r == SSH_ERR_STRING_TOO_LARGE) {
			error_fr(r, "parse");
			return -1;
		}
		fatal_fr(r, "parse");
	}

	debug_f("socket %u (fd=%d) type %d", socknum, e->fd, type);

	/* check whether agent is locked */
	if (locked && type != SSH_AGENTC_UNLOCK) {
		sshbuf_reset(e->request);
		switch (type) {
		case SSH2_AGENTC_REQUEST_IDENTITIES:
			/* send empty lists */
			no_identities(e);
			break;
		default:
			/* send a fail message for all other request types */
			send_status(e, 0);
		}
		return 1;
	}

	switch (type) {
	case SSH_AGENTC_LOCK:
	case SSH_AGENTC_UNLOCK:
		process_lock_agent(e, type == SSH_AGENTC_LOCK);
		break;
	case SSH_AGENTC_REMOVE_ALL_RSA_IDENTITIES:
		process_remove_all_identities(e); /* safe for !WITH_SSH1 */
		break;
	/* ssh2 */
	case SSH2_AGENTC_SIGN_REQUEST:
		process_sign_request2(e);
		break;
	case SSH2_AGENTC_REQUEST_IDENTITIES:
		process_request_identities(e);
		break;
	case SSH2_AGENTC_ADD_IDENTITY:
	case SSH2_AGENTC_ADD_ID_CONSTRAINED:
		process_add_identity(e);
		break;
	case SSH2_AGENTC_REMOVE_IDENTITY:
		process_remove_identity(e);
		break;
	case SSH2_AGENTC_REMOVE_ALL_IDENTITIES:
		process_remove_all_identities(e);
		break;
#ifdef ENABLE_PKCS11
	case SSH_AGENTC_ADD_SMARTCARD_KEY:
	case SSH_AGENTC_ADD_SMARTCARD_KEY_CONSTRAINED:
		process_add_smartcard_key(e);
		break;
	case SSH_AGENTC_REMOVE_SMARTCARD_KEY:
		process_remove_smartcard_key(e);
		break;
#endif /* ENABLE_PKCS11 */
	default:
		/* Unknown message.  Respond with failure. */
		error("Unknown message %d", type);
		sshbuf_reset(e->request);
		send_status(e, 0);
		break;
	}
	return 1;
}

static void
new_socket(sock_type type, int fd)
{
	u_int i, old_alloc, new_alloc;

	set_nonblock(fd);

	if (fd > max_fd)
		max_fd = fd;

	for (i = 0; i < sockets_alloc; i++)
		if (sockets[i].type == AUTH_UNUSED) {
			sockets[i].fd = fd;
			if ((sockets[i].input = sshbuf_new()) == NULL ||
			    (sockets[i].output = sshbuf_new()) == NULL ||
			    (sockets[i].request = sshbuf_new()) == NULL)
				fatal_f("sshbuf_new failed");
			sockets[i].type = type;
			return;
		}
	old_alloc = sockets_alloc;
	new_alloc = sockets_alloc + 10;
	sockets = xrecallocarray(sockets, old_alloc, new_alloc,
	    sizeof(sockets[0]));
	for (i = old_alloc; i < new_alloc; i++)
		sockets[i].type = AUTH_UNUSED;
	sockets_alloc = new_alloc;
	sockets[old_alloc].fd = fd;
	if ((sockets[old_alloc].input = sshbuf_new()) == NULL ||
	    (sockets[old_alloc].output = sshbuf_new()) == NULL ||
	    (sockets[old_alloc].request = sshbuf_new()) == NULL)
		fatal_f("sshbuf_new failed");
	sockets[old_alloc].type = type;
}

static int
handle_socket_read(u_int socknum)
{
	struct sockaddr_un sunaddr;
	socklen_t slen;
	uid_t euid;
	gid_t egid;
	int fd;

	slen = sizeof(sunaddr);
	fd = accept(sockets[socknum].fd, (struct sockaddr *)&sunaddr, &slen);
	if (fd == -1) {
		error("accept from AUTH_SOCKET: %s", strerror(errno));
		return -1;
	}
	if (getpeereid(fd, &euid, &egid) == -1) {
		error("getpeereid %d failed: %s", fd, strerror(errno));
		close(fd);
		return -1;
	}
	if ((euid != 0) && (getuid() != euid)) {
		error("uid mismatch: peer euid %u != uid %u",
		    (u_int) euid, (u_int) getuid());
		close(fd);
		return -1;
	}
	new_socket(AUTH_CONNECTION, fd);
	return 0;
}

static int
handle_conn_read(u_int socknum)
{
	char buf[AGENT_RBUF_LEN];
	ssize_t len;
	int r;

	if ((len = read(sockets[socknum].fd, buf, sizeof(buf))) <= 0) {
		if (len == -1) {
			if (errno == EAGAIN || errno == EINTR)
				return 0;
			error_f("read error on socket %u (fd %d): %s",
			    socknum, sockets[socknum].fd, strerror(errno));
		}
		return -1;
	}
	if ((r = sshbuf_put(sockets[socknum].input, buf, len)) != 0)
		fatal_fr(r, "compose");
	explicit_bzero(buf, sizeof(buf));
	while(1) {
		r = process_message(socknum);
		if (r == -1) return -1;
		if (r == 0) break;
	}
	return 0;
}

static int
handle_conn_write(u_int socknum)
{
	ssize_t len;
	int r;

	if (sshbuf_len(sockets[socknum].output) == 0)
		return 0; /* shouldn't happen */
	if ((len = write(sockets[socknum].fd,
	    sshbuf_ptr(sockets[socknum].output),
	    sshbuf_len(sockets[socknum].output))) <= 0) {
		if (len == -1) {
			if (errno == EAGAIN || errno == EINTR)
				return 0;
			error_f("read error on socket %u (fd %d): %s",
			    socknum, sockets[socknum].fd, strerror(errno));
		}
		return -1;
	}
	if ((r = sshbuf_consume(sockets[socknum].output, len)) != 0)
		fatal_fr(r, "consume");
	return 0;
}

static void
after_poll(struct pollfd *pfd, size_t npfd, u_int maxfds)
{
	size_t i;
	u_int socknum, activefds = npfd;

	for (i = 0; i < npfd; i++) {
		if (pfd[i].revents == 0)
			continue;
		/* Find sockets entry */
		for (socknum = 0; socknum < sockets_alloc; socknum++) {
			if (sockets[socknum].type != AUTH_SOCKET &&
			    sockets[socknum].type != AUTH_CONNECTION)
				continue;
			if (pfd[i].fd == sockets[socknum].fd)
				break;
		}
		if (socknum >= sockets_alloc) {
			error_f("no socket for fd %d", pfd[i].fd);
			continue;
		}
		/* Process events */
		switch (sockets[socknum].type) {
		case AUTH_SOCKET:
			if ((pfd[i].revents & (POLLIN|POLLHUP|POLLERR)) == 0)
				break;
			if (npfd > maxfds) {
				debug3("out of fds (active %u >= limit %u); "
				    "skipping accept", activefds, maxfds);
				break;
			}
			if (handle_socket_read(socknum) == 0)
				activefds++;
			break;
		case AUTH_CONNECTION:
			if ((pfd[i].revents & (POLLIN|POLLHUP|POLLERR)) != 0 &&
			    handle_conn_read(socknum) != 0)
				goto close_sock;
			if ((pfd[i].revents & (POLLOUT|POLLHUP)) != 0 &&
			    handle_conn_write(socknum) != 0) {
 close_sock:
				if (activefds == 0)
					fatal("activefds == 0 at close_sock");
				close_socket(&sockets[socknum]);
				activefds--;
				break;
			}
			break;
		default:
			break;
		}
	}
}

static int
prepare_ppoll(struct pollfd **pfdp, size_t *npfdp, struct timespec *timeoutp, u_int maxfds)
{
	struct pollfd *pfd = *pfdp;
	size_t i, j, npfd = 0;
	time_t deadline;
	int r;

	/* Count active sockets */
	for (i = 0; i < sockets_alloc; i++) {
		switch (sockets[i].type) {
		case AUTH_SOCKET:
		case AUTH_CONNECTION:
			npfd++;
			break;
		case AUTH_UNUSED:
			break;
		default:
			fatal("Unknown socket type %d", sockets[i].type);
			break;
		}
	}
	if (npfd != *npfdp &&
	    (pfd = recallocarray(pfd, *npfdp, npfd, sizeof(*pfd))) == NULL)
		fatal_f("recallocarray failed");
	*pfdp = pfd;
	*npfdp = npfd;

	for (i = j = 0; i < sockets_alloc; i++) {
		switch (sockets[i].type) {
		case AUTH_SOCKET:
			if (npfd > maxfds) {
				debug3("out of fds (active %zu >= limit %u); "
				    "skipping arming listener", npfd, maxfds);
				break;
			}
			pfd[j].fd = sockets[i].fd;
			pfd[j].revents = 0;
			pfd[j].events = POLLIN;
			j++;
			break;
		case AUTH_CONNECTION:
			pfd[j].fd = sockets[i].fd;
			pfd[j].revents = 0;
			/*
			 * Only prepare to read if we can handle a full-size
			 * input read buffer and enqueue a max size reply..
			 */
			if ((r = sshbuf_check_reserve(sockets[i].input,
			    AGENT_RBUF_LEN)) == 0 &&
			    (r = sshbuf_check_reserve(sockets[i].output,
			    AGENT_MAX_LEN)) == 0)
				pfd[j].events = POLLIN;
			else if (r != SSH_ERR_NO_BUFFER_SPACE)
				fatal_fr(r, "reserve");
			if (sshbuf_len(sockets[i].output) > 0)
				pfd[j].events |= POLLOUT;
			j++;
			break;
		default:
			break;
		}
	}
	deadline = reaper();
	if (parent_alive_interval != 0)
		deadline = (deadline == 0) ? parent_alive_interval :
		    MINIMUM(deadline, parent_alive_interval);
	if (deadline != 0)
		ptimeout_deadline_sec(timeoutp, deadline);
	return 1;
}

static void
cleanup_socket(void)
{
	if (cleanup_pid != 0 && getpid() != cleanup_pid)
		return;
	debug_f("cleanup");
	if (socket_name[0])
		unlink(socket_name);
	if (socket_dir[0])
		rmdir(socket_dir);
}

void
cleanup_exit(int i)
{
	cleanup_socket();
#ifdef ENABLE_PKCS11
	pkcs11_terminate();
#endif
	_exit(i);
}

static void
cleanup_handler(int sig)
{
	signalled_exit = sig;
}

static void
keydrop_handler(int sig)
{
	signalled_keydrop = sig;
}

static void
check_parent_exists(void)
{
	/*
	 * If our parent has exited then getppid() will return (pid_t)1,
	 * so testing for that should be safe.
	 */
	if (parent_pid != -1 && getppid() != parent_pid) {
		/* printf("Parent has died - Authentication agent exiting.\n"); */
		cleanup_exit(2);
	}
}

static void
usage(void)
{
	fprintf(stderr,
	    "usage: ssh-agent [-c | -s] [-Dd] [-a bind_address] [-E fingerprint_hash]\n"
	    "                 [-P allowed_providers] [-t life]\n"
	    "       ssh-agent [-a bind_address] [-E fingerprint_hash] [-P allowed_providers]\n"
	    "                 [-t life] command [arg ...]\n"
	    "       ssh-agent [-c | -s] -k\n");
	exit(1);
}

int
main(int ac, char **av)
{
	int c_flag = 0, d_flag = 0, D_flag = 0, k_flag = 0, s_flag = 0;
	int sock = -1, ch, result, saved_errno;
	char *shell, *format, *pidstr, *agentsocket = NULL;
	extern int optind;
	extern char *optarg;
	pid_t pid;
	char pidstrbuf[1 + 3 * sizeof pid];
	size_t len;
	mode_t prev_mask;
	struct pollfd *pfd = NULL;
	size_t npfd = 0;
	u_int maxfds;
	sigset_t nsigset;

	socket_name[0] = '\0';
	socket_dir[0] = '\0';

	ssh_malloc_init();	/* must be called before any mallocs */
	/* Ensure that fds 0, 1 and 2 are open or directed to /dev/null */
	sanitise_stdfd();

	/* drop */
	(void)setegid(getgid());
	(void)setgid(getgid());

	platform_disable_tracing(0);	/* strict=no */

	__progname = ssh_get_progname(av[0]);

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
#ifdef ENABLE_PKCS11
	ERR_load_PKCS11_strings();
#endif
	fill_default_xkalg();

	seed_rng();

	while ((ch = getopt(ac, av, "cDdksE:a:P:t:")) != -1) {
		switch (ch) {
		case 'E':
			fingerprint_hash = ssh_digest_alg_by_name(optarg);
			if (fingerprint_hash == -1)
				fatal("Invalid hash algorithm \"%s\"", optarg);
			break;
		case 'c':
			if (s_flag)
				usage();
			c_flag++;
			break;
		case 'k':
			k_flag++;
			break;
		case 'P':
			if (allowed_providers != NULL)
				fatal("-P option already specified");
			allowed_providers = xstrdup(optarg);
			break;
		case 's':
			if (c_flag)
				usage();
			s_flag++;
			break;
		case 'd':
			if (d_flag || D_flag)
				usage();
			d_flag++;
			break;
		case 'D':
			if (d_flag || D_flag)
				usage();
			D_flag++;
			break;
		case 'a':
			agentsocket = optarg;
			break;
		case 't':
			if (!set_lifetime(optarg)) {
				usage();
			}
			break;
		default:
			usage();
		}
	}
	ac -= optind;
	av += optind;

	if (ac > 0 && (c_flag || k_flag || s_flag || d_flag || D_flag))
		usage();

	if (allowed_providers == NULL)
		allowed_providers = xstrdup(DEFAULT_ALLOWED_PROVIDERS);

	if (ac == 0 && !c_flag && !s_flag) {
		shell = getenv("SHELL");
		if (shell != NULL && (len = strlen(shell)) > 2 &&
		    strncmp(shell + len - 3, "csh", 3) == 0)
			c_flag = 1;
	}
	if (k_flag) {
		const char *errstr = NULL;

		pidstr = getenv(SSH_AGENTPID_ENV_NAME);
		if (pidstr == NULL) {
			fprintf(stderr, "%s not set, cannot kill agent\n",
			    SSH_AGENTPID_ENV_NAME);
			exit(1);
		}
		pid = (int)strtonum(pidstr, 2, INT_MAX, &errstr);
		if (errstr) {
			fprintf(stderr,
			    "%s=\"%s\", which is not a good PID: %s\n",
			    SSH_AGENTPID_ENV_NAME, pidstr, errstr);
			exit(1);
		}
		if (kill(pid, SIGTERM) == -1) {
			perror("kill");
			exit(1);
		}
		format = c_flag ? "unsetenv %s;\n" : "unset %s;\n";
		printf(format, SSH_AUTHSOCKET_ENV_NAME);
		printf(format, SSH_AGENTPID_ENV_NAME);
		printf("echo Agent pid %ld killed;\n", (long)pid);
		exit(0);
	}

	/*
	 * Minimum file descriptors:
	 * stdio (3) + listener (1) + syslog (1 maybe) + connection (1) +
	 * a few spare for libc / stack protectors / sanitisers, etc.
	 */
#define SSH_AGENT_MIN_FDS (3+1+1+1+4)
{
#if defined(HAVE_GETRLIMIT) && defined(RLIMIT_NOFILE)
	rlim_t lim;
{	struct rlimit rlim;

	if (getrlimit(RLIMIT_NOFILE, &rlim) == -1)
		fatal("%s: getrlimit RLIMIT_NOFILE: %s", __progname, strerror(errno));
	if (rlim.rlim_cur < SSH_AGENT_MIN_FDS)
		fatal("%s: file descriptor rlimit %lld too low (minimum %u)",
		    __progname, (long long)rlim.rlim_cur, SSH_AGENT_MIN_FDS);
	lim = rlim.rlim_cur;
	if (lim == RLIM_INFINITY)
		lim = SSH_SYSFDMAX;
}
#else
	long lim = SSH_SYSFDMAX;
	if (lim < SSH_AGENT_MIN_FDS)
		fatal("%s: file descriptor limit %ld too low (minimum %u)",
		    __progname, lim, SSH_AGENT_MIN_FDS);
#endif
	maxfds = MINIMUM(lim, UINT_MAX) - SSH_AGENT_MIN_FDS;
}

	parent_pid = getpid();

	/* Has the socket been provided via socket activation? */
	/* TODO */

	/* Otherwise, create private directory for agent socket */
	if (sock == -1) {
		if (agentsocket == NULL) {
			mktemp_proto(socket_dir, sizeof(socket_dir));
			if (mkdtemp(socket_dir) == NULL) {
				perror("mkdtemp: private socket dir");
				exit(1);
			}
		{	int r = snprintf(socket_name, sizeof socket_name,
			    "%s/agent.%ld", socket_dir, (long)parent_pid);
			if (r < 0 || r > (int)sizeof(socket_name)) {
				fprintf(stderr, "too long socket path\n");
				exit(1);
			}
		}
		} else {
			/* Try to use specified agent socket */
			if (strlcpy(socket_name, agentsocket, sizeof socket_name)
			    > sizeof(socket_name)) {
				fprintf(stderr, "too long agent socket path\n");
				exit(1);
			}
		}
	}

	/*
	 * Create socket early so it will exist before command gets run from
	 * the parent.
	 */
	if (sock == -1) {
		prev_mask = umask(0177);
		sock = unix_listener(socket_name, SSH_LISTEN_BACKLOG, 0);
		if (sock < 0) {
			/* XXX - unix_listener() calls error() not perror() */
			*socket_name = '\0'; /* Don't unlink existing file */
			cleanup_exit(1);
		}
		umask(prev_mask);
	}

	/*
	 * Fork, and have the parent execute the command, if any, or present
	 * the socket data.  The child continues as the authentication agent.
	 */
	if (D_flag || d_flag) {
		log_init(__progname,
		    d_flag ? SYSLOG_LEVEL_DEBUG3 : SYSLOG_LEVEL_INFO,
		    SYSLOG_FACILITY_AUTH, 1);
		if (socket_name[0] != '\0') {
			format = c_flag ?
			    "setenv %s %s;\n" : "%s=%s; export %s;\n";
			printf(format, SSH_AUTHSOCKET_ENV_NAME, socket_name,
			    SSH_AUTHSOCKET_ENV_NAME);
			printf("echo Agent pid %ld;\n", (long)parent_pid);
			fflush(stdout);
		}
		goto skip;
	}
	pid = fork();
	if (pid == -1) {
		perror("fork");
		cleanup_exit(1);
	}
	if (pid != 0) {		/* Parent - execute the given command. */
		close(sock);
		snprintf(pidstrbuf, sizeof pidstrbuf, "%ld", (long)pid);
		if (ac == 0) {
			format = c_flag ? "setenv %s %s;\n" : "%s=%s; export %s;\n";
			printf(format, SSH_AUTHSOCKET_ENV_NAME, socket_name,
			    SSH_AUTHSOCKET_ENV_NAME);
			printf(format, SSH_AGENTPID_ENV_NAME, pidstrbuf,
			    SSH_AGENTPID_ENV_NAME);
			printf("echo Agent pid %ld;\n", (long)pid);
			exit(0);
		}
		if (setenv(SSH_AUTHSOCKET_ENV_NAME, socket_name, 1) == -1 ||
		    setenv(SSH_AGENTPID_ENV_NAME, pidstrbuf, 1) == -1) {
			perror("setenv");
			exit(1);
		}
		execvp(av[0], av);
		perror(av[0]);
		exit(1);
	}
	/* child */
	log_init(__progname, SYSLOG_LEVEL_INFO, SYSLOG_FACILITY_AUTH, 0);

	if (setsid() == -1) {
		error_f("setsid: %s", strerror(errno));
		cleanup_exit(1);
	}

	(void)chdir("/");
	if (stdfd_devnull(1, 1, 1) == -1)
		error_f("stdfd_devnull failed");

#if defined(HAVE_SETRLIMIT) && defined(RLIMIT_CORE)
{	struct rlimit rlim;

	/* deny core dumps, since memory contains unencrypted private keys */
	rlim.rlim_cur = rlim.rlim_max = 0;
	if (setrlimit(RLIMIT_CORE, &rlim) == -1) {
		error_f("setrlimit RLIMIT_CORE: %s", strerror(errno));
		cleanup_exit(1);
	}
}
#endif

skip:

	cleanup_pid = getpid();

#ifdef ENABLE_PKCS11
	pkcs11_init(0);
#endif
	new_socket(AUTH_SOCKET, sock);
	if (ac > 0)
		parent_alive_interval = 10;
	idtab_init();
	ssh_signal(SIGPIPE, SIG_IGN);
	ssh_signal(SIGINT, (d_flag | D_flag) ? cleanup_handler : SIG_IGN);
	ssh_signal(SIGHUP, cleanup_handler);
	ssh_signal(SIGTERM, cleanup_handler);
	ssh_signal(SIGUSR1, keydrop_handler);

	sigemptyset(&nsigset);
	sigaddset(&nsigset, SIGINT);
	sigaddset(&nsigset, SIGHUP);
	sigaddset(&nsigset, SIGTERM);
	sigaddset(&nsigset, SIGUSR1);

	if (pledge("stdio rpath cpath unix id proc exec", NULL) == -1)
		fatal("%s: pledge: %s", __progname, strerror(errno));
	platform_pledge_agent();

	while (1) {
		struct timespec timeout;

		ptimeout_init(&timeout);
		prepare_ppoll(&pfd, &npfd, &timeout, maxfds);

	{	sigset_t osigset;
		sigprocmask(SIG_BLOCK, &nsigset, &osigset);
		result = ppoll(pfd, npfd, ptimeout_get_tsp(&timeout), &osigset);
		saved_errno = errno;
		sigprocmask(SIG_SETMASK, &osigset, NULL);
	}
		if (signalled_exit != 0) {
			logit("exiting on signal %d", (int)signalled_exit);
			cleanup_exit(2);
			break; /* unreachable */
		}
		if (signalled_keydrop != 0) {
			logit("signal %d received; removing all keys",
			    (int)signalled_keydrop);
			remove_all_identities();
			signalled_keydrop = 0;
		}
		if (parent_alive_interval != 0)
			check_parent_exists();
		(void) reaper();	/* remove expired keys */
		if (result == -1) {
			if (saved_errno == EINTR)
				continue;
			fatal("ppoll: %s", strerror(saved_errno));
		} else if (result > 0)
			after_poll(pfd, npfd, maxfds);
	}
}
