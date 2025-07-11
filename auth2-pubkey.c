/* $OpenBSD: auth2-pubkey.c,v 1.122 2024/12/12 09:09:09 dtucker Exp $ */
/*
 * Copyright (c) 2000 Markus Friedl.  All rights reserved.
 * Copyright (c) 2010 Damien Miller.  All rights reserved.
 * Copyright (c) 2003-2025 Roumen Petrov.  All rights reserved.
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

#include <stdlib.h>
#include <errno.h>
#ifdef HAVE_PATHS_H
# include <paths.h>
#endif
#include <pwd.h>
#include <signal.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <limits.h>
#ifdef USE_SYSTEM_GLOB
# include <glob.h>
#else
# include "openbsd-compat/glob.h"
#endif

#include "xmalloc.h"
#include "ssh.h"
#include "ssh2.h"
#include "packet.h"
#include "kex.h"
#include "sshbuf.h"
#include "log.h"
#include "misc.h"
#include "servconf.h"
#include "compat.h"
#include "sshxkey.h"
#include "ssh-x509.h"
#include "hostfile.h"
#include "auth.h"
#include "pathnames.h"
#include "uidswap.h"
#include "auth-options.h"
#include "canohost.h"
#ifdef GSSAPI
#include "ssh-gss.h"
#endif
#include "monitor_wrap.h"
#include "authfile.h"
#include "match.h"
#include "channels.h" /* XXX for session.h */
#include "session.h" /* XXX for child_set_env(); refactor? */

/* import */
extern ServerOptions options;
extern struct authmethod_cfg methodcfg_pubkey;

/* return 1 if given publickey algorithm is allowed */
static int
pubkey_algorithm_allowed(const char* pkalg)
{
	if (
	    (options.pubkey_algorithms != NULL) &&
	    (match_pattern_list(pkalg, options.pubkey_algorithms, 0) != 1)
	) {
		debug("disallowed publickey algorithm: %s", pkalg);
		return 0;
	}

	if (
	    (options.accepted_algorithms != NULL) &&
	    (match_pattern_list(pkalg, options.accepted_algorithms, 0) != 1)
	) {
		debug("non-accepted publickey algorithm: %s", pkalg);
		return 0;
	}

	return 1;
}

static char *
format_key(const struct sshkey *key)
{
	char *ret, *fp = sshkey_fingerprint(key,
	    options.fingerprint_hash, SSH_FP_DEFAULT);

	xasprintf(&ret, "%s %s", sshkey_type(key), fp);
	free(fp);
	return ret;
}

static int
userauth_pubkey(struct ssh *ssh)
{
	Authctxt *authctxt = ssh->authctxt;
	struct passwd *pw = authctxt->pw;
	struct sshbuf *b = NULL;
	struct sshkey *key = NULL;
	char *pkalg = NULL, *userstyle = NULL, *key_s = NULL, *ca_s = NULL;
	u_char *pkblob = NULL, *sig = NULL, have_sig;
	size_t blen, slen;
	int r, pktype;
	int authenticated = 0;
	struct sshauthopt *authopts = NULL;

	if ((r = sshpkt_get_u8(ssh, &have_sig)) != 0 ||
	    (r = sshpkt_get_cstring(ssh, &pkalg, NULL)) != 0 ||
	    (r = sshpkt_get_string(ssh, &pkblob, &blen)) != 0)
		fatal_fr(r, "parse packet");
	pktype = sshkey_type_from_name(pkalg);
	if (pktype == KEY_UNSPEC) {
		/* this is perfectly legal */
		verbose("Unsupported public key algorithm: %s", pkalg);
		goto done;
	}
	if (!pubkey_algorithm_allowed(pkalg)) goto done;

	if ((r = Xkey_from_blob(pkalg, pkblob, blen, &key)) != 0) {
		error_fr(r, "parse key");
		goto done;
	}
	if (key == NULL) {
		error_f("cannot decode key: %s", pkalg);
		goto done;
	}
	if (key->type != pktype) {
		error_f("type mismatch for decoded key "
		    "(received %d, expected %d)", key->type, pktype);
		goto done;
	}
	if (auth2_key_already_used(authctxt, key)) {
		logit("refusing previously-used %s key", sshkey_type(key));
		goto done;
	}
	if ((r = sshkey_check_cert_sigtype(key,
	    options.ca_sign_algorithms)) != 0) {
		error_r(r, "Certificate signature algorithm %s",
		    (key->cert == NULL || key->cert->signature_type == NULL) ?
		    "(null)" : key->cert->signature_type);
		goto done;
	}
#if 0
	/* NOTE: key size is validated on read, sign and verify */
	if ((r = sshkey_check_length(key)) != 0) {
		error_r(r, "refusing %s key", sshkey_type(key));
		goto done;
	}
#endif

{	ssh_verify_ctx ctx = { pkalg, key, &ssh->compat };

	key_s = format_key(key);
	if (sshkey_is_cert(key))
		ca_s = format_key(key->cert->signature_key);

	if (have_sig) {
		debug3_f("have signature for %s %s%s%s", pkalg, key_s,
		    ca_s == NULL ? "" : " CA ", ca_s == NULL ? "" : ca_s);
		if ((r = sshpkt_get_string(ssh, &sig, &slen)) != 0 ||
		    (r = sshpkt_get_end(ssh)) != 0)
			fatal_fr(r, "parse signature packet");
		if ((b = sshbuf_new()) == NULL)
			fatal_f("sshbuf_new failed");
		if (ssh_compat_fellows(ssh, SSH_OLD_SESSIONID)) {
			if ((r = sshbuf_putb(b, ssh->kex->session_id)) != 0)
				fatal_fr(r, "put old session id");
		} else {
			if ((r = sshbuf_put_stringb(b,
			    ssh->kex->session_id)) != 0)
				fatal_fr(r, "put session id");
		}
		if (!authctxt->valid || authctxt->user == NULL) {
			debug2_f("disabled because of invalid user");
			goto done;
		}
		/* reconstruct packet */
		xasprintf(&userstyle, "%s%s%s", authctxt->user,
		    authctxt->style ? ":" : "",
		    authctxt->style ? authctxt->style : "");
		if ((r = sshbuf_put_u8(b, SSH2_MSG_USERAUTH_REQUEST)) != 0 ||
		    (r = sshbuf_put_cstring(b, userstyle)) != 0 ||
		    (r = sshbuf_put_cstring(b, authctxt->service)) != 0 ||
		    (r = sshbuf_put_cstring(b, "publickey")) != 0 ||
		    (r = sshbuf_put_u8(b, have_sig)) != 0 ||
		    (r = sshbuf_put_cstring(b, pkalg)) != 0 ||
		    (r = sshbuf_put_string(b, pkblob, blen)) != 0)
			fatal_fr(r, "reconstruct packet");
#ifdef DEBUG_PK
		sshbuf_dump(b, stderr);
#endif
		/* test for correct signature */
		authenticated = 0;
		if (PRIVSEP(user_xkey_allowed(ssh, pw, &ctx, 1, &authopts)) &&
		    PRIVSEP(Xkey_verify(&ctx, sig, slen,
			sshbuf_ptr(b), sshbuf_len(b))) == 0) {
			authenticated = 1;
		}
		auth2_record_key(authctxt, authenticated, key);
	} else {
		debug_f("test pkalg %s pkblob %s%s%s", pkalg, key_s,
		    ca_s == NULL ? "" : " CA ", ca_s == NULL ? "" : ca_s);

		if ((r = sshpkt_get_end(ssh)) != 0)
			fatal_fr(r, "parse packet");

		if (!authctxt->valid || authctxt->user == NULL) {
			debug2_f("disabled because of invalid user");
			goto done;
		}
		/* XXX fake reply and always send PK_OK ? */
		/*
		 * XXX this allows testing whether a user is allowed
		 * to login: if you happen to have a valid pubkey this
		 * message is sent. the message is NEVER sent at all
		 * if a user is not allowed to login. is this an
		 * issue? -markus
		 */
		if (PRIVSEP(user_xkey_allowed(ssh, pw, &ctx, 0, NULL))) {
			if ((r = sshpkt_start(ssh, SSH2_MSG_USERAUTH_PK_OK))
			    != 0 ||
			    (r = sshpkt_put_cstring(ssh, pkalg)) != 0 ||
			    (r = sshpkt_put_string(ssh, pkblob, blen)) != 0 ||
			    (r = sshpkt_send(ssh)) != 0 ||
			    (r = ssh_packet_write_wait(ssh)) != 0)
				fatal_fr(r, "send packet");
			authctxt->postponed = 1;
		}
	}
}
done:
	if (authenticated == 1 && auth_activate_options(ssh, authopts) != 0) {
		debug_f("key options inconsistent with existing");
		authenticated = 0;
	}
	debug2_f("authenticated %d pkalg %s", authenticated, pkalg);

	sshauthopt_free(authopts);
	sshkey_free(key);
	sshbuf_free(b);
	free(userstyle);
	free(pkalg);
	free(pkblob);
	free(key_s);
	free(ca_s);
	free(sig);
	return authenticated;
}

static int
match_principals_file(struct passwd *pw, char *file,
    struct sshkey_cert *cert, struct sshauthopt **authoptsp)
{
	int success = 0;
	glob_t gl;
	struct sshauthopt *opts = NULL;

	if (authoptsp != NULL)
		*authoptsp = NULL;

{	int r;
	temporarily_use_uid(pw);
	r = glob(file, 0, NULL, &gl);
	restore_uid();
	if (r != 0) {
		if (r != GLOB_NOMATCH)
			error_f("glob \"%s\" failed", file);
		return 0;
	}
}
	if (gl.gl_pathc > INT_MAX)
		fatal_f("too many glob results for \"%s\"", file);
	debug3_f("glob \"%s\" returned %zu matches", file, gl.gl_pathc);

{	size_t i;
	for (i = 0; i < gl.gl_pathc; i++) {
		FILE *f;

		temporarily_use_uid(pw);
		debug("trying authorized principals file %s", gl.gl_pathv[i]);
		f = auth_openprincipals(gl.gl_pathv[i], pw, options.strict_modes);
		if (f == NULL) {
			restore_uid();
			continue;
		}
		success = auth_process_principals(f, gl.gl_pathv[i], cert, &opts);
		fclose(f);
		restore_uid();

		if (success) break;
		sshauthopt_free(opts);
		opts = NULL;
	}
}
	globfree(&gl);

	if (success && authoptsp != NULL) {
		*authoptsp = opts;
		opts = NULL;
	}
	sshauthopt_free(opts);
	return success;
}

/*
 * Checks whether principal is allowed in output of command.
 * returns 1 if the principal is allowed or 0 otherwise.
 */
static int
match_principals_command(struct passwd *user_pw, const struct sshkey *key,
    const char *conn_id, const char *rdomain, struct sshauthopt **authoptsp)
{
	struct passwd *runas_pw = NULL;
	const struct sshkey_cert *cert = key->cert;
	FILE *f = NULL;
	int r, ok, found_principal = 0;
	int i, ac = 0, uid_swapped = 0;
	pid_t pid;
	char *tmp, *username = NULL, *command = NULL, **av = NULL;
	char *ca_fp = NULL, *key_fp = NULL, *catext = NULL, *keytext = NULL;
	char serial_s[32], uidstr[32];
	void (*osigchld)(int);

	if (authoptsp != NULL)
		*authoptsp = NULL;
	if (options.authorized_principals_command == NULL)
		return 0;
	if (options.authorized_principals_command_user == NULL) {
		error("No user for AuthorizedPrincipalsCommand specified, "
		    "skipping");
		return 0;
	}

	/*
	 * NB. all returns later this function should go via "out" to
	 * ensure the original SIGCHLD handler is restored properly.
	 */
	osigchld = ssh_signal(SIGCHLD, SIG_DFL);

	/* Prepare and verify the user for the command */
	username = percent_expand(options.authorized_principals_command_user,
	    "u", user_pw->pw_name, (char *)NULL);
	runas_pw = getpwnam(username);
	if (runas_pw == NULL) {
		error("AuthorizedPrincipalsCommandUser \"%s\" not found: %s",
		    username, strerror(errno));
		goto out;
	}

	/* Turn the command into an argument vector */
	if (argv_split(options.authorized_principals_command,
	    &ac, &av, 0) != 0) {
		error("AuthorizedPrincipalsCommand \"%s\" contains "
		    "invalid quotes", options.authorized_principals_command);
		goto out;
	}
	if (ac == 0) {
		error("AuthorizedPrincipalsCommand \"%s\" yielded no arguments",
		    options.authorized_principals_command);
		goto out;
	}
	if ((ca_fp = sshkey_fingerprint(cert->signature_key,
	    options.fingerprint_hash, SSH_FP_DEFAULT)) == NULL) {
		error_f("sshkey_fingerprint failed");
		goto out;
	}
	if ((key_fp = sshkey_fingerprint(key,
	    options.fingerprint_hash, SSH_FP_DEFAULT)) == NULL) {
		error_f("sshkey_fingerprint failed");
		goto out;
	}
	if ((r = sshkey_to_base64(cert->signature_key, &catext)) != 0) {
		error_fr(r, "sshkey_to_base64 failed");
		goto out;
	}
	if ((r = sshkey_to_base64(key, &keytext)) != 0) {
		error_fr(r, "sshkey_to_base64 failed");
		goto out;
	}
	snprintf(serial_s, sizeof(serial_s), "%llu",
	    (unsigned long long)cert->serial);
	snprintf(uidstr, sizeof(uidstr), "%llu",
	    (unsigned long long)user_pw->pw_uid);
	for (i = 1; i < ac; i++) {
		tmp = percent_expand(av[i],
		    "C", conn_id,
		    "D", rdomain,
		    "U", uidstr,
		    "u", user_pw->pw_name,
		    "h", user_pw->pw_dir,
		    "t", sshkey_ssh_name(key),
		    "T", sshkey_ssh_name(cert->signature_key),
		    "f", key_fp,
		    "F", ca_fp,
		    "k", keytext,
		    "K", catext,
		    "i", cert->key_id,
		    "s", serial_s,
		    (char *)NULL);
		if (tmp == NULL)
			fatal_f("percent_expand failed");
		free(av[i]);
		av[i] = tmp;
	}
	/* Prepare a printable command for logs, etc. */
	command = argv_assemble(ac, av);

	if ((pid = subprocess("AuthorizedPrincipalsCommand", command,
	    ac, av, &f,
	    SSH_SUBPROCESS_STDOUT_CAPTURE|SSH_SUBPROCESS_STDERR_DISCARD,
	    runas_pw, temporarily_use_uid, restore_uid)) == 0)
		goto out;

	uid_swapped = 1;
	temporarily_use_uid(runas_pw);

	ok = auth_process_principals(f, "(command)", cert, authoptsp);

	fclose(f);
	f = NULL;

	if (exited_cleanly(pid, "AuthorizedPrincipalsCommand", command, 0) != 0)
		goto out;

	/* Read completed successfully */
	found_principal = ok;
 out:
	if (f != NULL)
		fclose(f);
	ssh_signal(SIGCHLD, osigchld);
	argv_free(av, ac);
	if (uid_swapped)
		restore_uid();
	free(command);
	free(username);
	free(ca_fp);
	free(key_fp);
	free(catext);
	free(keytext);
	return found_principal;
}

/* Authenticate a certificate key against TrustedUserCAKeys */
static int
user_cert_trusted_ca(struct passwd *pw, struct sshkey *key,
    const char *remote_ip, const char *remote_host,
    const char *conn_id, const char *rdomain, struct sshauthopt **authoptsp)
{
	char *ca_fp, *principals_file = NULL;
	const char *reason;
	struct sshauthopt *principals_opts = NULL, *cert_opts = NULL;
	struct sshauthopt *final_opts = NULL;
	int r, ret = 0, found_principal = 0, use_authorized_principals;

	if (authoptsp != NULL)
		*authoptsp = NULL;

	if (!sshkey_is_cert(key) || options.trusted_user_ca_keys == NULL)
		return 0;

	if ((ca_fp = sshkey_fingerprint(key->cert->signature_key,
	    options.fingerprint_hash, SSH_FP_DEFAULT)) == NULL)
		return 0;

	if ((r = sshkey_in_file(key->cert->signature_key,
	    options.trusted_user_ca_keys, 1, 0)) != 0) {
		debug2_r(r, "CA %s %s is not listed in %s",
		    sshkey_type(key->cert->signature_key), ca_fp,
		    options.trusted_user_ca_keys);
		goto out;
	}
	/*
	 * If AuthorizedPrincipals is in use, then compare the certificate
	 * principals against the names in that file rather than matching
	 * against the username.
	 */
	if ((principals_file = authorized_principals_file(pw)) != NULL) {
		if (match_principals_file(pw, principals_file,
		    key->cert, &principals_opts))
			found_principal = 1;
	}
	/* Try querying command if specified */
	if (!found_principal && match_principals_command(pw, key,
	    conn_id, rdomain, &principals_opts))
		found_principal = 1;
	/* If principals file or command is specified, then require a match */
	use_authorized_principals = principals_file != NULL ||
	    options.authorized_principals_command != NULL;
	if (!found_principal && use_authorized_principals) {
		reason = "Certificate does not contain an authorized principal";
		goto fail_reason;
	}
	if (use_authorized_principals && principals_opts == NULL)
		fatal_f("internal error: missing principals_opts");
	if (sshkey_cert_check_authority_now(key, 0, 1, 0,
	    use_authorized_principals ? NULL : pw->pw_name, &reason) != 0)
		goto fail_reason;

	/* Check authority from options in key and from principals file/cmd */
	if ((cert_opts = sshauthopt_from_cert(key)) == NULL) {
		reason = "Invalid certificate options";
		goto fail_reason;
	}
	if (auth_authorise_keyopts(pw, cert_opts, 0,
	    remote_ip, remote_host, "cert") != 0) {
		reason = "Refused by certificate options";
		goto fail_reason;
	}
	if (principals_opts == NULL) {
		final_opts = cert_opts;
		cert_opts = NULL;
	} else {
		if (auth_authorise_keyopts(pw, principals_opts, 0,
		    remote_ip, remote_host, "principals") != 0) {
			reason = "Refused by certificate principals options";
			goto fail_reason;
		}
		if ((final_opts = sshauthopt_merge(principals_opts,
		    cert_opts, &reason)) == NULL) {
 fail_reason:
			error("%s", reason);
			auth_debug_add("%s", reason);
			goto out;
		}
	}

	/* Success */
	verbose("Accepted certificate ID \"%s\" (serial %llu) signed by "
	    "%s CA %s via %s", key->cert->key_id,
	    (unsigned long long)key->cert->serial,
	    sshkey_type(key->cert->signature_key), ca_fp,
	    options.trusted_user_ca_keys);
	if (authoptsp != NULL) {
		*authoptsp = final_opts;
		final_opts = NULL;
	}
	ret = 1;
 out:
	sshauthopt_free(principals_opts);
	sshauthopt_free(cert_opts);
	sshauthopt_free(final_opts);
	free(principals_file);
	free(ca_fp);
	return ret;
}

/*
 * Checks whether key is allowed in file.
 * returns 1 if the key is allowed or 0 otherwise.
 */
static int
user_key_allowed2(struct passwd *pw, struct sshkey *key,
    char *file, const char *remote_ip, const char *remote_host,
    struct sshauthopt **authoptsp)
{
	FILE *f;
	int found_key = 0;

	if (authoptsp != NULL)
		*authoptsp = NULL;

	/* Temporarily use the user's uid. */
	temporarily_use_uid(pw);

	debug("trying authorized keys file %s", file);
	if ((f = auth_openkeyfile(file, pw, options.strict_modes)) != NULL) {
		found_key = auth_check_authkeys_file(pw, f, file,
		    key, remote_ip, remote_host, authoptsp);
		fclose(f);
	}

	restore_uid();
	return found_key;
}

/*
 * Checks whether key is allowed in output of command.
 * returns 1 if the key is allowed or 0 otherwise.
 */
static int
user_key_command_allowed2(struct passwd *user_pw, struct sshkey *key,
    const char *remote_ip, const char *remote_host,
    const char *conn_id, const char *rdomain, struct sshauthopt **authoptsp)
{
	struct passwd *runas_pw = NULL;
	FILE *f = NULL;
	int r, ok, found_key = 0;
	int i, uid_swapped = 0, ac = 0;
	pid_t pid;
	char *username = NULL, *key_fp = NULL, *keytext = NULL;
	char uidstr[32], *tmp, *command = NULL, **av = NULL;
	void (*osigchld)(int);

	if (authoptsp != NULL)
		*authoptsp = NULL;
	if (options.authorized_keys_command == NULL)
		return 0;
	if (options.authorized_keys_command_user == NULL) {
		error("No user for AuthorizedKeysCommand specified, skipping");
		return 0;
	}

	/*
	 * NB. all returns later this function should go via "out" to
	 * ensure the original SIGCHLD handler is restored properly.
	 */
	osigchld = ssh_signal(SIGCHLD, SIG_DFL);

	/* Prepare and verify the user for the command */
	username = percent_expand(options.authorized_keys_command_user,
	    "u", user_pw->pw_name, (char *)NULL);
	runas_pw = getpwnam(username);
	if (runas_pw == NULL) {
		error("AuthorizedKeysCommandUser \"%s\" not found: %s",
		    username, strerror(errno));
		goto out;
	}

	/* Prepare AuthorizedKeysCommand */
	if ((key_fp = sshkey_fingerprint(key, options.fingerprint_hash,
	    SSH_FP_DEFAULT)) == NULL) {
		error_f("sshkey_fingerprint failed");
		goto out;
	}
	if ((r = sshkey_to_base64(key, &keytext)) != 0) {
		error_fr(r, "sshkey_to_base64 failed");
		goto out;
	}

	/* Turn the command into an argument vector */
	if (argv_split(options.authorized_keys_command, &ac, &av, 0) != 0) {
		error("AuthorizedKeysCommand \"%s\" contains invalid quotes",
		    options.authorized_keys_command);
		goto out;
	}
	if (ac == 0) {
		error("AuthorizedKeysCommand \"%s\" yielded no arguments",
		    options.authorized_keys_command);
		goto out;
	}
	snprintf(uidstr, sizeof(uidstr), "%llu",
	    (unsigned long long)user_pw->pw_uid);
	for (i = 1; i < ac; i++) {
		tmp = percent_expand(av[i],
		    "C", conn_id,
		    "D", rdomain,
		    "U", uidstr,
		    "u", user_pw->pw_name,
		    "h", user_pw->pw_dir,
		    "t", sshkey_ssh_name(key),
		    "f", key_fp,
		    "k", keytext,
		    (char *)NULL);
		if (tmp == NULL)
			fatal_f("percent_expand failed");
		free(av[i]);
		av[i] = tmp;
	}
	/* Prepare a printable command for logs, etc. */
	command = argv_assemble(ac, av);

	/*
	 * If AuthorizedKeysCommand was run without arguments
	 * then fall back to the old behaviour of passing the
	 * target username as a single argument.
	 */
	if (ac == 1) {
		av = xreallocarray(av, ac + 2, sizeof(*av));
		av[1] = xstrdup(user_pw->pw_name);
		av[2] = NULL;
		/* Fix up command too, since it is used in log messages */
		free(command);
		xasprintf(&command, "%s %s", av[0], av[1]);
	}

	if ((pid = subprocess("AuthorizedKeysCommand", command,
	    ac, av, &f,
	    SSH_SUBPROCESS_STDOUT_CAPTURE|SSH_SUBPROCESS_STDERR_DISCARD,
	    runas_pw, temporarily_use_uid, restore_uid)) == 0)
		goto out;

	uid_swapped = 1;
	temporarily_use_uid(runas_pw);

	ok = auth_check_authkeys_file(user_pw, f,
	    options.authorized_keys_command, key, remote_ip,
	    remote_host, authoptsp);

	fclose(f);
	f = NULL;

	if (exited_cleanly(pid, "AuthorizedKeysCommand", command, 0) != 0)
		goto out;

	/* Read completed successfully */
	found_key = ok;
 out:
	if (f != NULL)
		fclose(f);
	ssh_signal(SIGCHLD, osigchld);
	argv_free(av, ac);
	if (uid_swapped)
		restore_uid();
	free(command);
	free(username);
	free(key_fp);
	free(keytext);
	return found_key;
}

/*
 * Check whether key authenticates and authorises the user.
 */
int
user_xkey_allowed(struct ssh *ssh, struct passwd *pw, ssh_verify_ctx *ctx,
    int auth_attempt, struct sshauthopt **authoptsp)
{
	struct sshkey *key = ctx->key;
	u_int success = 0;
	char *conn_id = NULL;
	struct sshauthopt *opts = NULL;
	const char *rdomain, *remote_ip, *remote_host;

	UNUSED(auth_attempt);
	if (authoptsp != NULL)
		*authoptsp = NULL;

	if (options.x509flags.validate_first &&
	    sshkey_is_x509(key) &&
	    (xkey_validate_cert(key) < 0))
		return 0;
	if (auth_key_is_revoked(key))
		return 0;
	if (sshkey_is_cert(key) &&
	    auth_key_is_revoked(key->cert->signature_key))
		return 0;

	rdomain = ssh_packet_rdomain_in(ssh);
	if (rdomain == NULL) rdomain = "";
	remote_ip = ssh_remote_ipaddr(ssh);
	remote_host = auth_get_canonical_hostname(ssh, options.use_dns);

{	u_int i;
	for (i = 0; i < options.num_authkeys_files; i++) {
		char *file;

		if (strcasecmp(options.authorized_keys_files[i], "none") == 0)
			continue;
		file = expand_authorized_keys(
		    options.authorized_keys_files[i], pw);

	{	glob_t gl;

		{	int r;
			temporarily_use_uid(pw);
			r = glob(file, 0, NULL, &gl);
			restore_uid();
			if (r != 0) {
				if (r != GLOB_NOMATCH)
					error_f("glob \"%s\" failed", file);
				free(file);
				continue;
			}
		}

		if (gl.gl_pathc > INT_MAX)
			fatal_f("too many glob results for \"%s\"", file);
		debug3_f("glob \"%s\" returned %zu matches", file, gl.gl_pathc);
		free(file);

		{	size_t j;
			for (j = 0; j < gl.gl_pathc; j++) {
				success = user_key_allowed2(pw, key, gl.gl_pathv[j],
				    remote_ip, remote_host, &opts);
				if (success) goto out;
				sshauthopt_free(opts);
				opts = NULL;
			}
		}
	}
	}
}

	xasprintf(&conn_id, "%s %d %s %d",
	    ssh_local_ipaddr(ssh), ssh_local_port(ssh),
	    remote_ip, ssh_remote_port(ssh));

	success = user_cert_trusted_ca(pw, key, remote_ip, remote_host, conn_id, rdomain, &opts);
	if (success) goto out;
	sshauthopt_free(opts);
	opts = NULL;

	success = user_key_command_allowed2(pw, key, remote_ip, remote_host, conn_id, rdomain, &opts);

 out:
	free(conn_id);
	if (success &&
	    !options.x509flags.validate_first &&
	    sshkey_is_x509(key)
	)
		success = (xkey_validate_cert(key) == 0);

	if (success && authoptsp != NULL) {
		*authoptsp = opts;
		opts = NULL;
	}
	sshauthopt_free(opts);
	return success;
}

Authmethod method_pubkey = {
	&methodcfg_pubkey,
	userauth_pubkey
};
