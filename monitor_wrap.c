/* $OpenBSD: monitor_wrap.c,v 1.123 2021/04/15 16:24:31 markus Exp $ */
/*
 * Copyright 2002 Niels Provos <provos@citi.umich.edu>
 * Copyright 2002 Markus Friedl <markus@openbsd.org>
 * All rights reserved.
 *
 * Copyright (c) 2007-2021 Roumen Petrov.  All rights reserved.
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
#include <sys/uio.h>

#include <errno.h>
#include <pwd.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#ifdef WITH_OPENSSL
#include <openssl/bn.h>
#include <openssl/dh.h>
#include <openssl/evp.h>
#endif

#include "openbsd-compat/sys-queue.h"
#include "xmalloc.h"
#include "ssh.h"
#include "ssh-x509.h"
#include "cipher.h"
#include "kex.h"
#include "hostfile.h"
#include "auth.h"
#include "auth-options.h"
#include "packet.h"
#include "mac.h"
#include "log.h"
#include "auth-pam.h"
#include "monitor.h"
#ifdef GSSAPI
#include "ssh-gss.h"
#endif
#include "monitor_wrap.h"
#include "compat.h"
#include "atomicio.h"
#include "monitor_fdpass.h"
#include "misc.h"

#include "channels.h"
#include "session.h"
#include "servconf.h"

#include "ssherr.h"

/* Imports */
extern struct monitor *pmonitor;
extern struct sshbuf *loginmsg;
extern ServerOptions options;

void
mm_log_handler(LogLevel level, const char *msg, void *ctx)
{
	struct sshbuf *log_msg;
	struct monitor *mon = (struct monitor *)ctx;
	int r;
	size_t len;

	if (mon->m_log_sendfd == -1)
		fatal_f("no log channel");

	if ((log_msg = sshbuf_new()) == NULL)
		fatal_f("sshbuf_new failed");

	if ((r = sshbuf_put_u32(log_msg, 0)) != 0 || /* length; filled below */
	    (r = sshbuf_put_u32(log_msg, level)) != 0 ||
	    (r = sshbuf_put_cstring(log_msg, msg)) != 0)
		fatal_fr(r, "assemble");
	if ((len = sshbuf_len(log_msg)) < 4 || len > 0xffffffff)
		fatal_f("bad length %zu", len);
	POKE_U32(sshbuf_mutable_ptr(log_msg), len - 4);
	if (atomicio(vwrite, mon->m_log_sendfd,
	    sshbuf_mutable_ptr(log_msg), len) != len)
		fatal_f("write: %s", strerror(errno));
	sshbuf_free(log_msg);
}

int
mm_is_monitor(void)
{
	/*
	 * m_pid is only set in the privileged part, and
	 * points to the unprivileged child.
	 */
	return (pmonitor && pmonitor->m_pid > 0);
}

void
mm_request_send(int sock, enum monitor_reqtype type, struct sshbuf *m)
{
	size_t mlen = sshbuf_len(m);
	u_char buf[5];

	debug3_f("entering, type %d", type);

	if (mlen >= 0xffffffff)
		fatal_f("bad length %zu", mlen);
	POKE_U32(buf, mlen + 1);
	buf[4] = (u_char) type;		/* 1st byte of payload is mesg-type */
	if (atomicio(vwrite, sock, buf, sizeof(buf)) != sizeof(buf))
		fatal_f("write: %s", strerror(errno));
	if (atomicio(vwrite, sock, sshbuf_mutable_ptr(m), mlen) != mlen)
		fatal_f("write: %s", strerror(errno));
}

void
mm_request_receive(int sock, struct sshbuf *m)
{
	u_char buf[4], *p = NULL;
	u_int msg_len;
	int r;

	debug3_f("entering");

	if (atomicio(read, sock, buf, sizeof(buf)) != sizeof(buf)) {
		if (errno == EPIPE)
			cleanup_exit(255);
		fatal_f("read: %s", strerror(errno));
	}
	msg_len = PEEK_U32(buf);
	if (msg_len > 256 * 1024)
		fatal_f("read: bad msg_len %d", msg_len);
	sshbuf_reset(m);
	if ((r = sshbuf_reserve(m, msg_len, &p)) != 0)
		fatal_fr(r, "reserve");
	if (atomicio(read, sock, p, msg_len) != msg_len)
		fatal_f("read: %s", strerror(errno));
}

void
mm_request_receive_expect(int sock, enum monitor_reqtype type, struct sshbuf *m)
{
	u_char rtype;
	int r;

	debug3_f("entering, type %d", type);

	mm_request_receive(sock, m);
	if ((r = sshbuf_get_u8(m, &rtype)) != 0)
		fatal_fr(r, "parse");
	if (rtype != type)
		fatal_f("read: rtype %d != type %d", rtype, type);
}

#ifdef WITH_OPENSSL
EVP_PKEY*
mm_kex_new_dh_group_bits(int min, int nbits, int max)
{
	int r;
	u_char success = 0;
	struct sshbuf *m;

	if ((m = sshbuf_new()) == NULL)
		fatal_f("sshbuf_new failed");
	if ((r = sshbuf_put_u32(m, min)) != 0 ||
	    (r = sshbuf_put_u32(m, nbits)) != 0 ||
	    (r = sshbuf_put_u32(m, max)) != 0)
		fatal_fr(r, "assemble");

	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_MODULI, m);

	debug3_f("waiting for MONITOR_ANS_MODULI");
	mm_request_receive_expect(pmonitor->m_recvfd, MONITOR_ANS_MODULI, m);

	if ((r = sshbuf_get_u8(m, &success)) != 0)
		fatal_fr(r, "parse success");
	if (success == 0)
		fatal_f("MONITOR_ANS_MODULI failed");

{	BIGNUM *p, *g;

	if ((r = sshbuf_get_bignum2(m, &p)) != 0 ||
	    (r = sshbuf_get_bignum2(m, &g)) != 0)
		fatal_fr(r, "parse group");

	debug3_f("remaining %zu", sshbuf_len(m));
	sshbuf_free(m);

	return kex_new_dh_group(p, g);
}
}
#endif

int
mm_Xkey_sign(struct ssh *ssh, ssh_sign_ctx *ctx, u_char **sigp, size_t *lenp,
    const u_char *data, size_t datalen
) {
	const char *hostkey_alg = ctx->alg;
	struct sshkey *key = ctx->key;
	struct kex *kex = *pmonitor->m_pkex;
	struct sshbuf *m;
	u_int ndx = kex->host_key_index(key, 0, ssh);
	int r;

	debug3_f("entering");
	if ((m = sshbuf_new()) == NULL)
		fatal_f("sshbuf_new failed");
	if ((r = sshbuf_put_u32(m, ndx)) != 0 ||
	    (r = sshbuf_put_string(m, data, datalen)) != 0 ||
	    (r = sshbuf_put_cstring(m, hostkey_alg)) != 0 ||
	    (r = sshbuf_put_compat(m, ctx->compat)) != 0)
		fatal_fr(r, "assemble");

	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_SIGN, m);

	debug3_f("waiting for MONITOR_ANS_SIGN");
	mm_request_receive_expect(pmonitor->m_recvfd, MONITOR_ANS_SIGN, m);
	if ((r = sshbuf_get_string(m, sigp, lenp)) != 0)
		fatal_fr(r, "parse");
	sshbuf_free(m);

	return (0);
}

#define GETPW(b, id) \
	do { \
		if ((r = sshbuf_get_string_direct(b, &p, &len)) != 0) \
			fatal_fr(r, "parse pw %s", #id); \
		if (len != sizeof(pw->id)) \
			fatal_f("bad length for %s", #id); \
		memcpy(&pw->id, p, len); \
	} while (0)

struct passwd *
mm_getpwnamallow(struct ssh *ssh, const char *username)
{
	struct sshbuf *m;
	struct passwd *pw;
	size_t len;
	u_int i;
	ServerOptions *newopts;
	int r;
	u_char ok;
	const u_char *p;

	debug3_f("entering");

	if ((m = sshbuf_new()) == NULL)
		fatal_f("sshbuf_new failed");
	if ((r = sshbuf_put_cstring(m, username)) != 0)
		fatal_fr(r, "assemble");

	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_PWNAM, m);

	debug3_f("waiting for MONITOR_ANS_PWNAM");
	mm_request_receive_expect(pmonitor->m_recvfd, MONITOR_ANS_PWNAM, m);

	if ((r = sshbuf_get_u8(m, &ok)) != 0)
		fatal_fr(r, "parse success");
	if (ok == 0) {
		pw = NULL;
		goto out;
	}

	pw = xcalloc(sizeof(*pw), 1);
	GETPW(m, pw_uid);
	GETPW(m, pw_gid);
#ifdef HAVE_STRUCT_PASSWD_PW_CHANGE
	GETPW(m, pw_change);
#endif
#ifdef HAVE_STRUCT_PASSWD_PW_EXPIRE
	GETPW(m, pw_expire);
#endif
	if ((r = sshbuf_get_cstring(m, &pw->pw_name, NULL)) != 0 ||
	    (r = sshbuf_get_cstring(m, &pw->pw_passwd, NULL)) != 0 ||
#ifdef HAVE_STRUCT_PASSWD_PW_GECOS
	    (r = sshbuf_get_cstring(m, &pw->pw_gecos, NULL)) != 0 ||
#endif
#ifdef HAVE_STRUCT_PASSWD_PW_CLASS
	    (r = sshbuf_get_cstring(m, &pw->pw_class, NULL)) != 0 ||
#endif
	    (r = sshbuf_get_cstring(m, &pw->pw_dir, NULL)) != 0 ||
	    (r = sshbuf_get_cstring(m, &pw->pw_shell, NULL)) != 0)
		fatal_fr(r, "parse pw");

out:
	/* copy options block as a Match directive may have changed some */
	if ((r = sshbuf_get_string_direct(m, &p, &len)) != 0)
		fatal_fr(r, "parse opts");
	if (len != sizeof(*newopts))
		fatal_f("option block size mismatch");
	newopts = xcalloc(sizeof(*newopts), 1);
	memcpy(newopts, p, sizeof(*newopts));

	r = sshbuf_get_cstring(m, &newopts->hostbased_algorithms, NULL);
	if (r != 0)
		fatal_fr(r, "parse hostbased_algorithms");
	if (*newopts->hostbased_algorithms == '\0') {
		free(newopts->hostbased_algorithms);
		newopts->hostbased_algorithms = xstrdup("*");
	}

	r = sshbuf_get_cstring(m, &newopts->pubkey_algorithms, NULL);
	if (r != 0)
		fatal_fr(r, "parse pubkey_algorithms");
	if (*newopts->pubkey_algorithms == '\0') {
		free(newopts->pubkey_algorithms);
		newopts->pubkey_algorithms = xstrdup("*");
	}

#define M_CP_STROPT(x) do { \
		if (newopts->x != NULL && \
		    (r = sshbuf_get_cstring(m, &newopts->x, NULL)) != 0) \
			fatal_fr(r, "parse %s", #x); \
	} while (0)
#define M_CP_STRARRAYOPT(x, nx) do { \
		newopts->x = newopts->nx == 0 ? \
		    NULL : xcalloc(newopts->nx, sizeof(*newopts->x)); \
		for (i = 0; i < newopts->nx; i++) { \
			if ((r = sshbuf_get_cstring(m, \
			    &newopts->x[i], NULL)) != 0) \
				fatal_fr(r, "parse %s", #x); \
		} \
	} while (0)
	/* See comment in servconf.h */
	COPY_MATCH_STRING_OPTS();

#undef M_CP_STROPT
#undef M_CP_STRARRAYOPT

	copy_set_server_options(&options, newopts, 1);
	log_change_level(options.log_level);
	log_verbose_init(options.log_verbose, options.num_log_verbose);
	process_permitopen(ssh, &options);
	free(newopts);

	sshbuf_free(m);

	return (pw);
}

char *
mm_auth2_read_banner(void)
{
	struct sshbuf *m;
	char *banner;
	int r;

	debug3_f("entering");

	if ((m = sshbuf_new()) == NULL)
		fatal_f("sshbuf_new failed");
	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_AUTH2_READ_BANNER, m);
	sshbuf_reset(m);

	mm_request_receive_expect(pmonitor->m_recvfd,
	    MONITOR_ANS_AUTH2_READ_BANNER, m);
	if ((r = sshbuf_get_cstring(m, &banner, NULL)) != 0)
		fatal_fr(r, "parse");
	sshbuf_free(m);

	/* treat empty banner as missing banner */
	if (strlen(banner) == 0) {
		free(banner);
		banner = NULL;
	}
	return (banner);
}

/* Inform the privileged process about service and style */

void
mm_inform_authserv(char *service, char *style)
{
	struct sshbuf *m;
	int r;

	debug3_f("entering");

	if ((m = sshbuf_new()) == NULL)
		fatal_f("sshbuf_new failed");
	if ((r = sshbuf_put_cstring(m, service)) != 0 ||
	    (r = sshbuf_put_cstring(m, style ? style : "")) != 0)
		fatal_fr(r, "assemble");

	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_AUTHSERV, m);

	sshbuf_free(m);
}

/* Do the password authentication */
int
mm_auth_password(struct ssh *ssh, char *password)
{
	struct sshbuf *m;
	int r, authenticated = 0;
#ifdef USE_PAM
	int maxtries = 0;
#endif
	u_int32_t val;

	UNUSED(ssh);
	debug3_f("entering");

	if ((m = sshbuf_new()) == NULL)
		fatal_f("sshbuf_new failed");
	if ((r = sshbuf_put_cstring(m, password)) != 0)
		fatal_fr(r, "assemble");
	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_AUTHPASSWORD, m);

	debug3_f("waiting for MONITOR_ANS_AUTHPASSWORD");
	mm_request_receive_expect(pmonitor->m_recvfd,
	    MONITOR_ANS_AUTHPASSWORD, m);

	if ((r = sshbuf_get_u32(m, &val)) != 0) /*authenticated*/
		fatal_fr(r, "parse");
	authenticated = val;
#ifdef USE_PAM
	if ((r = sshbuf_get_u32(m, &val)) != 0) /*maxtries*/
		fatal_fr(r, "parse PAM");
	maxtries = val;
	if (maxtries > INT_MAX)
		fatal_f("bad maxtries");
	sshpam_set_maxtries_reached(maxtries);
#endif

	sshbuf_free(m);

	debug3_f("user %sauthenticated", authenticated ? "" : "not ");
	return (authenticated);
}

static int
mm_xkey_allowed(enum mm_keytype type, const char *user, const char *host,
    ssh_verify_ctx *ctx, int pubkey_auth_attempt, struct sshauthopt **authoptp)
{
	const char *pkalg = ctx->alg;
	struct sshbuf *m;
	int r, allowed = 0;
	struct sshauthopt *opts = NULL;
	u_int32_t val;

	debug3_f("entering");

	if (authoptp != NULL)
		*authoptp = NULL;

	if (pkalg == NULL) pkalg = sshkey_ssh_name(ctx->key);

	if ((m = sshbuf_new()) == NULL)
		fatal_f("sshbuf_new failed");
	if ((r = sshbuf_put_u32(m, type)) != 0 ||
	    (r = sshbuf_put_cstring(m, user ? user : "")) != 0 ||
	    (r = sshbuf_put_cstring(m, host ? host : "")) != 0 ||
	    (r = sshbuf_put_cstring(m, pkalg)) != 0 ||
	    (r = Xkey_puts(pkalg, ctx->key, m)) != 0 ||
	    (r = sshbuf_put_u32(m, pubkey_auth_attempt)) != 0)
		fatal_fr(r, "assemble");

	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_KEYALLOWED, m);

	debug3_f("waiting for MONITOR_ANS_KEYALLOWED");
	mm_request_receive_expect(pmonitor->m_recvfd,
	    MONITOR_ANS_KEYALLOWED, m);

	if ((r = sshbuf_get_u32(m, &val)) != 0) /*allowed*/
		fatal_fr(r, "parse");
	allowed = val;
	if (allowed && type == MM_USERKEY &&
	    (r = sshauthopt_deserialise(m, &opts)) != 0)
		fatal_fr(r, "sshauthopt_deserialise");
	sshbuf_free(m);

	if (authoptp != NULL) {
		*authoptp = opts;
		opts = NULL;
	}
	sshauthopt_free(opts);

	return allowed;
}

int
mm_user_xkey_allowed(
    struct ssh *ssh, struct passwd *pw, ssh_verify_ctx *ctx,
    int pubkey_auth_attempt, struct sshauthopt **authoptp
) {
	UNUSED(ssh);
	UNUSED(pw);
	return (mm_xkey_allowed(MM_USERKEY, NULL, NULL, ctx,
	    pubkey_auth_attempt, authoptp));
}

int
mm_hostbased_xkey_allowed(
    struct ssh *ssh, struct passwd *pw, ssh_verify_ctx *ctx,
    const char *user, const char *host
) {
	UNUSED(ssh);
	UNUSED(pw);
	return (mm_xkey_allowed(MM_HOSTKEY, user, host, ctx, 0, NULL));
}

/*
 * This key verify needs to send the key type along, because the
 * privileged parent makes the decision if the key is allowed
 * for authentication.
 */

int
mm_Xkey_verify(
    ssh_verify_ctx *ctx,
    const u_char *sig, size_t siglen,
    const u_char *data, size_t datalen
) {
	const char *pkalg = ctx->alg;
	struct sshbuf *m;
	u_int32_t encoded_ret = 0;
	int r;

	debug3_f("entering");

	if (pkalg == NULL) pkalg = sshkey_ssh_name(ctx->key);

	if ((m = sshbuf_new()) == NULL)
		fatal_f("sshbuf_new failed");
	if ((r = sshbuf_put_cstring(m, pkalg)) != 0 ||
	    (r = Xkey_puts(pkalg, ctx->key, m)) != 0 ||
	    (r = sshbuf_put_string(m, sig, siglen)) != 0 ||
	    (r = sshbuf_put_string(m, data, datalen)) != 0)
		fatal_fr(r, "assemble");

	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_KEYVERIFY, m);

	debug3_f("waiting for MONITOR_ANS_KEYVERIFY");
	mm_request_receive_expect(pmonitor->m_recvfd,
	    MONITOR_ANS_KEYVERIFY, m);

	if ((r = sshbuf_get_u32(m, &encoded_ret)) != 0)
		fatal_fr(r, "parse");

	sshbuf_free(m);

	if (encoded_ret != 0)
		return SSH_ERR_SIGNATURE_INVALID;
	return 0;
}

void
mm_send_keystate(struct ssh *ssh, struct monitor *monitor)
{
	struct sshbuf *m;
	int r;

	if ((m = sshbuf_new()) == NULL)
		fatal_f("sshbuf_new failed");
	if ((r = ssh_packet_get_state(ssh, m)) != 0)
		fatal_fr(r, "ssh_packet_get_state");
	mm_request_send(monitor->m_recvfd, MONITOR_REQ_KEYEXPORT, m);
	debug3_f("finished sending state");
	sshbuf_free(m);
}

int
mm_pty_allocate(int *ptyfd, int *ttyfd, char *namebuf, size_t namebuflen)
{
	struct sshbuf *m;
	char *p, *msg;
	int tmp1 = -1, tmp2 = -1, r;
	u_int32_t success = 0;

	/* Kludge: ensure there are fds free to receive the pty/tty */
	if ((tmp1 = dup(pmonitor->m_recvfd)) == -1 ||
	    (tmp2 = dup(pmonitor->m_recvfd)) == -1) {
		error_f("cannot allocate fds for pty");
		if (tmp1 > 0)
			close(tmp1);
		if (tmp2 > 0)
			close(tmp2);
		return 0;
	}
	close(tmp1);
	close(tmp2);

	if ((m = sshbuf_new()) == NULL)
		fatal_f("sshbuf_new failed");
	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_PTY, m);

	debug3_f("waiting for MONITOR_ANS_PTY");
	mm_request_receive_expect(pmonitor->m_recvfd, MONITOR_ANS_PTY, m);

	if ((r = sshbuf_get_u32(m, &success)) != 0)
		fatal_fr(r, "parse success");
	if (success == 0) {
		debug3_f("pty alloc failed");
		sshbuf_free(m);
		return (0);
	}
	if ((r = sshbuf_get_cstring(m, &p, NULL)) != 0 ||
	    (r = sshbuf_get_cstring(m, &msg, NULL)) != 0)
		fatal_fr(r, "parse");
	sshbuf_free(m);

	strlcpy(namebuf, p, namebuflen); /* Possible truncation */
	free(p);

	if ((r = sshbuf_put(loginmsg, msg, strlen(msg))) != 0)
		fatal_fr(r, "put loginmsg");
	free(msg);

	if ((*ptyfd = mm_receive_fd(pmonitor->m_recvfd)) == -1 ||
	    (*ttyfd = mm_receive_fd(pmonitor->m_recvfd)) == -1)
		fatal_f("receive fds failed");

	/* Success */
	return (1);
}

void
mm_session_pty_cleanup2(Session *s)
{
	struct sshbuf *m;
	int r;

	if (s->ttyfd == -1)
		return;
	if ((m = sshbuf_new()) == NULL)
		fatal_f("sshbuf_new failed");
	if ((r = sshbuf_put_cstring(m, s->tty)) != 0)
		fatal_fr(r, "assemble");
	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_PTYCLEANUP, m);
	sshbuf_free(m);

	/* closed dup'ed master */
	if (s->ptymaster != -1 && close(s->ptymaster) == -1)
		error("close(s->ptymaster/%d): %s",
		    s->ptymaster, strerror(errno));

	/* unlink pty from session */
	s->ttyfd = -1;
}

#ifdef USE_PAM
void
mm_start_pam(struct ssh *ssh)
{
	struct sshbuf *m;

	UNUSED(ssh);
	debug3_f("entering");
	if (!options.use_pam)
		fatal("UsePAM=no, but ended up in %s anyway", __func__);
	if ((m = sshbuf_new()) == NULL)
		fatal_f("sshbuf_new failed");
	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_PAM_START, m);

	sshbuf_free(m);
}

u_int
mm_do_pam_account(void)
{
	struct sshbuf *m;
	u_int32_t ret;
	char *msg;
	size_t msglen;
	int r;

	debug3_f("entering");
	if (!options.use_pam)
		fatal("UsePAM=no, but ended up in %s anyway", __func__);

	if ((m = sshbuf_new()) == NULL)
		fatal_f("sshbuf_new failed");
	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_PAM_ACCOUNT, m);

	mm_request_receive_expect(pmonitor->m_recvfd,
	    MONITOR_ANS_PAM_ACCOUNT, m);
	if ((r = sshbuf_get_u32(m, &ret)) != 0 ||
	    (r = sshbuf_get_cstring(m, &msg, &msglen)) != 0 ||
	    (r = sshbuf_put(loginmsg, msg, msglen)) != 0)
		fatal_fr(r, "assemble message");

	free(msg);
	sshbuf_free(m);

	debug3_f("returning %d", ret);

	return (ret);
}

void *
mm_sshpam_init_ctx(Authctxt *authctxt)
{
	struct sshbuf *m;
	u_int32_t success;
	int r;

	debug3_f("entering");
	if ((m = sshbuf_new()) == NULL)
		fatal_f("sshbuf_new failed");
	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_PAM_INIT_CTX, m);
	debug3_f("waiting for MONITOR_ANS_PAM_INIT_CTX");
	mm_request_receive_expect(pmonitor->m_recvfd,
	    MONITOR_ANS_PAM_INIT_CTX, m);
	if ((r = sshbuf_get_u32(m, &success)) != 0)
		fatal_fr(r, "parse");
	if (success == 0) {
		debug3_f("pam_init_ctx failed");
		sshbuf_free(m);
		return (NULL);
	}
	sshbuf_free(m);
	return (authctxt);
}

int
mm_sshpam_query(void *ctx, char **name, char **info,
    u_int *num, char ***prompts, u_int **echo_on)
{
	struct sshbuf *m;
	u_int i;
	u_int32_t ret, n, val;
	int r;

	UNUSED(ctx);
	debug3_f("entering");
	if ((m = sshbuf_new()) == NULL)
		fatal_f("sshbuf_new failed");
	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_PAM_QUERY, m);
	debug3_f("waiting for MONITOR_ANS_PAM_QUERY");
	mm_request_receive_expect(pmonitor->m_recvfd, MONITOR_ANS_PAM_QUERY, m);
	if ((r = sshbuf_get_u32(m, &ret)) != 0 ||
	    (r = sshbuf_get_cstring(m, name, NULL)) != 0 ||
	    (r = sshbuf_get_cstring(m, info, NULL)) != 0 ||
	    (r = sshbuf_get_u32(m, &n)) != 0 ||
	    (r = sshbuf_get_u32(m, &val)) != 0) /*num*/
		fatal_fr(r, "parse");
	*num = val;
	debug3_f("pam_query returned %d", (int)ret);
	sshpam_set_maxtries_reached(n);
	if (*num > PAM_MAX_NUM_MSG)
		fatal_f("received %u PAM messages, expected <= %u",
		    *num, PAM_MAX_NUM_MSG);
	*prompts = xcalloc((*num + 1), sizeof(char *));
	*echo_on = xcalloc((*num + 1), sizeof(u_int));
	for (i = 0; i < *num; ++i) {
		if ((r = sshbuf_get_cstring(m, &((*prompts)[i]), NULL)) != 0 ||
		    (r = sshbuf_get_u32(m, &val)) != 0) /*echo_on*/
			fatal_fr(r, "parse prompt %u", i);
		(*echo_on)[i] = val;
	}
	sshbuf_free(m);
	return (ret);
}

int
mm_sshpam_respond(void *ctx, u_int num, char **resp)
{
	struct sshbuf *m;
	u_int i;
	u_int32_t n;
	int r, ret;

	UNUSED(ctx);
	debug3_f("entering");
	if ((m = sshbuf_new()) == NULL)
		fatal_f("sshbuf_new failed");
	if ((r = sshbuf_put_u32(m, num)) != 0)
		fatal_fr(r, "assemble");
	for (i = 0; i < num; ++i) {
		if ((r = sshbuf_put_cstring(m, resp[i])) != 0)
			fatal_fr(r, "assemble respond %u", i);
	}
	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_PAM_RESPOND, m);
	debug3_f("waiting for MONITOR_ANS_PAM_RESPOND");
	mm_request_receive_expect(pmonitor->m_recvfd,
	    MONITOR_ANS_PAM_RESPOND, m);
	if ((r = sshbuf_get_u32(m, &n)) != 0)
		fatal_fr(r, "parse");
	ret = (int)n; /* XXX */
	debug3_f("pam_respond returned %d", ret);
	sshbuf_free(m);
	return (ret);
}

void
mm_sshpam_free_ctx(void *ctxtp)
{
	struct sshbuf *m;

	UNUSED(ctxtp);
	debug3_f("entering");
	if ((m = sshbuf_new()) == NULL)
		fatal_f("sshbuf_new failed");
	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_PAM_FREE_CTX, m);
	debug3_f("waiting for MONITOR_ANS_PAM_FREE_CTX");
	mm_request_receive_expect(pmonitor->m_recvfd,
	    MONITOR_ANS_PAM_FREE_CTX, m);
	sshbuf_free(m);
}
#endif /* USE_PAM */

/* Request process termination */

void
mm_terminate(void)
{
	struct sshbuf *m;

	if ((m = sshbuf_new()) == NULL)
		fatal_f("sshbuf_new failed");
	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_TERM, m);
	sshbuf_free(m);
}

static void
mm_chall_setup(char **name, char **infotxt, u_int *numprompts,
    char ***prompts, u_int **echo_on)
{
	*name = xstrdup("");
	*infotxt = xstrdup("");
	*numprompts = 1;
	*prompts = xcalloc(*numprompts, sizeof(char *));
	*echo_on = xcalloc(*numprompts, sizeof(u_int));
	(*echo_on)[0] = 0;
}

int
mm_bsdauth_query(void *ctx, char **name, char **infotxt,
   u_int *numprompts, char ***prompts, u_int **echo_on)
{
	struct sshbuf *m;
	u_int32_t success;
	char *challenge;
	int r;

	UNUSED(ctx);
	debug3_f("entering");

	if ((m = sshbuf_new()) == NULL)
		fatal_f("sshbuf_new failed");
	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_BSDAUTHQUERY, m);

	mm_request_receive_expect(pmonitor->m_recvfd,
	    MONITOR_ANS_BSDAUTHQUERY, m);
	if ((r = sshbuf_get_u32(m, &success)) != 0)
		fatal_fr(r, "parse success");
	if (success == 0) {
		debug3_f("no challenge");
		sshbuf_free(m);
		return (-1);
	}

	/* Get the challenge, and format the response */
	if ((r = sshbuf_get_cstring(m, &challenge, NULL)) != 0)
		fatal_fr(r, "parse challenge");
	sshbuf_free(m);

	mm_chall_setup(name, infotxt, numprompts, prompts, echo_on);
	(*prompts)[0] = challenge;

	debug3_f("received challenge: %s", challenge);

	return (0);
}

int
mm_bsdauth_respond(void *ctx, u_int numresponses, char **responses)
{
	struct sshbuf *m;
	u_int32_t authok;
	int r;

	UNUSED(ctx);
	debug3_f("entering");
	if (numresponses != 1)
		return (-1);

	if ((m = sshbuf_new()) == NULL)
		fatal_f("sshbuf_new failed");
	if ((r = sshbuf_put_cstring(m, responses[0])) != 0)
		fatal_fr(r, "assemble");
	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_BSDAUTHRESPOND, m);

	mm_request_receive_expect(pmonitor->m_recvfd,
	    MONITOR_ANS_BSDAUTHRESPOND, m);

	if ((r = sshbuf_get_u32(m, &authok)) != 0)
		fatal_fr(r, "parse");
	sshbuf_free(m);

	return ((authok == 0) ? -1 : 0);
}

#ifdef SSH_AUDIT_EVENTS
void
mm_audit_event(struct ssh *ssh, ssh_audit_event_t event)
{
	struct sshbuf *m;
	int r;

	UNUSED(ssh);
	debug3_f("entering");

	if ((m = sshbuf_new()) == NULL)
		fatal_f("sshbuf_new failed");
	if ((r = sshbuf_put_u32(m, event)) != 0)
		fatal_fr(r, "assemble");

	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_AUDIT_EVENT, m);
	sshbuf_free(m);
}

void
mm_audit_run_command(const char *command)
{
	struct sshbuf *m;
	int r;

	debug3_f("entering command %s", command);

	if ((m = sshbuf_new()) == NULL)
		fatal_f("sshbuf_new failed");
	if ((r = sshbuf_put_cstring(m, command)) != 0)
		fatal_fr(r, "assemble");

	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_AUDIT_COMMAND, m);
	sshbuf_free(m);
}
#endif /* SSH_AUDIT_EVENTS */

#ifdef GSSAPI
OM_uint32
mm_ssh_gssapi_server_ctx(Gssctxt **ctx, gss_OID goid)
{
	struct sshbuf *m;
	u_int32_t major;
	int r;

	/* Client doesn't get to see the context */
	*ctx = NULL;

	if ((m = sshbuf_new()) == NULL)
		fatal_f("sshbuf_new failed");
	if ((r = sshbuf_put_string(m, goid->elements, goid->length)) != 0)
		fatal_fr(r, "assemble");

	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_GSSSETUP, m);
	mm_request_receive_expect(pmonitor->m_recvfd, MONITOR_ANS_GSSSETUP, m);

	if ((r = sshbuf_get_u32(m, &major)) != 0)
		fatal_fr(r, "parse");

	sshbuf_free(m);
	return (major);
}

OM_uint32
mm_ssh_gssapi_accept_ctx(Gssctxt *ctx, gss_buffer_desc *in,
    gss_buffer_desc *out, OM_uint32 *flagsp)
{
	struct sshbuf *m;
	u_int32_t major, flags;
	int r;

	UNUSED(ctx);
	if ((m = sshbuf_new()) == NULL)
		fatal_f("sshbuf_new failed");
	if ((r = sshbuf_put_string(m, in->value, in->length)) != 0)
		fatal_fr(r, "assemble");

	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_GSSSTEP, m);
	mm_request_receive_expect(pmonitor->m_recvfd, MONITOR_ANS_GSSSTEP, m);

	if ((r = sshbuf_get_u32(m, &major)) != 0 ||
	    (r = ssh_gssapi_get_buffer_desc(m, out)) != 0)
		fatal_fr(r, "parse");
	if (flagsp != NULL) {
		if ((r = sshbuf_get_u32(m, &flags)) != 0)
			fatal_fr(r, "parse flags");
		*flagsp = flags;
	}

	sshbuf_free(m);

	return (major);
}

OM_uint32
mm_ssh_gssapi_checkmic(Gssctxt *ctx, gss_buffer_t gssbuf, gss_buffer_t gssmic)
{
	struct sshbuf *m;
	u_int32_t major;
	int r;

	UNUSED(ctx);
	if ((m = sshbuf_new()) == NULL)
		fatal_f("sshbuf_new failed");
	if ((r = sshbuf_put_string(m, gssbuf->value, gssbuf->length)) != 0 ||
	    (r = sshbuf_put_string(m, gssmic->value, gssmic->length)) != 0)
		fatal_fr(r, "assemble");

	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_GSSCHECKMIC, m);
	mm_request_receive_expect(pmonitor->m_recvfd,
	    MONITOR_ANS_GSSCHECKMIC, m);

	if ((r = sshbuf_get_u32(m, &major)) != 0)
		fatal_fr(r, "parse");
	sshbuf_free(m);
	return(major);
}

int
mm_ssh_gssapi_userok(char *user)
{
	struct sshbuf *m;
	u_int32_t authenticated = 0;
	int r;

	UNUSED(user);
	if ((m = sshbuf_new()) == NULL)
		fatal_f("sshbuf_new failed");

	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_GSSUSEROK, m);
	mm_request_receive_expect(pmonitor->m_recvfd,
	    MONITOR_ANS_GSSUSEROK, m);

	if ((r = sshbuf_get_u32(m, &authenticated)) != 0)
		fatal_fr(r, "parse");

	sshbuf_free(m);
	debug3_f("user %sauthenticated", authenticated ? "" : "not ");
	return (authenticated);
}
#endif /* GSSAPI */
