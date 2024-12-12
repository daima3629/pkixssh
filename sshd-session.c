/* $OpenBSD: sshd-session.c,v 1.9 2024/09/09 02:39:57 djm Exp $ */
/*
 * SSH2 implementation:
 * Privilege Separation:
 *
 * Copyright (c) 2000, 2001, 2002 Markus Friedl.  All rights reserved.
 * Copyright (c) 2002 Niels Provos.  All rights reserved.
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

/* Prototypes for various functions defined later in this file. */
void destroy_sensitive_data(void);
void demote_sensitive_data(void);
static void do_ssh2_kex(struct ssh *);

/*
 * Signal handler for the alarm after the login grace period has expired.
 * As usual, this may only take signal-safe actions, even though it is
 * terminal.
 */
static void
grace_alarm_handler(int sig)
{
	UNUSED(sig);
#if 0
/* NOTE: "OpenSSH bug 3286". See sshsigdie() in log.c
 * PKIX-SSH was not impacted as it does not activate logs in sigdie.
 * With removing explicit send of alarm signal log is activated.
 */
	if (use_privsep && pmonitor != NULL && pmonitor->m_pid > 0)
		kill(pmonitor->m_pid, SIGALRM);
#endif

	/*
	 * Try to kill any processes that we have spawned, E.g. authorized
	 * keys command helpers or privsep children.
	 */
	if (getpgid(0) == getpid()) {
#ifdef HAVE_SIGACTION
		struct sigaction sa;

		/* mask all other signals while in handler */
		memset(&sa, 0, sizeof(sa));
		sa.sa_handler = SIG_IGN;
		sigfillset(&sa.sa_mask);
#if defined(SA_RESTART) && !defined(BROKEN_SA_RESTART)
		sa.sa_flags = SA_RESTART;
#endif
		(void)sigaction(SIGTERM, &sa, NULL);
#else
		ssh_signal(SIGTERM, SIG_IGN);
#endif
		kill(0, SIGTERM);
	}

	/* Log error and exit. */
	sigdie("Timeout before authentication for %s port %d",
	    ssh_remote_ipaddr(the_active_state),
	    ssh_remote_port(the_active_state));
}

#undef USE_GRACE_ALARM_TIMER
#if defined(HAVE_SETITIMER)
/* TODO: setitimer(2) is obsolete, to use timer_settimer(2) */
#  define USE_GRACE_ALARM_TIMER	1
#endif
/*
 * We don't want to listen forever unless the other side
 * successfully authenticates itself.  So we set up an alarm which is
 * cleared after successful authentication.  A limit of zero
 * indicates no limit. Note that we don't set the alarm in debugging
 * mode; it is just annoying to have the server exit just when you
 * are about to discover the bug.
 */
static inline void
grace_alarm_start(int grace_time) {
	if (debug_flag) return;
	if (grace_time <= 0) return;

#ifdef USE_GRACE_ALARM_TIMER
{	struct itimerval itv;
	int ujitter = arc4random_uniform(4 * 1000000);

	timerclear(&itv.it_interval);
	itv.it_value.tv_sec = grace_time;
	itv.it_value.tv_sec += ujitter / 1000000;
	itv.it_value.tv_usec = ujitter % 1000000;

	if (setitimer(ITIMER_REAL, &itv, NULL) == -1)
		fatal("login grace time setitimer failed");
}
#else
	alarm(grace_time);
#endif
}

/*
 * Cancel the alarm we set to limit the time taken for
 * authentication.
 */
static inline void
grace_alarm_stop(void) {
#ifdef USE_GRACE_ALARM_TIMER
{	struct itimerval itv;

	timerclear(&itv.it_interval);
	timerclear(&itv.it_value);

	if (setitimer(ITIMER_REAL, &itv, NULL) == -1)
		fatal("login grace time clear failed");
}
#else
	alarm(0);
#endif
}

/* Destroy the host and server keys.  They will no longer be needed. */
void
destroy_sensitive_data(void)
{
	u_int i;

	for (i = 0; i < options.num_host_key_files; i++) {
		if (sensitive_data.host_keys[i]) {
			sshkey_free(sensitive_data.host_keys[i]);
			sensitive_data.host_keys[i] = NULL;
		}
		if (sensitive_data.host_certificates[i]) {
			sshkey_free(sensitive_data.host_certificates[i]);
			sensitive_data.host_certificates[i] = NULL;
		}
	}
}

/* Demote private to public keys for network child */
void
demote_sensitive_data(void)
{
	struct sshkey *tmp;
	u_int i;
	int r;

	for (i = 0; i < options.num_host_key_files; i++) {
		if (sensitive_data.host_keys[i]) {
			if ((r = sshkey_from_private(
			    sensitive_data.host_keys[i], &tmp)) != 0)
				fatal_r(r, "could not demote host %s key",
				    sshkey_type(sensitive_data.host_keys[i]));
			sshkey_free(sensitive_data.host_keys[i]);
			sensitive_data.host_keys[i] = tmp;
		}
		/* Certs do not need demotion */
	}
}

static void
reseed_prngs(void)
{
	u_int32_t rnd[256];

#ifdef WITH_OPENSSL
	RAND_poll();
#endif
	arc4random_stir(); /* noop on recent arc4random() implementations */
	arc4random_buf(rnd, sizeof(rnd)); /* let arc4random notice PID change */

#ifdef WITH_OPENSSL
	RAND_seed(rnd, sizeof(rnd));
	/* give libcrypto a chance to notice the PID change */
	if ((RAND_bytes((u_char *)rnd, 1)) <= 0)
		fatal_f("RAND_bytes failed");
#endif

	explicit_bzero(rnd, sizeof(rnd));
}

static void
privsep_preauth_child(void)
{
	gid_t gidset[1];

	/* Enable keyboard-interactive devices for privilege separation */
	privsep_challenge_enable();

#ifdef GSSAPI
	/* Cache supported mechanism OIDs for later use */
	ssh_gssapi_prepare_supported_oids();
#endif

	reseed_prngs();

	/* Demote the private keys to public keys. */
	demote_sensitive_data();

	/* Demote the child */
	if (privsep_chroot) {
		/* Change our root directory */
		if (chroot(_PATH_PRIVSEP_CHROOT_DIR) == -1)
			fatal("chroot(\"%s\"): %s", _PATH_PRIVSEP_CHROOT_DIR,
			    strerror(errno));
		if (chdir("/") == -1)
			fatal("chdir(\"/\"): %s", strerror(errno));

		/* Drop our privileges */
		debug3("privsep user:group %u:%u", (u_int)privsep_pw->pw_uid,
		    (u_int)privsep_pw->pw_gid);
		gidset[0] = privsep_pw->pw_gid;
		if (setgroups(1, gidset) == -1)
			fatal("setgroups: %.100s", strerror(errno));
		permanently_set_uid(privsep_pw);
	}
}

static int
privsep_preauth(struct ssh *ssh)
{
	int status, r;
	pid_t pid;
	struct ssh_sandbox *box = NULL;

	/* Set up unprivileged child process to deal with network data */
	pmonitor = monitor_init();
	/* Store a pointer to the kex for later rekeying */
	pmonitor->m_pkex = &ssh->kex;

	if (use_privsep == PRIVSEP_ON)
		box = ssh_sandbox_init(pmonitor);
	pid = fork();
	if (pid == -1) {
		fatal("fork of unprivileged child failed");
	} else if (pid != 0) {
		debug2("Network child is on pid %ld", (long)pid);

		pmonitor->m_pid = pid;
		if (have_agent) {
			r = ssh_get_authentication_socket(&auth_sock);
			if (r != 0) {
				error_r(r, "Could not get agent socket");
				have_agent = 0;
			}
		}
		if (box != NULL)
			ssh_sandbox_parent_preauth(box, pid);
		monitor_child_preauth(ssh, pmonitor);

		/* Wait for the child's exit status */
		while (waitpid(pid, &status, 0) == -1) {
			if (errno == EINTR)
				continue;
			pmonitor->m_pid = -1;
			fatal_f("waitpid: %s", strerror(errno));
		}
		privsep_is_preauth = 0;
		pmonitor->m_pid = -1;
		if (WIFEXITED(status)) {
			if (WEXITSTATUS(status) != 0)
				fatal_f("preauth child exited with status %d",
				    WEXITSTATUS(status));
		} else if (WIFSIGNALED(status))
			fatal_f("preauth child terminated by signal %d",
			    WTERMSIG(status));
		if (box != NULL)
			ssh_sandbox_parent_finish(box);
		return 1;
	} else {
		/* child */
		close(pmonitor->m_sendfd);
		close(pmonitor->m_log_recvfd);

		/* Arrange for logging to be sent to the monitor */
		set_log_handler(mm_log_handler, pmonitor);

		privsep_preauth_child();
		setproctitle("%s", "[net]");
		if (box != NULL)
			ssh_sandbox_child(box);

		return 0;
	}
}

static void
privsep_postauth(struct ssh *ssh, Authctxt *authctxt)
{
#ifdef DISABLE_FD_PASSING
	if (1) {
#else
	if (authctxt->pw->pw_uid == 0) {
#endif
		/* File descriptor passing is broken or root login */
		use_privsep = 0;
		goto skip;
	}

	/* New socket pair */
	monitor_reinit(pmonitor);

	pmonitor->m_pid = fork();
	if (pmonitor->m_pid == -1)
		fatal("fork of unprivileged child failed");
	else if (pmonitor->m_pid != 0) {
		verbose("User child is on pid %ld", (long)pmonitor->m_pid);
		sshbuf_reset(loginmsg);
		monitor_clear_keystate(ssh);
		monitor_child_postauth(ssh, pmonitor);

		/* NEVERREACHED */
		exit(0);
	}

	/* child */

	close(pmonitor->m_sendfd);
	pmonitor->m_sendfd = -1;

	/* Demote the private keys to public keys. */
	demote_sensitive_data();

	reseed_prngs();

	/* Drop privileges */
	do_setusercontext(authctxt->pw);

 skip:
	/* It is safe now to apply the key state */
	monitor_apply_keystate(ssh);

	/*
	 * Tell the packet layer that authentication was successful, since
	 * this information is not part of the key state.
	 */
	ssh_packet_set_authenticated(ssh);
}

static struct sshkey *
get_hostkey_by_type(int type, int subtype, int need_private, struct ssh *ssh)
{
	u_int i;
	struct sshkey *key;

	UNUSED(ssh);
	for (i = 0; i < options.num_host_key_files; i++) {
		switch (type) {
		case KEY_RSA_CERT:
	#ifdef WITH_DSA
		case KEY_DSA_CERT:
	#endif
		case KEY_ECDSA_CERT:
		case KEY_ED25519_CERT:
	#ifdef WITH_XMSS
		case KEY_XMSS_CERT:
	#endif
			key = sensitive_data.host_certificates[i];
			break;
		default:
			key = sensitive_data.host_keys[i];
			if (key == NULL && !need_private)
				key = sensitive_data.host_pubkeys[i];
			break;
		}
		if (key != NULL && key->type == type &&
		    (subtype == -1 || subtype == key->ecdsa_nid)
		)
			return need_private ?
			    sensitive_data.host_keys[i] : key;
	}
	return NULL;
}

static struct sshkey*
get_hostkey_by_alg(const char* alg, int need_private, struct ssh *ssh) {
	u_int i;
	struct sshkey *key;

	UNUSED(ssh);
	for (i = 0; i < options.num_host_key_files; i++) {
		key = sensitive_data.host_keys[i];
		if (key == NULL && !need_private)
			key = sensitive_data.host_pubkeys[i];

		if (key == NULL) continue;

	{	const char **s;
		for (s = sensitive_data.host_algorithms[i];
		    *s != NULL; s++) {
			if (strcmp(alg, *s) == 0)
				break;
		}
		if (*s != NULL)
			return need_private ?
			    sensitive_data.host_keys[i] : key;
	}
	}
	return NULL;
}

struct sshkey *
get_hostkey_public_by_alg(const char* alg, struct ssh *ssh)
{
	struct sshkey *key;

	key = get_hostkey_by_alg(alg, 0, ssh);
	if (key != NULL) return key;

{	int keytype, subtype;
	sshkey_types_from_name(alg, &keytype, &subtype);
	return get_hostkey_by_type(keytype, subtype, 0, ssh);
}
}

struct sshkey *
get_hostkey_private_by_alg(const char* alg, struct ssh *ssh)
{
	struct sshkey *key;

	key = get_hostkey_by_alg(alg, 1, ssh);
	if (key != NULL) return key;

{	int keytype, subtype;
	sshkey_types_from_name(alg, &keytype, &subtype);
	return get_hostkey_by_type(keytype, subtype, 1, ssh);
}
}

struct sshkey *
get_hostkey_by_index(u_int ind)
{
	return ind < options.num_host_key_files
		? sensitive_data.host_keys[ind]
		: NULL;
}

struct sshkey *
get_hostkey_public_by_index(u_int ind, struct ssh *ssh)
{
	UNUSED(ssh);
	return ind < options.num_host_key_files
		? sensitive_data.host_pubkeys[ind]
		: NULL;
}

static const char**
get_hostkey_alg_by_index(u_int ind, struct ssh *ssh)
{
	UNUSED(ssh);
	return ind < options.num_host_key_files
		? sensitive_data.host_algorithms[ind]
		: NULL;
}

int
get_hostkey_index(struct sshkey *key, int compare, struct ssh *ssh)
{
	u_int i;

	UNUSED(ssh);
	for (i = 0; i < options.num_host_key_files; i++) {
		if (sshkey_is_cert(key)) {
			if (key == sensitive_data.host_certificates[i] ||
			    (compare && sensitive_data.host_certificates[i] &&
			    sshkey_equal(key,
			    sensitive_data.host_certificates[i])))
				return (i);
		} else {
			if (key == sensitive_data.host_keys[i] ||
			    (compare && sensitive_data.host_keys[i] &&
			    sshkey_equal_public(key, sensitive_data.host_keys[i])))
				return (i);
			if (key == sensitive_data.host_pubkeys[i] ||
			    (compare && sensitive_data.host_pubkeys[i] &&
			    sshkey_equal_public(key, sensitive_data.host_pubkeys[i])))
				return (i);
		}
	}
	return (-1);
}

/* Inform the client of all hostkeys */
static void
notify_hostkeys(struct ssh *ssh)
{
	struct sshbuf *buf;
	struct sshkey *key;
	u_int i, nkeys;
	int r;
	char *fp;

	/* Some clients cannot cope with the hostkeys message, skip those. */
	if (ssh_compat_fellows(ssh, SSH_BUG_HOSTKEYS))
		return;

	if ((buf = sshbuf_new()) == NULL)
		fatal_f("sshbuf_new");
	for (i = nkeys = 0; i < options.num_host_key_files; i++) {
		const char* pkalg;
		key = get_hostkey_public_by_index(i, ssh);
		if (key == NULL || key->type == KEY_UNSPEC ||
		    sshkey_is_cert(key))
			continue;
		fp = sshkey_fingerprint(key, options.fingerprint_hash,
		    SSH_FP_DEFAULT);

{	/* Note rsa-sha2-256 and rsa-sha2-512 public key algorithms
	 * use same key blob format as ssh-rsa!
	 */
	const char *rsa_patern = "ssh-rsa,rsa-sha2-256,rsa-sha2-512";
	const char **key_algs = get_hostkey_alg_by_index(i, ssh);
	int n_algs, rsa_format = 0;

	for (n_algs = 0; key_algs[n_algs] != NULL; n_algs++) {
		pkalg = key_algs[n_algs];
		if (match_pattern_list(pkalg, rsa_patern, 0) == 1) {
			if (rsa_format) continue;
			rsa_format = 1;
			pkalg = "ssh-rsa";
		}

		debug3_f("key %d: %s %s", i, pkalg, fp);
		if (nkeys == 0 && n_algs == 0) {
			/*
			 * Start building the request when we find the
			 * first usable key.
			 */
			if ((r = sshpkt_start(ssh, SSH2_MSG_GLOBAL_REQUEST)) != 0 ||
			    (r = sshpkt_put_cstring(ssh, "hostkeys-00@openssh.com")) != 0 ||
			    (r = sshpkt_put_u8(ssh, 0)) != 0) /* want reply */
				sshpkt_fatal(ssh, r, "%s: start request", __func__);
		}
		/* Append the key to the request */
		sshbuf_reset(buf);
		if ((r = Xkey_putb(pkalg, key, buf)) != 0)
			fatal_fr(r, "couldn't put hostkey %d", i);
		if ((r = sshpkt_put_stringb(ssh, buf)) != 0)
			sshpkt_fatal(ssh, r, "%s: append key", __func__);
	}
}
		free(fp);
		nkeys++;
	}
	debug3_f("sent %u hostkeys", nkeys);
	if (nkeys == 0)
		fatal_f("no hostkeys");
	if ((r = sshpkt_send(ssh)) != 0)
		sshpkt_fatal(ssh, r, "%s: send", __func__);
	sshbuf_free(buf);
}

static void
recv_rexec_state(int fd, struct sshbuf *conf)
{
	struct sshbuf *m, *inc;
	u_char *cp, ver;
	size_t len;
	int r;
	struct include_item *item;

	debug3_f("entering fd = %d", fd);

	if ((m = sshbuf_new()) == NULL || (inc = sshbuf_new()) == NULL)
		fatal_f("sshbuf_new failed");
	if (ssh_msg_recv(fd, m) == -1)
		fatal_f("ssh_msg_recv failed");
	if ((r = sshbuf_get_u8(m, &ver)) != 0)
		fatal_fr(r, "parse version");
	if (ver != 0)
		fatal_f("rexec version mismatch");
	if ((r = sshbuf_get_string(m, &cp, &len)) != 0 ||
	    (r = sshbuf_get_stringb(m, inc)) != 0)
		fatal_fr(r, "parse config");

	if (conf != NULL && (r = sshbuf_put(conf, cp, len)))
		fatal_fr(r, "sshbuf_put");

	while (sshbuf_len(inc) != 0) {
		item = xcalloc(1, sizeof(*item));
		if ((item->contents = sshbuf_new()) == NULL)
			fatal_f("sshbuf_new failed");
		if ((r = sshbuf_get_cstring(inc, &item->selector, NULL)) != 0 ||
		    (r = sshbuf_get_cstring(inc, &item->filename, NULL)) != 0 ||
		    (r = sshbuf_get_stringb(inc, item->contents)) != 0)
			fatal_fr(r, "parse includes");
		TAILQ_INSERT_TAIL(&includes, item, entry);
	}

	free(cp);
	sshbuf_free(m);

	debug3_f("done");
}

/*
 * If IP options are supported, make sure there are none (log and
 * return an error if any are found).  Basically we are worried about
 * source routing; it can be used to pretend you are somebody
 * (ip-address) you are not. That itself may be "almost acceptable"
 * under certain circumstances, but rhosts authentication is useless
 * if source routing is accepted. Notice also that if we just dropped
 * source routing here, the other side could use IP spoofing to do
 * rest of the interaction and could still bypass security.  So we
 * exit here if we detect any IP options.
 */
static void
check_ip_options(struct ssh *ssh)
{
#ifdef IP_OPTIONS
	int sock_in = ssh_packet_get_connection_in(ssh);
	struct sockaddr_storage from;
	u_char opts[200];
	socklen_t i, option_size = sizeof(opts), fromlen = sizeof(from);
	char text[sizeof(opts) * 3 + 1];

	memset(&from, 0, sizeof(from));
	if (getpeername(sock_in, (struct sockaddr *)&from,
	    &fromlen) == -1)
		return;
	if (from.ss_family != AF_INET)
		return;
	/* XXX IPv6 options? */

	if (getsockopt(sock_in, IPPROTO_IP, IP_OPTIONS, opts,
	    &option_size) != -1 && option_size != 0) {
		text[0] = '\0';
		for (i = 0; i < option_size; i++)
			snprintf(text + i*3, sizeof(text) - i*3,
			    " %2.2x", opts[i]);
		fatal("Connection from %.100s port %d with IP opts: %.800s",
		    ssh_remote_ipaddr(ssh), ssh_remote_port(ssh), text);
	}
#endif /* IP_OPTIONS */
}

#ifdef ENABLE_ROUTING_DOMAIN
/* Set the routing domain for this process */
static void
set_process_rdomain(struct ssh *ssh, const char *name)
{
#if defined(HAVE_SYS_SET_PROCESS_RDOMAIN)
	if (name == NULL)
		return; /* default */

	if (strcmp(name, "%D") == 0) {
		/* "expands" to routing domain of connection */
		if ((name = ssh_packet_rdomain_in(ssh)) == NULL)
			return;
	}
	/* NB. We don't pass 'ssh' to sys_set_process_rdomain() */
	return sys_set_process_rdomain(name);
#elif defined(HAVE_SETRTABLE)
	int rtable, ortable = getrtable();
	const char *errstr;

	if (name == NULL)
		return; /* default */

	if (strcmp(name, "%D") == 0) {
		/* "expands" to routing domain of connection */
		if ((name = ssh_packet_rdomain_in(ssh)) == NULL)
			return;
	}

	rtable = (int)strtonum(name, 0, 255, &errstr);
	if (errstr != NULL) /* Shouldn't happen */
		fatal("Invalid routing domain \"%s\": %s", name, errstr);
	if (rtable != ortable && setrtable(rtable) != 0)
		fatal("Unable to set routing domain %d: %s",
		    rtable, strerror(errno));
	debug_f("set routing domain %d (was %d)", rtable, ortable);
#else /* defined(HAVE_SETRTABLE) */
	/*unreachable*/
	UNUSED(ssh);
	UNUSED(name);
	fatal("Unable to set routing domain: not supported in this platform");
#endif
}
#endif /*def ENABLE_ROUTING_DOMAIN*/

int
Xsshd_hostkey_sign(
    struct ssh *ssh, ssh_sign_ctx *ctx, struct sshkey *pubkey,
    u_char **signature, size_t *slenp, const u_char *data, size_t dlen
) {
	int r;

	if (use_privsep) {
		if (ctx->key) {
			r = mm_Xkey_sign(ssh, ctx, signature, slenp, data, dlen);
			if (r != 0)
				fatal_fr(r, "Xkey_sign failed");
		} else {
			ssh_sign_ctx mm_ctx = { ctx->alg, pubkey, ctx->compat,
			    ctx->provider, ctx->pin };
			r = mm_Xkey_sign(ssh, &mm_ctx, signature, slenp, data, dlen);
			if (r != 0)
				fatal_fr(r, "pubkey Xkey_sign failed");
		}
	} else {
		if (ctx->key) {
			r = Xkey_sign(ctx, signature, slenp, data, dlen);
			if (r != 0)
				fatal_fr(r, "Xkey_sign failed");
		} else {
			ssh_sign_ctx a_ctx = { ctx->alg, NULL, ctx->compat,
			    ctx->provider, ctx->pin };
			/* mimic logic in priviledged mode */
			if (sshkey_is_cert(pubkey)) {
				int nxd = get_hostkey_index(pubkey, 0, ssh);
				if (nxd < 0)
					fatal_f("missing custom certificate");
				pubkey = get_hostkey_public_by_index(nxd, ssh);
				if (pubkey == NULL)
					fatal_f("missing public key");
			}
			a_ctx.key = pubkey;
			r = Xssh_agent_sign(auth_sock, &a_ctx, signature, slenp,
			    data, dlen);
			if (r != 0)
				fatal_fr(r, "Xssh_agent_sign failed");
		}
	}
	return 0;
}

/* SSH2 key exchange */
static void
do_ssh2_kex(struct ssh *ssh)
{
	char *myproposal[PROPOSAL_MAX] = { KEX_SERVER };
	struct kex *kex;
	int r;

	if (options.rekey_limit || options.rekey_interval)
		ssh_packet_set_rekey_limits(ssh, options.rekey_limit,
		    options.rekey_interval);

{	/* prepare proposal */
	char *s, *hkalgs = NULL;
	const char *compression = NULL;

	s = kex_names_cat(options.kex_algorithms,
#ifndef WITHOUT_ETM_FUNCTIONALITY
	    "kex-strict-s-v00@openssh.com"
#else
	    ""
#endif
	);
	if (s == NULL) fatal_f("kex_names_cat");

	if (options.compression == COMP_NONE)
		compression = "none";

	hkalgs = list_hostkey_types();

	kex_proposal_populate_entries(ssh, myproposal, s, options.ciphers,
	    options.macs, compression, hkalgs);

	free(hkalgs);
	free(s);
}

	/* start key exchange */
	if ((r = kex_setup(ssh, myproposal)) != 0)
		fatal_fr(r, "kex_setup");
	kex = ssh->kex;
	kex->find_host_public_key=&get_hostkey_public_by_alg;
	kex->find_host_private_key=&get_hostkey_private_by_alg;
	kex->host_key_index=&get_hostkey_index;
	kex->xsign = Xsshd_hostkey_sign;

	ssh_dispatch_run_fatal(ssh, DISPATCH_BLOCK, &kex->done);

#ifdef DEBUG_KEX
	/* send 1st encrypted/maced/compressed message */
	if ((r = sshpkt_start(ssh, SSH2_MSG_IGNORE)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, "roumen")) != 0 ||
	    (r = sshpkt_send(ssh)) != 0 ||
	    (r = ssh_packet_write_wait(ssh)) != 0)
		fatal_fr(r, "kex 1st message");
#endif
	kex_proposal_free_entries(myproposal);
	debug("KEX done");
}

/* server specific fatal cleanup */
void
cleanup_exit(int i)
{
	if (the_active_state != NULL && the_authctxt != NULL) {
		do_cleanup(the_active_state, the_authctxt);
		if (use_privsep && privsep_is_preauth &&
		    pmonitor != NULL && pmonitor->m_pid > 1) {
			debug("Killing privsep child %d", pmonitor->m_pid);
			if (kill(pmonitor->m_pid, SIGKILL) != 0 &&
			    errno != ESRCH)
				error_f("kill(%d): %s", pmonitor->m_pid,
				    strerror(errno));
		}
	}
#ifdef SSH_AUDIT_EVENTS
	/* done after do_cleanup so it can cancel the PAM auth 'thread' */
	if (the_active_state != NULL && (!use_privsep || mm_is_monitor()))
		audit_event(the_active_state, SSH_CONNECTION_ABANDON);
#endif
	_exit(i);
}
