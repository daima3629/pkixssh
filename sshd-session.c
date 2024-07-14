/*
 * Signal handler for the alarm after the login grace period has expired.
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
		ssh_signal(SIGTERM, SIG_IGN);
		kill(0, SIGTERM);
	}

	/* Log error and exit. */
	sigdie("Timeout before authentication for %s port %d",
	    ssh_remote_ipaddr(the_active_state),
	    ssh_remote_port(the_active_state));
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

static void
append_hostkey_type(struct sshbuf *b, const char *s)
{
	int r;

	if (match_pattern_list(s, options.hostkeyalgorithms, 0) != 1) {
		debug3_f("%s key not permitted by HostkeyAlgorithms", s);
		return;
	}
	if ((r = sshbuf_putf(b, "%s%s", sshbuf_len(b) > 0 ? "," : "", s)) != 0)
		fatal_fr(r, "sshbuf_putf");
}

static void
add_hostkey_algoritms(int k, struct sshbuf *b) {
	const char **algs;

	algs = sensitive_data.host_algorithms[k];
	if (algs == NULL) {
		debug("no suitable algorithms for host key %d", k);
		return;
	}

	for (; *algs != NULL; algs++) {
		const char *pkalg = *algs;

		/* Check that the key is accepted in HostkeyAlgorithms */
		if (match_pattern_list(pkalg,
		    options.hostkeyalgorithms, 0) != 1
		) {
			debug3_f("%s not permitted by "
				"HostkeyAlgorithms for key %d",
				pkalg, k);
			continue;
		}

		if (sshbuf_len(b) > 0) {
			if (sshbuf_put(b, ",", 1) != 0)
				goto err;
		}
		if (sshbuf_put(b, pkalg, strlen(pkalg)) != 0)
			goto err;
	}

	return;
err:
	fatal("cannot prepare hotkey algorithm list");
}

static char *
list_hostkey_types(void)
{
	struct sshbuf *b;
	struct sshkey *key;
	char *ret;
	u_int i;

	if ((b = sshbuf_new()) == NULL)
		fatal_f("sshbuf_new failed");
	for (i = 0; i < options.num_host_key_files; i++) {
		key = sensitive_data.host_keys[i];
		if (key == NULL)
			key = sensitive_data.host_pubkeys[i];
		if (key == NULL)
			continue;

		add_hostkey_algoritms(i, b);

		/* If the private key has a cert peer, then list that too */
		key = sensitive_data.host_certificates[i];
		if (key == NULL)
			continue;
		switch (key->type) {
		case KEY_RSA_CERT:
			/* for RSA we also support SHA2 signatures */
			append_hostkey_type(b,
			    "rsa-sha2-256-cert-v01@openssh.com");
			append_hostkey_type(b,
			    "rsa-sha2-512-cert-v01@openssh.com");
			/* FALLTHROUGH */
	#ifdef WITH_DSA
		case KEY_DSA_CERT:
	#endif
		case KEY_ECDSA_CERT:
		case KEY_ED25519_CERT:
	#ifdef WITH_XMSS
		case KEY_XMSS_CERT:
	#endif
			append_hostkey_type(b, sshkey_ssh_name(key));
			break;
		}
	}
	if ((ret = sshbuf_dup_string(b)) == NULL)
		fatal_f("sshbuf_dup_string failed");
	sshbuf_free(b);
	debug_f("%s", ret);
	return ret;
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
