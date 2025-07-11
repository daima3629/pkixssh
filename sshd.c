/* $OpenBSD: sshd.c,v 1.615 2025/02/10 23:19:26 djm Exp $ */
/*
 * Author: Tatu Ylonen <ylo@cs.hut.fi>
 * Copyright (c) 1995 Tatu Ylonen <ylo@cs.hut.fi>, Espoo, Finland
 *                    All rights reserved
 * This program is the ssh daemon.  It listens for connections from clients,
 * and performs authentication, executes use commands or shell, and forwards
 * information to/from the application to the user client over an encrypted
 * connection.  This can also handle forwarding of X11, TCP/IP, and
 * authentication agent connections.
 *
 * As far as I am concerned, the code I have written for this software
 * can be used freely for any purpose.  Any derived versions of this
 * software must be clearly marked as such, and if the derived work is
 * incompatible with the protocol description in the RFC file, it must be
 * called by a name other than "ssh" or "Secure Shell".
 *
 * SSH2 implementation:
 * Privilege Separation:
 *
 * Copyright (c) 2000, 2001, 2002 Markus Friedl.  All rights reserved.
 * Copyright (c) 2002 Niels Provos.  All rights reserved.
 * Copyright (c) 2002-2025 Roumen Petrov.  All rights reserved.
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
#include <sys/ioctl.h>
#include <sys/socket.h>
#ifdef HAVE_SYS_STAT_H
# include <sys/stat.h>
#endif
#ifdef HAVE_SYS_TIME_H
# include <sys/time.h>
#endif
#include "openbsd-compat/sys-tree.h"
#include "openbsd-compat/sys-queue.h"
#include <sys/wait.h>

#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#ifdef HAVE_PATHS_H
#include <paths.h>
#endif
#include <grp.h>
#ifdef HAVE_POLL_H
# include <poll.h>
#else
# ifdef HAVE_SYS_POLL_H
#  include <sys/poll.h>
# endif
#endif
#include <pwd.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <limits.h>

#ifdef WITH_OPENSSL
#include <openssl/rand.h>
#include "evp-compat.h"
#endif

#ifdef HAVE_FIPSCHECK_H
#  include <fipscheck.h>
#endif

#ifdef HAVE_SECUREWARE
#include <sys/security.h>
#include <prot.h>
#endif

#include "xmalloc.h"
#include "ssh.h"
#include "ssh2.h"
#include "sshpty.h"
#include "packet.h"
#include "log.h"
#include "sshbuf.h"
#include "misc.h"
#include "match.h"
#include "servconf.h"
#include "uidswap.h"
#include "compat.h"
#include "cipher.h"
#include "digest.h"
#include "ssh-x509.h"
#include "sshkey.h"
#include "ssh-xkalg.h"
#include "kex.h"
#include "myproposal.h"
#include "authfile.h"
#include "pathnames.h"
#include "atomicio.h"
#include "canohost.h"
#include "hostfile.h"
#include "auth.h"
#include "authfd.h"
#include "msg.h"
#include "dispatch.h"
#include "channels.h"
#include "session.h"
#include "monitor.h"
#ifdef GSSAPI
#include "ssh-gss.h"
#endif
#include "monitor_wrap.h"
#include "ssh-sandbox.h"
#include "auth-options.h"
#include "version.h"
#include "ssherr.h"
#include "srclimit.h"

#ifdef LIBWRAP
#include <tcpd.h>
#include <syslog.h>
int allow_severity;
int deny_severity;
#endif /* LIBWRAP */

#if 0
/* Random seed after closefrom() breaks daemon functionality.
 * Failure it not common. For instance "reexec" regression test may
 * fail in audit enabled builds.
 *
 * Remark:
 * Postponed random seed is work-around for random generator provided
 * by some engine, i.e. these that open descriptors for their own use.
 *
 * NOTE: If random seed is postponed reexec functionality may clobber
 * file descriptors. Re-exec is based on hard-coded descriptor numbers
 * and that all descriptors after certain number are closed.
 * For instance OpenSSL 1.1.1* may keep random device file descriptors
 * open. In such case postponed random seed change numbers used. In
 * consequence hard-coded "reexec" number may clash with used.
 */
# define POSTPONE_RANDOM_SEED
#endif

/* Re-exec fds */
#define REEXEC_DEVCRYPTO_RESERVED_FD	(STDERR_FILENO + 1)
#define REEXEC_STARTUP_PIPE_FD		(STDERR_FILENO + 2)
#define REEXEC_CONFIG_PASS_FD		(STDERR_FILENO + 3)
#define REEXEC_MIN_FREE_FD		(STDERR_FILENO + 4)

extern char *__progname;

extern void dh_set_moduli_file(const char *);

/* used in ssh-x509.c */
extern int (*pssh_x509store_verify_cert)(X509 *cert, STACK_OF(X509) *untrusted);
extern STACK_OF(X509)* (*pssh_x509store_build_certchain)(X509 *cert, STACK_OF(X509) *untrusted);

/* Server configuration options. */
ServerOptions options;

/* Name of the server configuration file. */
char *config_file_name = _PATH_SERVER_CONFIG_FILE;

/*
 * Debug mode flag.  This can be set on the command line.  If debug
 * mode is enabled, extra debugging output will be sent to the system
 * log, the daemon will not go to background, and will exit after processing
 * the first connection.
 */
int debug_flag = 0;

/*
 * Indicating that the daemon should only test the configuration and keys.
 * If test_flag > 1 ("-T" flag), then sshd will also dump the effective
 * configuration, optionally using connection information provided by the
 * "-C" flag.
 */
static int test_flag = 0;

/* Flag indicating that the daemon is being started from inetd. */
static int inetd_flag = 0;

/* Flag indicating that sshd should not detach and become a daemon. */
static int no_daemon_flag = 0;

/* debug goes to stderr unless inetd_flag is set */
int log_stderr = 0;

/* Saved arguments to main(). */
static char **saved_argv;
static int saved_argc;

/* re-exec */
static int rexeced_flag = 0;
static int rexec_flag = 1;
static int rexec_argc = 0;
static char **rexec_argv;

/*
 * The sockets that the server is listening; this is used in the SIGHUP
 * signal handler.
 */
#define	MAX_LISTEN_SOCKS	16
static int listen_socks[MAX_LISTEN_SOCKS];
static int num_listen_socks = 0;

/* Daemon's agent connection */
int auth_sock = -1;
static int have_agent = 0;

/*
 * Any really sensitive data in the application is contained in this
 * structure. The idea is that this structure could be locked into memory so
 * that the pages do not get written into swap.  However, there are some
 * problems. The private key contains BIGNUMs, and we do not (in principle)
 * have access to the internals of them, and locking just the structure is
 * not very useful.  Currently, memory locking is not implemented.
 */
struct {
	struct sshkey	**host_keys;		/* all private host keys */
	struct sshkey	**host_pubkeys;		/* all public host keys */
	const char	***host_algorithms;	/* all public-key algorithms per host key */
	struct sshkey	**host_certificates;	/* all public host certificates */
	int		have_ssh2_key;
} sensitive_data;

/* This is set to true when a signal is received. */
static volatile sig_atomic_t received_sighup = 0;
static volatile sig_atomic_t received_sigterm = 0;

/* record remote hostname or ip */
u_int utmp_len = HOST_NAME_MAX+1;

/*
 * startup_pipes/flags are used for tracking children of the listening sshd
 * process early in their lifespans. This tracking is needed for three things:
 *
 * 1) Implementing the MaxStartups limit of concurrent unauthenticated
 *    connections.
 * 2) Avoiding a race condition for SIGHUP processing, where child processes
 *    may have listen_socks open that could collide with main listener process
 *    after it restarts.
 * 3) Ensuring that rexec'd sshd processes have received their initial state
 *    from the parent listen process before handling SIGHUP.
 *
 * Child processes signal that they have completed closure of the listen_socks
 * and (if applicable) received their rexec state by sending a char over their
 * sock. Child processes signal that authentication has completed by closing
 * the sock (or by exiting).
 */
static int *startup_pipes = NULL;
static int *startup_flags = NULL;	/* Indicates child closed listener */
static int startup_pipe = -1;		/* in child */

/* variables used for privilege separation */
int use_privsep = -1;
struct monitor *pmonitor = NULL;
int privsep_is_preauth = 1;
static int privsep_chroot = 1;

/* global connection state and authentication contexts */
Authctxt *the_authctxt = NULL;
static struct ssh *the_active_state = NULL;

/* global key/cert auth options. XXX move to permanent ssh->authctxt? */
struct sshauthopt *auth_opts = NULL;

/* sshd_config buffer */
struct sshbuf *cfg;

/* Included files from the configuration file */
struct include_list includes = TAILQ_HEAD_INITIALIZER(includes);

/* message to be displayed after login */
struct sshbuf *loginmsg;

/* Unprivileged user */
struct passwd *privsep_pw = NULL;

static char *listener_proctitle;

static inline struct ssh*
create_session(int fd_in, int fd_out)
{
	the_active_state = ssh_packet_set_connection(NULL, fd_in, fd_out);
	if (the_active_state == NULL)
		fatal_f("ssh_packet_set_connection failed");

	ssh_packet_set_server(the_active_state);
	return the_active_state;
}

/*
 * Close all listening sockets
 */
static void
close_listen_socks(void)
{
	int i;

	for (i = 0; i < num_listen_socks; i++)
		close(listen_socks[i]);
	num_listen_socks = 0;
}

static void
close_startup_pipes(void)
{
	int i;

	if (startup_pipes)
		for (i = 0; i < options.max_startups; i++)
			if (startup_pipes[i] != -1)
				close(startup_pipes[i]);
}

/*
 * Signal handler for SIGHUP.  Sshd execs itself when it receives SIGHUP;
 * the effect is to reread the configuration file (and to regenerate
 * the server key).
 */

static void
sighup_handler(int sig)
{
	UNUSED(sig);
	received_sighup = 1;
}

/*
 * Called from the main program after receiving SIGHUP.
 * Restarts the server.
 */
static void
sighup_restart(void)
{
	logit("Received SIGHUP; restarting.");
	if (options.pid_file != NULL)
		unlink(options.pid_file);
	platform_pre_restart();
	close_listen_socks();
	close_startup_pipes();
	ssh_signal(SIGHUP, SIG_IGN); /* will be restored after exec */
	execv(saved_argv[0], saved_argv);
	logit("RESTART FAILED: av[0]='%.100s', error: %.100s.", saved_argv[0],
	    strerror(errno));
	exit(1);
}

/*
 * Generic signal handler for terminating signals in the master daemon.
 */
static void
sigterm_handler(int sig)
{
	received_sigterm = sig;
}

/*
 * SIGCHLD handler.  This is called whenever a child dies.  This will then
 * reap any zombies left by exited children.
 */
static void
main_sigchld_handler(int sig)
{
	int save_errno = errno;
	pid_t pid;
	int status;

	UNUSED(sig);
	while ((pid = waitpid(-1, &status, WNOHANG)) > 0 ||
	    (pid == -1 && errno == EINTR))
		;
	errno = save_errno;
}

#include "sshd-auth.c"
#include "sshd-session.c"

static int
prepare_server_banner(struct ssh *ssh)
{
	const char *fips = "";
	int r;

#ifdef OPENSSL_FIPS
	if (FIPS_mode()) fips= " FIPS";
#endif

	/* NOTE: Version string is prepared and sent with <CR><LF> at end.
	 * After identification exchange trailing <CR><LF> is removed for
	 * further use in key exchange messages.
	 */
	r = sshbuf_putf(ssh->kex->server_version,
	    "SSH-%d.%d-%s PKIX["PACKAGE_VERSION"%s]%s%s\r\n",
	    PROTOCOL_MAJOR_2, PROTOCOL_MINOR_2, SSH_VERSION, fips,
	    *options.version_addendum == '\0' ? "" : " ",
	    options.version_addendum);
	return r;
}

/*
 * returns 1 if connection should be dropped, 0 otherwise.
 * dropping starts at connection #max_startups_begin with a probability
 * of (max_startups_rate/100). the probability increases linearly until
 * all connections are dropped for startups > max_startups
 */
static int
should_drop_connection(int startups)
{
	int p, r;

	if (startups < options.max_startups_begin)
		return 0;
	if (startups >= options.max_startups)
		return 1;
	if (options.max_startups_rate == 100)
		return 1;

	p  = 100 - options.max_startups_rate;
	p *= startups - options.max_startups_begin;
	p /= options.max_startups - options.max_startups_begin;
	p += options.max_startups_rate;
	r = arc4random_uniform(100);

	debug_f("p %d, r %d", p, r);
	return (r < p) ? 1 : 0;
}

/*
 * Check whether connection should be accepted by MaxStartups.
 * Returns 0 if the connection is accepted. If the connection is refused,
 * returns 1 and attempts to send notification to client.
 * Logs when the MaxStartups condition is entered or exited, and periodically
 * while in that state.
 */
static int
drop_connection(int sock, int startups, int notify_pipe)
{
	static u_int ndropped = 0;
	static time_t first_drop, last_drop;

	if (!should_drop_connection(startups) &&
	    srclimit_check_allow(sock, notify_pipe) == 1) {
		if (ndropped == 0) return 0;

		if (startups < options.max_startups_begin - 1) {
			char *t = fmttime(monotime() - first_drop);
			/* XXX maybe need better hysteresis here */
			logit("exited MaxStartups throttling after %s, "
			    "%u connections dropped", t, ndropped);
			free(t);
		}
		ndropped = 0;
		return 0;
	}

#define SSHD_MAXSTARTUPS_LOG_INTERVAL	(5 * 60)
{	time_t now = monotime();

	if (ndropped++ == 0) {
		error("beginning MaxStartups throttling");
		first_drop = now;
	} else if (last_drop + SSHD_MAXSTARTUPS_LOG_INTERVAL < now) {
		/* Periodic logs */
		char *t = fmttime(now - first_drop);
		error("in MaxStartups throttling for %s, "
		    "%u connections dropped", t, ndropped);
		free(t);
	}
	last_drop = now;
}
{
	char *laddr = get_local_ipaddr(sock);
	char *raddr = get_peer_ipaddr(sock);
	const char msg[] = "Exceeded MaxStartups\r\n";

	verbose("drop connection #%d "
	    "from [%s]:%d on [%s]:%d past MaxStartups",
	    startups,
	    raddr, get_peer_port(sock),
	    laddr, get_local_port(sock));
	free(laddr);
	free(raddr);
	/* best-effort notification to client */
	(void)write(sock, msg, sizeof(msg) - 1);
}
	return 1;
}

static void
usage(void)
{
	fprintf(stderr, "%s, %s\n", SSH_RELEASE, ssh_OpenSSL_version_text());
	fprintf(stderr,
"usage: sshd [-46DdeGiqTtV] [-C connection_spec] [-c host_cert_file]\n"
"            [-E log_file] [-f config_file] [-g login_grace_time]\n"
"            [-h host_key_file] [-o option] [-p port] [-u len]\n"
	);
	exit(1);
}

static void
send_rexec_state(int fd, struct sshbuf *conf)
{
	struct sshbuf *m = NULL, *inc = NULL;
	struct include_item *item = NULL;
	int r;

	debug3_f("entering fd = %d config len %zu", fd,
	    sshbuf_len(conf));

	if ((m = sshbuf_new()) == NULL || (inc = sshbuf_new()) == NULL)
		fatal_f("sshbuf_new failed");

	/* pack includes into a string */
	TAILQ_FOREACH(item, &includes, entry) {
		if ((r = sshbuf_put_cstring(inc, item->selector)) != 0 ||
		    (r = sshbuf_put_cstring(inc, item->filename)) != 0 ||
		    (r = sshbuf_put_stringb(inc, item->contents)) != 0)
			fatal_fr(r, "compose includes");
	}

	/*
	 * Protocol from reexec master to child:
	 *	string	configuration
	 *	string	included_files[] {
	 *		string	selector
	 *		string	filename
	 *		string	contents
	 *	}
	 */
	if ((r = sshbuf_put_stringb(m, conf)) != 0 ||
	    (r = sshbuf_put_stringb(m, inc)) != 0)
		fatal_fr(r, "compose config");

	if (ssh_msg_send(fd, 0, m) == -1)
		error_f("ssh_msg_send failed");

	sshbuf_free(m);
	sshbuf_free(inc);

	debug3_f("done");
}

/* Accept a connection from inetd */
static void
server_accept_inetd(int *sock_in, int *sock_out)
{
	if (rexeced_flag) {
		close(REEXEC_CONFIG_PASS_FD);
		*sock_in = *sock_out = dup(STDIN_FILENO);
	} else {
		*sock_in = dup(STDIN_FILENO);
		*sock_out = dup(STDOUT_FILENO);
	}
	/*
	 * We intentionally do not close the descriptors 0, 1, and 2
	 * as our code for setting the descriptors won't work if
	 * ttyfd happens to be one of those.
	 */
	if (stdfd_devnull(1, 1, !log_stderr) == -1)
		error_f("stdfd_devnull failed");
	debug("inetd sockets after dupping: %d, %d", *sock_in, *sock_out);
}

/*
 * Listen for TCP connections
 */
static void
listen_on_addrs(struct listenaddr *la)
{
	int ret, listen_sock;
	struct addrinfo *ai;
	char ntop[NI_MAXHOST], strport[NI_MAXSERV];

	for (ai = la->addrs; ai; ai = ai->ai_next) {
		if (ai->ai_family != AF_INET && ai->ai_family != AF_INET6)
			continue;
		if (num_listen_socks >= MAX_LISTEN_SOCKS)
			fatal("Too many listen sockets. "
			    "Enlarge MAX_LISTEN_SOCKS");
		if ((ret = getnameinfo(ai->ai_addr, ai->ai_addrlen,
		    ntop, sizeof(ntop), strport, sizeof(strport),
		    NI_NUMERICHOST|NI_NUMERICSERV)) != 0) {
			error("getnameinfo failed: %.100s",
			    ssh_gai_strerror(ret));
			continue;
		}
		/* Create socket for listening. */
		listen_sock = socket(ai->ai_family, ai->ai_socktype,
		    ai->ai_protocol);
		if (listen_sock == -1) {
			/* kernel may not support ipv6 */
			verbose("socket: %.100s", strerror(errno));
			continue;
		}
		if (set_nonblock(listen_sock) == -1) {
			close(listen_sock);
			continue;
		}
		if (fcntl(listen_sock, F_SETFD, FD_CLOEXEC) == -1) {
			verbose("socket: CLOEXEC: %s", strerror(errno));
			close(listen_sock);
			continue;
		}
		/* Socket options */
		set_reuseaddr(listen_sock);
		if (la->rdomain != NULL &&
		    set_rdomain(listen_sock, la->rdomain) == -1) {
			close(listen_sock);
			continue;
		}

		/* Only communicate in IPv6 over AF_INET6 sockets. */
		if (ai->ai_family == AF_INET6)
			sock_set_v6only(listen_sock);

		debug("Bind to port %s on %s.", strport, ntop);

		/* Bind the socket to the desired port. */
		if (bind(listen_sock, ai->ai_addr, ai->ai_addrlen) == -1) {
			error("Bind to port %s on %s failed: %.200s.",
			    strport, ntop, strerror(errno));
			close(listen_sock);
			continue;
		}
		listen_socks[num_listen_socks] = listen_sock;
		num_listen_socks++;

		/* Start listening on the port. */
		if (listen(listen_sock, SSH_LISTEN_BACKLOG) == -1)
			fatal("listen on [%s]:%s: %.100s",
			    ntop, strport, strerror(errno));
		logit("Server listening on %s port %s%s%s.",
		    ntop, strport,
		    la->rdomain == NULL ? "" : " rdomain ",
		    la->rdomain == NULL ? "" : la->rdomain);
	}
}

static void
server_listen(void)
{
	u_int i;

	/* Initialise per-source limit tracking. */
	srclimit_init(options.max_startups, options.per_source_max_startups,
	    options.per_source_masklen_ipv4, options.per_source_masklen_ipv6);

	for (i = 0; i < options.num_listen_addrs; i++) {
		listen_on_addrs(&options.listen_addrs[i]);
		freeaddrinfo(options.listen_addrs[i].addrs);
		free(options.listen_addrs[i].rdomain);
		memset(&options.listen_addrs[i], 0,
		    sizeof(options.listen_addrs[i]));
	}
	free(options.listen_addrs);
	options.listen_addrs = NULL;
	options.num_listen_addrs = 0;

	if (!num_listen_socks)
		fatal("Cannot bind any address.");
}

/*
 * The main TCP accept loop. Note that, for the non-debug case, returns
 * from this function are in a forked subprocess.
 */
static void
server_accept_loop(int *sock_in, int *sock_out, int *newsock, int *config_s)
{
	struct pollfd *pfd = NULL;
	int i, j, ret, npfd;
	int ostartups = -1, startups = 0, listening = 0, lameduck = 0;
	int startup_p[2] = { -1 , -1 }, *startup_pollfd;
	struct sockaddr_storage from;
	socklen_t fromlen;
	pid_t pid;
	u_char rnd[256];
	sigset_t nsigset, osigset;

	/* pipes connected to unauthenticated child sshd processes */
	startup_pipes = xcalloc(options.max_startups, sizeof(int));
	startup_flags = xcalloc(options.max_startups, sizeof(int));
	startup_pollfd = xcalloc(options.max_startups, sizeof(int));
	for (i = 0; i < options.max_startups; i++)
		startup_pipes[i] = -1;

	/*
	 * Prepare signal mask that we use to block signals that might set
	 * received_sigterm or received_sighup, so that we are guaranteed
	 * to immediately wake up the ppoll if a signal is received after
	 * the flag is checked.
	 */
	sigemptyset(&nsigset);
	sigaddset(&nsigset, SIGHUP);
	sigaddset(&nsigset, SIGCHLD);
	sigaddset(&nsigset, SIGTERM);
	sigaddset(&nsigset, SIGQUIT);

	/* sized for worst-case */
	pfd = xcalloc(num_listen_socks + options.max_startups,
	    sizeof(struct pollfd));

	/*
	 * Stay listening for connections until the system crashes or
	 * the daemon is killed with a signal.
	 */
	for (;;) {
		sigprocmask(SIG_BLOCK, &nsigset, &osigset);
		if (received_sigterm) {
			logit("Received signal %d; terminating.",
			    (int) received_sigterm);
			close_listen_socks();
			if (options.pid_file != NULL)
				unlink(options.pid_file);
			exit(received_sigterm == SIGTERM ? 0 : 255);
		}
		if (ostartups != startups) {
			setproctitle("%s [listener] %d of %d-%d startups",
			    listener_proctitle, startups,
			    options.max_startups_begin, options.max_startups);
			ostartups = startups;
		}
		if (received_sighup) {
			if (!lameduck) {
				debug("Received SIGHUP; waiting for children");
				close_listen_socks();
				lameduck = 1;
			}
			if (listening <= 0) {
				sigprocmask(SIG_SETMASK, &osigset, NULL);
				sighup_restart();
			}
		}

		for (i = 0; i < num_listen_socks; i++) {
			pfd[i].fd = listen_socks[i];
			pfd[i].events = POLLIN;
		}
		npfd = num_listen_socks;
		for (i = 0; i < options.max_startups; i++) {
			startup_pollfd[i] = -1;
			if (startup_pipes[i] != -1) {
				pfd[npfd].fd = startup_pipes[i];
				pfd[npfd].events = POLLIN;
				startup_pollfd[i] = npfd++;
			}
		}

		/* Wait until a connection arrives or a child exits. */
		ret = ppoll(pfd, npfd, NULL, &osigset);
		if (ret == -1 && errno != EINTR) {
			error("ppoll: %.100s", strerror(errno));
			if (errno == EINVAL)
				cleanup_exit(1); /* can't recover */
		}
		sigprocmask(SIG_SETMASK, &osigset, NULL);
		if (ret == -1)
			continue;

		for (i = 0; i < options.max_startups; i++) {
			char c = 0;

			if (startup_pipes[i] == -1 ||
			    startup_pollfd[i] == -1 ||
			    !(pfd[startup_pollfd[i]].revents & (POLLIN|POLLHUP)))
				continue;

			switch (read(startup_pipes[i], &c, sizeof(c))) {
			case -1:
				if (errno == EINTR || errno == EAGAIN)
					continue;
				if (errno != EPIPE) {
					error_f("startup pipe %d (fd=%d): "
					    "read %s", i, startup_pipes[i],
					    strerror(errno));
				}
				/* FALLTHROUGH */
			case 0:
				/* child exited or completed auth */
				close(startup_pipes[i]);
				srclimit_done(startup_pipes[i]);
				startup_pipes[i] = -1;
				startups--;
				if (startup_flags[i]) {
					listening--;
					startup_flags[i] = 0;
				}
				break;
			case 1:
				/* child has finished preliminaries */
				if (startup_flags[i]) {
					listening--;
					startup_flags[i] = 0;
				}
				break;
			}
		}
		for (i = 0; i < num_listen_socks; i++) {
			if (!(pfd[i].revents & (POLLIN|POLLHUP)))
				continue;
			fromlen = sizeof(from);
			*newsock = accept(listen_socks[i],
			    (struct sockaddr *)&from, &fromlen);
			if (*newsock == -1) {
				if (errno != EINTR && errno != EWOULDBLOCK &&
				    errno != ECONNABORTED && errno != EAGAIN)
					error("accept: %.100s",
					    strerror(errno));
				if (errno == EMFILE || errno == ENFILE)
					usleep(100 * 1000);
				continue;
			}
			if (unset_nonblock(*newsock) == -1) {
				close(*newsock);
				continue;
			}
			if (pipe(startup_p) == -1) {
				error_f("pipe(startup_p): %s", strerror(errno));
				close(*newsock);
				continue;
			}
			if (drop_connection(*newsock, startups, startup_p[0])) {
				close(*newsock);
				close(startup_p[0]);
				close(startup_p[1]);
				continue;
			}

			if (rexec_flag && socketpair(AF_UNIX,
			    SOCK_STREAM, 0, config_s) == -1) {
				error("reexec socketpair: %s",
				    strerror(errno));
				close(*newsock);
				close(startup_p[0]);
				close(startup_p[1]);
				continue;
			}

			for (j = 0; j < options.max_startups; j++)
				if (startup_pipes[j] == -1) {
					startup_pipes[j] = startup_p[0];
					startups++;
					startup_flags[j] = 1;
					break;
				}

			/*
			 * Got connection.  Fork a child to handle it, unless
			 * we are in debugging mode.
			 */
			if (debug_flag) {
				/*
				 * In debugging mode.  Close the listening
				 * socket, and start processing the
				 * connection without forking.
				 */
				debug("Server will not fork when running in debugging mode.");
				close_listen_socks();
				*sock_in = *newsock;
				*sock_out = *newsock;
				close(startup_p[0]);
				close(startup_p[1]);
				startup_pipe = -1;
				pid = getpid();
				if (rexec_flag) {
					send_rexec_state(config_s[0], cfg);
					close(config_s[0]);
				}
				free(pfd);
				return;
			}

			/*
			 * Normal production daemon.  Fork, and have
			 * the child process the connection. The
			 * parent continues listening.
			 */
			platform_pre_fork();
			listening++;
			if ((pid = fork()) == 0) {
				/*
				 * Child.  Close the listening and
				 * max_startup sockets.  Start using
				 * the accepted socket. Reinitialize
				 * logging (since our pid has changed).
				 * We return from this function to handle
				 * the connection.
				 */
				platform_post_fork_child();
				startup_pipe = startup_p[1];
				close_startup_pipes();
				close_listen_socks();
				*sock_in = *newsock;
				*sock_out = *newsock;
				log_init(__progname,
				    options.log_level,
				    options.log_facility,
				    log_stderr);
				if (rexec_flag)
					close(config_s[0]);
				else {
					/*
					 * Signal parent that the preliminaries
					 * for this child are complete. For the
					 * re-exec case, this happens after the
					 * child has received the rexec state
					 * from the server.
					 */
					(void)atomicio(vwrite, startup_pipe,
					    "\0", 1);
				}
				free(pfd);
				return;
			}

			/* Parent.  Stay in the loop. */
			platform_post_fork_parent(pid);
			if (pid == -1)
				error("fork: %.100s", strerror(errno));
			else
				debug("Forked child %ld.", (long)pid);

			close(startup_p[1]);

			if (rexec_flag) {
				close(config_s[1]);
				send_rexec_state(config_s[0], cfg);
				close(config_s[0]);
			}
			close(*newsock);

			/*
			 * Ensure that our random state differs
			 * from that of the child
			 */
			arc4random_stir();
			arc4random_buf(rnd, sizeof(rnd));
#ifdef WITH_OPENSSL
			RAND_seed(rnd, sizeof(rnd));
			if ((RAND_bytes((u_char *)rnd, 1)) <= 0)
				fatal_f("RAND_bytes failed");
#endif
			explicit_bzero(rnd, sizeof(rnd));
		}
	}
}

static void
accumulate_host_timing_secret(struct sshbuf *server_cfg,
    struct sshkey *key)
{
	static struct ssh_digest_ctx *ctx = NULL;
	int digest_alg;
	u_char *hash;
	size_t len;
	struct sshbuf *buf;
	int r;

	digest_alg = ssh_digest_maxbytes();
	if (ctx == NULL && (ctx = ssh_digest_start(digest_alg)) == NULL)
		fatal_f("ssh_digest_start");
	if (key == NULL) { /* finalize */
		/* add server config in case we are using agent for host keys */
		if (ssh_digest_update(ctx, sshbuf_ptr(server_cfg),
		    sshbuf_len(server_cfg)) != 0)
			fatal_f("ssh_digest_update");
		len = ssh_digest_bytes(digest_alg);
		hash = xmalloc(len);
		if (ssh_digest_final(ctx, hash, len) != 0)
			fatal_f("ssh_digest_final");
		options.timing_secret = PEEK_U64(hash);
		freezero(hash, len);
		ssh_digest_free(ctx);
		ctx = NULL;
		return;
	}
	if ((buf = sshbuf_new()) == NULL)
		fatal_f("could not allocate buffer");
	if ((r = sshkey_private_serialize(key, buf)) != 0)
		fatal_fr(r, "encode %s key", sshkey_ssh_name(key));
	if (ssh_digest_update(ctx, sshbuf_ptr(buf), sshbuf_len(buf)) != 0)
		fatal_f("ssh_digest_update");
	sshbuf_reset(buf);
	sshbuf_free(buf);
}

static char *
prepare_proctitle(int ac, char **av)
{
	char *ret = NULL;
	int i;

	for (i = 0; i < ac; i++)
		xextendf(&ret, " ", "%s", av[i]);
	return ret;
}

static void
print_config(struct ssh *ssh, struct connection_info *connection_info)
{
	/*
	 * If no connection info was provided by -C then use
	 * use a blank one that will cause no predicate to match.
	 */
	if (connection_info == NULL)
		connection_info = server_get_connection_info(ssh, 0, 0);
	connection_info->test = 1;
	parse_server_match_config(&options, &includes, connection_info);
	dump_config(&options);
	exit(0);
}

/*
 * Main program for the daemon.
 */
int
main(int ac, char **av)
{
	struct ssh *ssh = NULL;
	extern char *optarg;
	extern int optind;
	int r, opt, on = 1, do_dump_cfg = 0, already_daemon, remote_port;
	int sock_in = -1, sock_out = -1, newsock = -1;
	const char *remote_ip, *rdomain;
	char *fp, *line, *laddr, *logfile = NULL;
	int config_s[2] = { -1 , -1 };
	u_int i, j;
	u_int64_t ibytes, obytes;
	mode_t new_umask;
	struct sshkey *key;
	struct sshkey *pubkey;
	int keytype;
	Authctxt *authctxt;
	struct connection_info *connection_info = NULL;

	ssh_malloc_init();	/* must be called before any mallocs */

#ifdef HAVE_SECUREWARE
	(void)set_auth_parameters(ac, av);
#endif
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
	pssh_x509store_verify_cert = ssh_x509store_verify_cert;
	pssh_x509store_build_certchain = ssh_x509store_build_certchain;

/* work-around for environments that fail to clear masked signal on fork or exec */
{	sigset_t sigmask;

	sigemptyset(&sigmask);
	sigprocmask(SIG_SETMASK, &sigmask, NULL);
}

	/* Save argv. Duplicate so setproctitle emulation doesn't clobber it */
	saved_argc = ac;
	rexec_argc = ac;
	saved_argv = xcalloc(ac + 1, sizeof(*saved_argv));
	for (i = 0; (int)i < ac; i++)
		saved_argv[i] = xstrdup(av[i]);
	saved_argv[i] = NULL;

#ifndef HAVE_SETPROCTITLE
	/* Prepare for later setproctitle emulation */
	compat_init_setproctitle(ac, av);
	av = saved_argv;
#endif

	if (geteuid() == 0 && setgroups(0, NULL) == -1)
		debug("setgroups(): %.200s", strerror(errno));

	/* Ensure that fds 0, 1 and 2 are open or directed to /dev/null */
	sanitise_stdfd();

#ifdef HAVE_RAND_KEEP_RANDOM_DEVICES_OPEN
	/* Disable the retention of file descriptors used as random seed
	 * sources - ensure consistent OpenSSL functionality between
	 * different OS version, releases and event build configurations.
	 * Note this is OpenSSL pre 1.1.1 functionality.
	 */
	RAND_keep_random_devices_open(0);
#endif
#ifndef POSTPONE_RANDOM_SEED
	seed_rng();
#endif

	/* Initialize configuration options to their default values. */
	initialize_server_options(&options);

	/* Parse command-line arguments. */
	while ((opt = getopt(ac, av,
	    "C:E:b:c:f:g:h:k:o:p:u:46DGQRTdeiqrtV")) != -1) {
		switch (opt) {
		case '4':
			options.address_family = AF_INET;
			break;
		case '6':
			options.address_family = AF_INET6;
			break;
		case 'f':
			config_file_name = optarg;
			break;
		case 'c':
			servconf_add_hostcert("[command-line]", 0,
			    &options, optarg);
			break;
		case 'd':
			if (debug_flag == 0) {
				debug_flag = 1;
				options.log_level = SYSLOG_LEVEL_DEBUG1;
			} else if (options.log_level < SYSLOG_LEVEL_DEBUG3)
				options.log_level++;
			break;
		case 'D':
			no_daemon_flag = 1;
			break;
		case 'G':
			do_dump_cfg = 1;
			break;
		case 'E':
			logfile = optarg;
			/* FALLTHROUGH */
		case 'e':
			log_stderr = 1;
			break;
		case 'i':
			inetd_flag = 1;
			break;
		case 'r':
			rexec_flag = 0;
			break;
		case 'R':
			rexeced_flag = 1;
			inetd_flag = 1;
			break;
		case 'Q':
			/* ignored */
			break;
		case 'q':
			options.log_level = SYSLOG_LEVEL_QUIET;
			break;
		case 'b':
			/* protocol 1, ignored */
			break;
		case 'p':
			options.ports_from_cmdline = 1;
			if (options.num_ports >= MAX_PORTS) {
				fprintf(stderr, "too many ports.\n");
				exit(1);
			}
			options.ports[options.num_ports++] = a2port(optarg);
			if (options.ports[options.num_ports-1] <= 0) {
				fprintf(stderr, "Bad port number.\n");
				exit(1);
			}
			break;
		case 'g':
		{	long t = convtime(optarg);
			if (t == -1) {
				fprintf(stderr, "Invalid login grace time.\n");
				exit(1);
			}
		#if SIZEOF_LONG_INT > SIZEOF_INT
			if (t > INT_MAX) {
				fprintf(stderr, "Login grace time too high.\n");
				exit(1);
			}
		#endif
			options.login_grace_time = (int)t; /*safe cast*/
		}	break;
		case 'k':
			/* protocol 1, ignored */
			break;
		case 'h':
			servconf_add_hostkey("[command-line]", 0,
			    &options, optarg, 1);
			break;
		case 't':
			test_flag = 1;
			break;
		case 'T':
			test_flag = 2;
			break;
		case 'C':
			connection_info = server_get_connection_info(ssh, 0, 0);
			if (parse_server_match_testspec(connection_info,
			    optarg) == -1)
				exit(1);
			break;
		case 'u':
			utmp_len = (u_int)strtonum(optarg, 0, HOST_NAME_MAX+1+1, NULL);
			if (utmp_len > HOST_NAME_MAX+1) {
				fprintf(stderr, "Invalid utmp length.\n");
				exit(1);
			}
			break;
		case 'o':
			line = xstrdup(optarg);
			if (process_server_config_line(&options, line,
			    "command-line", 0, NULL, NULL, &includes) != 0)
				exit(1);
			free(line);
			break;
		case 'V':
			fprintf(stderr, "%s, %s\n",
			    SSH_RELEASE, ssh_OpenSSL_version_text());
			exit(0);
		default:
			usage();
			break;
		}
	}
	if (rexeced_flag || inetd_flag)
		rexec_flag = 0;
#ifdef __ANDROID__
	/* NOTE: Android model does not recommend absolute paths */
#else
	if (!test_flag && !do_dump_cfg && rexec_flag && !path_absolute(av[0]))
		fatal("sshd re-exec requires execution with an absolute path");
#endif
	if (rexeced_flag)
		closefrom(REEXEC_MIN_FREE_FD);
	else
		closefrom(REEXEC_DEVCRYPTO_RESERVED_FD);

#ifdef POSTPONE_RANDOM_SEED
	seed_rng();
#endif

	/* If requested, redirect the logs to the specified logfile. */
	if (logfile != NULL)
		log_redirect_stderr_to(logfile);
	/*
	 * Force logging to stderr until we have loaded the private host
	 * key (unless started from inetd)
	 */
	log_init(__progname,
	    options.log_level == SYSLOG_LEVEL_NOT_SET ?
	    SYSLOG_LEVEL_INFO : options.log_level,
	    options.log_facility == SYSLOG_FACILITY_NOT_SET ?
	    SYSLOG_FACILITY_AUTH : options.log_facility,
	    log_stderr || !inetd_flag || debug_flag);

	/*
	 * Unset KRB5CCNAME, otherwise the user's session may inherit it from
	 * root's environment
	 */
	if (getenv("KRB5CCNAME") != NULL)
		(void) unsetenv("KRB5CCNAME");

	sensitive_data.have_ssh2_key = 0;

	/*
	 * If we're not doing an extended test do not silently ignore connection
	 * test params.
	 */
	if (test_flag < 2 && connection_info != NULL)
		fatal("Config test connection parameter (-C) provided without "
		    "test mode (-T)");

	if (get_log_level() >= SYSLOG_LEVEL_DEBUG1)
		logit("%s version %s, %s", __progname, SSH_RELEASE, ssh_OpenSSL_version_text());
	debug3_uname();

	/* Fetch our configuration */
	if ((cfg = sshbuf_new()) == NULL)
		fatal_f("sshbuf_new failed");
	if (rexeced_flag) {
		setproctitle("%s", "[rexeced]");
		recv_rexec_state(REEXEC_CONFIG_PASS_FD, cfg);
		if (!debug_flag) {
			startup_pipe = dup(REEXEC_STARTUP_PIPE_FD);
			close(REEXEC_STARTUP_PIPE_FD);
			/*
			 * Signal parent that this child is at a point where
			 * they can go away if they have a SIGHUP pending.
			 */
			(void)atomicio(vwrite, startup_pipe, "\0", 1);
		}
	} else if (strcasecmp(config_file_name, "none") != 0)
		load_server_config(config_file_name, cfg);

	parse_server_config(&options, rexeced_flag ? "rexec" : config_file_name,
	    cfg, &includes, NULL, rexeced_flag);

#ifdef ENABLE_KEX_DH
	if (options.moduli_file != NULL)
		dh_set_moduli_file(options.moduli_file);
#endif

	/* Fill in default values for those options not explicitly set. */
	fill_default_server_options(&options);

	/* Check that options are sensible */
	if (options.authorized_keys_command_user == NULL &&
	    (options.authorized_keys_command != NULL &&
	    strcasecmp(options.authorized_keys_command, "none") != 0))
		fatal("AuthorizedKeysCommand set without "
		    "AuthorizedKeysCommandUser");
	if (options.authorized_principals_command_user == NULL &&
	    (options.authorized_principals_command != NULL &&
	    strcasecmp(options.authorized_principals_command, "none") != 0))
		fatal("AuthorizedPrincipalsCommand set without "
		    "AuthorizedPrincipalsCommandUser");

	/*
	 * Check whether there is any path through configured auth methods.
	 * Unfortunately it is not possible to verify this generally before
	 * daemonisation in the presence of Match block, but this catches
	 * and warns for trivial misconfigurations that could break login.
	 */
	if (options.num_auth_methods != 0) {
		for (i = 0; i < options.num_auth_methods; i++) {
			if (auth2_methods_valid(options.auth_methods[i],
			    1) == 0)
				break;
		}
		if (i >= options.num_auth_methods)
			fatal("AuthenticationMethods cannot be satisfied by "
			    "enabled authentication methods");
	}

	/* Check that there are no remaining arguments. */
	if (optind < ac) {
		fprintf(stderr, "Extra argument %s.\n", av[optind]);
		exit(1);
	}

	if (do_dump_cfg)
		print_config(ssh, connection_info);

	/* Store privilege separation user for later use if required. */
	privsep_chroot = use_privsep && (getuid() == 0 || geteuid() == 0);
	if ((privsep_pw = getpwnam(SSH_PRIVSEP_USER)) == NULL) {
		if (privsep_chroot || options.kerberos_authentication)
			fatal("Privilege separation user %s does not exist",
			    SSH_PRIVSEP_USER);
	} else {
		privsep_pw = pwcopy(privsep_pw);
		freezero(privsep_pw->pw_passwd, strlen(privsep_pw->pw_passwd));
		privsep_pw->pw_passwd = xstrdup("*");
	}
	endpwent();

	/* load host keys */
	sensitive_data.host_keys = xcalloc(options.num_host_key_files,
	    sizeof(struct sshkey *));
	sensitive_data.host_pubkeys = xcalloc(options.num_host_key_files,
	    sizeof(struct sshkey *));
	sensitive_data.host_algorithms = xcalloc(options.num_host_key_files,
	    sizeof(const char **));

	if (options.host_key_agent) {
		if (strcmp(options.host_key_agent, SSH_AUTHSOCKET_ENV_NAME))
			setenv(SSH_AUTHSOCKET_ENV_NAME,
			    options.host_key_agent, 1);
		if ((r = ssh_get_authentication_socket(NULL)) == 0)
			have_agent = 1;
		else
			error_r(r, "Could not connect to agent \"%s\"",
			    options.host_key_agent);
	}

	for (i = 0; i < options.num_host_key_files; i++) {
		int ll = options.host_key_file_userprovided[i] ?
		    SYSLOG_LEVEL_ERROR : SYSLOG_LEVEL_DEBUG1;

		if (options.host_key_files[i] == NULL)
			continue;
		if ((r = sshkey_load_private(options.host_key_files[i], "",
		    &key, NULL)) != 0 && r != SSH_ERR_SYSTEM_ERROR)
			do_log2_r(r, ll, "Unable to load host key \"%s\"",
			    options.host_key_files[i]);
		if (r == 0 && (r = sshkey_shield_private(key)) != 0) {
			do_log2_r(r, ll, "Unable to shield host key \"%s\"",
			    options.host_key_files[i]);
			sshkey_free(key);
			key = NULL;
		}
		if ((r = sshkey_load_public(options.host_key_files[i],
		    &pubkey, NULL)) != 0 && r != SSH_ERR_SYSTEM_ERROR)
			do_log2_r(r, ll, "Unable to load host key \"%s\"",
			    options.host_key_files[i]);
		if (pubkey != NULL && key != NULL) {
			if (!sshkey_equal(pubkey, key)) {
				error("Public key for %s does not match "
				    "private key", options.host_key_files[i]);
				sshkey_free(pubkey);
				pubkey = NULL;
			}
		}
		if (pubkey == NULL && key != NULL) {
			if ((r = sshkey_from_private(key, &pubkey)) != 0)
				fatal_r(r, "Could not demote key: \"%s\"",
				    options.host_key_files[i]);
		}
	#if 0
		/* NOTE: key size is validated on read, sign and verify */
		if (pubkey != NULL && (r = sshkey_check_length(pubkey)) != 0) {
			error_fr(r, "Host key %s", options.host_key_files[i]);
			sshkey_free(pubkey);
			sshkey_free(key);
			continue;
		}
	#endif
		sensitive_data.host_keys[i] = key;
		sensitive_data.host_pubkeys[i] = pubkey;
		sensitive_data.host_algorithms[i] = Xkey_algoriths(pubkey);

		if (key == NULL && pubkey != NULL && have_agent) {
			debug("will rely on agent for hostkey %s",
			    options.host_key_files[i]);
			keytype = pubkey->type;
		} else if (key != NULL) {
			keytype = key->type;
			accumulate_host_timing_secret(cfg, key);
		} else {
			do_log2(ll, "Unable to load host key: %s",
			    options.host_key_files[i]);
			sensitive_data.host_keys[i] = NULL;
			sensitive_data.host_pubkeys[i] = NULL;
			continue;
		}

		switch (keytype) {
		case KEY_RSA:
	#ifdef WITH_DSA
		case KEY_DSA:
	#endif
		case KEY_ECDSA:
		case KEY_ED25519:
	#ifdef WITH_XMSS
		case KEY_XMSS:
	#endif
			if (have_agent || key != NULL)
				sensitive_data.have_ssh2_key = 1;
			break;
		}
		if ((fp = sshkey_fingerprint(pubkey, options.fingerprint_hash,
		    SSH_FP_DEFAULT)) == NULL)
			fatal("sshkey_fingerprint failed");
		debug("%s host key #%d: %s %s",
		    key ? "private" : "agent", i, sshkey_ssh_name(pubkey), fp);
		free(fp);
	}
	accumulate_host_timing_secret(cfg, NULL);
	if (!sensitive_data.have_ssh2_key) {
		logit("sshd: no hostkeys available -- exiting.");
		exit(1);
	}

	/*
	 * Load certificates. They are stored in an array at identical
	 * indices to the public keys that they relate to.
	 */
	sensitive_data.host_certificates = xcalloc(options.num_host_key_files,
	    sizeof(struct sshkey *));
	for (i = 0; i < options.num_host_key_files; i++)
		sensitive_data.host_certificates[i] = NULL;

	for (i = 0; i < options.num_host_cert_files; i++) {
		if (options.host_cert_files[i] == NULL)
			continue;
		if ((r = sshkey_load_public(options.host_cert_files[i],
		    &key, NULL)) != 0) {
			error_r(r, "Could not load host certificate \"%s\"",
			    options.host_cert_files[i]);
			continue;
		}
		if (!sshkey_is_cert(key)) {
			error("Certificate file is not a certificate: %s",
			    options.host_cert_files[i]);
			sshkey_free(key);
			continue;
		}
		/* Find matching private key */
		for (j = 0; j < options.num_host_key_files; j++) {
			if (sshkey_equal_public(key,
			    sensitive_data.host_pubkeys[j])) {
				sensitive_data.host_certificates[j] = key;
				break;
			}
		}
		if (j >= options.num_host_key_files) {
			error("No matching private key for certificate: %s",
			    options.host_cert_files[i]);
			sshkey_free(key);
			continue;
		}
		sensitive_data.host_certificates[j] = key;
		debug("host certificate: #%u type %d %s", j, key->type,
		    sshkey_type(key));
	}

	if (privsep_chroot) {
		struct stat st;

		if ((stat(_PATH_PRIVSEP_CHROOT_DIR, &st) == -1) ||
		    (S_ISDIR(st.st_mode) == 0))
			fatal("Missing privilege separation directory: %s",
			    _PATH_PRIVSEP_CHROOT_DIR);

#ifdef HAVE_CYGWIN
		if (check_ntsec(_PATH_PRIVSEP_CHROOT_DIR) &&
		    (st.st_uid != getuid () ||
		    (st.st_mode & (S_IWGRP|S_IWOTH)) != 0))
#else
		if (st.st_uid != 0 || (st.st_mode & (S_IWGRP|S_IWOTH)) != 0)
#endif
			fatal("%s must be owned by root and not group or "
			    "world-writable.", _PATH_PRIVSEP_CHROOT_DIR);
	}

	if (test_flag > 1)
		print_config(ssh, connection_info);

	/* Configuration looks good, so exit if in test mode. */
	if (test_flag)
		exit(0);

#ifdef __ANDROID__
	/* NOTE:
	 * A  signal 31 (SIGSYS), code 1 (SYS_SECCOMP), ...
	 * A  Cause: seccomp prevented call to disallowed ... system call ...
	 */
#else
	/*
	 * Clear out any supplemental groups we may have inherited.  This
	 * prevents inadvertent creation of files with bad modes (in the
	 * portable version at least, it's certainly possible for PAM
	 * to create a file, and we can't control the code in every
	 * module which might be used).
	 */
	if (setgroups(0, NULL) == -1)
		debug("setgroups() failed: %.200s", strerror(errno));
#endif

	if (rexec_flag) {
		if (rexec_argc < 0)
			fatal("rexec_argc %d < 0", rexec_argc);
		rexec_argv = xcalloc(rexec_argc + 2, sizeof(char *));
		for (i = 0; i < (u_int)rexec_argc; i++) {
			debug("rexec_argv[%d]='%s'", i, saved_argv[i]);
			rexec_argv[i] = saved_argv[i];
		}
		rexec_argv[rexec_argc] = "-R";
		rexec_argv[rexec_argc + 1] = NULL;
	}
	listener_proctitle = prepare_proctitle(ac, av);

	/* Ensure that umask disallows at least group and world write */
	new_umask = umask(0077) | 0022;
	(void) umask(new_umask);

	/* Initialize the log (it is reinitialized below in case we forked). */
	if (debug_flag && (!inetd_flag || rexeced_flag))
		log_stderr = 1;
	log_init(__progname, options.log_level, options.log_facility, log_stderr);
	log_verbose_init(options.log_verbose, options.num_log_verbose);

	/*
	 * If not in debugging mode, not started from inetd and not already
	 * daemonized (eg re-exec via SIGHUP), disconnect from the controlling
	 * terminal, and fork.  The original process exits.
	 */
	already_daemon = daemonized();
	if (!(debug_flag || inetd_flag || no_daemon_flag || already_daemon)) {

		if (daemon(0, 0) == -1)
			fatal("daemon() failed: %.200s", strerror(errno));

		disconnect_controlling_tty();
	}
	/* Reinitialize the log (because of the fork above). */
	log_init(__progname, options.log_level, options.log_facility, log_stderr);

	/*
	 * Chdir to the root directory so that the current disk can be
	 * unmounted if desired.
	 */
	if (chdir("/") == -1)
		error("chdir(\"/\"): %s", strerror(errno));

	/* ignore SIGPIPE */
	ssh_signal(SIGPIPE, SIG_IGN);

	/* Get a connection, either from inetd or a listening TCP socket */
	if (inetd_flag) {
		server_accept_inetd(&sock_in, &sock_out);
	} else {
		platform_pre_listen();
		server_listen();

		ssh_signal(SIGHUP, sighup_handler);
		ssh_signal(SIGCHLD, main_sigchld_handler);
		ssh_signal(SIGTERM, sigterm_handler);
		ssh_signal(SIGQUIT, sigterm_handler);

		platform_post_listen();

		/*
		 * Write out the pid file after the sigterm handler
		 * is setup and the listen sockets are bound
		 */
		if (options.pid_file != NULL && !debug_flag) {
			FILE *f = fopen(options.pid_file, "w");

			if (f == NULL) {
				error("Couldn't create pid file \"%s\": %s",
				    options.pid_file, strerror(errno));
			} else {
				fprintf(f, "%ld\n", (long) getpid());
				fclose(f);
			}
		}

		/* Accept a connection and return in a forked child */
		server_accept_loop(&sock_in, &sock_out,
		    &newsock, config_s);
	}

	/* This is the child processing a new connection. */
	setproctitle("%s", "[accepted]");

	/*
	 * Create a new session and process group since the 4.4BSD
	 * setlogin() affects the entire process group.  We don't
	 * want the child to be able to affect the parent.
	 */
	if (!debug_flag && !inetd_flag && setsid() == -1)
		error("setsid: %.100s", strerror(errno));

	if (rexec_flag) {
		debug("rexec start in %d out %d newsock %d pipe %d sock %d",
		    sock_in, sock_out, newsock, startup_pipe, config_s[0]);
		if (dup2(newsock, STDIN_FILENO) == -1)
			error("dup2 reexec stdin: %s", strerror(errno));
		if (dup2(STDIN_FILENO, STDOUT_FILENO) == -1)
			error("dup2 reexec, stdout: %s", strerror(errno));
		if (startup_pipe == -1)
			close(REEXEC_STARTUP_PIPE_FD);
		else if (startup_pipe != REEXEC_STARTUP_PIPE_FD) {
			if (dup2(startup_pipe, REEXEC_STARTUP_PIPE_FD) == -1)
				error("dup2 reexec startup: %s", strerror(errno));
			close(startup_pipe);
			startup_pipe = REEXEC_STARTUP_PIPE_FD;
		}

		if (dup2(config_s[1], REEXEC_CONFIG_PASS_FD) == -1)
			error("dup2 reexec config: %s", strerror(errno));
		close(config_s[1]);

		ssh_signal(SIGHUP, SIG_IGN); /* avoid reset to SIG_DFL */
		execv(rexec_argv[0], rexec_argv);

		/* Reexec has failed, fall back and continue */
		error("rexec of %s failed: %s", rexec_argv[0], strerror(errno));
		recv_rexec_state(REEXEC_CONFIG_PASS_FD, NULL);
		log_init(__progname, options.log_level,
		    options.log_facility, log_stderr);

		/* Clean up fds */
		close(REEXEC_CONFIG_PASS_FD);
		newsock = sock_out = sock_in = dup(STDIN_FILENO);
		if (stdfd_devnull(1, 1, 0) == -1)
			error_f("stdfd_devnull failed");
		debug("rexec cleanup in %d out %d newsock %d pipe %d sock %d",
		    sock_in, sock_out, newsock, startup_pipe, config_s[0]);
	}

	/* Executed child processes don't need these. */
	(void)fcntl(sock_out, F_SETFD, FD_CLOEXEC);
	(void)fcntl(sock_in, F_SETFD, FD_CLOEXEC);

	/* We will not restart on SIGHUP since it no longer makes sense. */
	ssh_signal(SIGALRM, SIG_DFL);
	ssh_signal(SIGHUP, SIG_DFL);
	ssh_signal(SIGTERM, SIG_DFL);
	ssh_signal(SIGQUIT, SIG_DFL);
	ssh_signal(SIGCHLD, SIG_DFL);
	ssh_signal(SIGINT, SIG_DFL);

	/*
	 * Register our connection.  This turns encryption off because we do
	 * not have a key.
	 */
	ssh = create_session(sock_in, sock_out);

	check_ip_options(ssh);

	/* Prepare the channels layer */
	channel_init_channels(ssh);
	channel_set_af(ssh, options.address_family);
	server_process_permitopen(ssh);
	server_process_channel_timeouts(ssh);

	/* Set SO_KEEPALIVE if requested. */
	if (options.tcp_keep_alive && ssh_packet_connection_is_on_socket(ssh) &&
	    setsockopt(sock_in, SOL_SOCKET, SO_KEEPALIVE, &on, sizeof(on)) == -1)
		error("setsockopt SO_KEEPALIVE: %.100s", strerror(errno));

	if ((remote_port = ssh_remote_port(ssh)) < 0) {
		debug("ssh_remote_port failed");
		cleanup_exit(255);
	}

#ifdef ENABLE_ROUTING_DOMAIN
	if (options.routing_domain != NULL)
		set_process_rdomain(ssh, options.routing_domain);
#endif

	/*
	 * The rest of the code depends on the fact that
	 * ssh_remote_ipaddr() caches the remote ip, even if
	 * the socket goes away.
	 */
	remote_ip = ssh_remote_ipaddr(ssh);

#ifdef SSH_AUDIT_EVENTS
	audit_connection_from(remote_ip, remote_port);
#endif
#ifdef LIBWRAP
	allow_severity = options.log_facility|LOG_INFO;
	deny_severity = options.log_facility|LOG_WARNING;
	/* Check whether logins are denied from this host. */
	if (ssh_packet_connection_is_on_socket(ssh)) {
		struct request_info req;

		request_init(&req, RQ_DAEMON, __progname, RQ_FILE, sock_in, 0);
		fromhost(&req);

		if (!hosts_access(&req)) {
			debug("Connection refused by tcp wrapper");
			refuse(&req);
			/* NOTREACHED */
			fatal("libwrap refuse returns");
		}
	}
#endif /* LIBWRAP */

	rdomain = ssh_packet_rdomain_in(ssh);

	/* Log the connection. */
	laddr = get_local_ipaddr(sock_in);
	verbose("Connection from %s port %d on %s port %d%s%s%s",
	    remote_ip, remote_port, laddr,  ssh_local_port(ssh),
	    rdomain == NULL ? "" : " rdomain \"",
	    rdomain == NULL ? "" : rdomain,
	    rdomain == NULL ? "" : "\"");
	free(laddr);

	ssh_signal(SIGALRM, grace_alarm_handler);
	grace_alarm_start(options.login_grace_time);

	if ((r = prepare_server_banner(ssh)) != 0)
		sshpkt_fatal(ssh, r, "prepare server banner");

	if ((r = kex_exchange_identification(ssh, -1)) != 0)
		sshpkt_fatal(ssh, r, "banner exchange");

	ssh_packet_set_nonblocking(ssh);

	/* allocate authentication context */
	authctxt = xcalloc(1, sizeof(*authctxt));
	ssh->authctxt = authctxt;

	authctxt->loginmsg = loginmsg;

	/* XXX global for cleanup, access from other modules */
	the_authctxt = authctxt;

	/* Set default key authentication options */
	if ((auth_opts = sshauthopt_new_with_keys_defaults()) == NULL)
		fatal("allocation failed");

	/* prepare buffer to collect messages to display to user after login */
	if ((loginmsg = sshbuf_new()) == NULL)
		fatal_f("sshbuf_new failed");
	auth_debug_reset();

	if (use_privsep) {
		if (privsep_preauth(ssh) == 1)
			goto authenticated;
	} else if (have_agent) {
		if ((r = ssh_get_authentication_socket(&auth_sock)) != 0) {
			error_r(r, "Unable to get agent socket");
			have_agent = 0;
		}
	}

	/* perform the key exchange */
	/* authenticate user and start session */
	do_ssh2_kex(ssh);
	do_authentication2(ssh);

	/*
	 * If we use privilege separation, the unprivileged child transfers
	 * the current keystate and exits
	 */
	if (use_privsep) {
		mm_send_keystate(ssh, pmonitor);
		ssh_packet_clear_keys(ssh);
		exit(0);
	}

 authenticated:
	grace_alarm_stop();
	ssh_signal(SIGALRM, SIG_DFL);
	authctxt->authenticated = 1;
	if (startup_pipe != -1) {
		close(startup_pipe);
		startup_pipe = -1;
	}

#ifdef SSH_AUDIT_EVENTS
	audit_event(ssh, SSH_AUTH_SUCCESS);
#endif

#ifdef GSSAPI
	if (options.gss_authentication) {
		temporarily_use_uid(authctxt->pw);
		ssh_gssapi_storecreds();
		restore_uid();
	}
#endif
#ifdef USE_PAM
	if (options.use_pam) {
		do_pam_setcred(1);
		do_pam_session(ssh);
	}
#endif

	/*
	 * In privilege separation, we fork another child and prepare
	 * file descriptor passing.
	 */
	if (use_privsep) {
		privsep_postauth(ssh, authctxt);
		/* the monitor process [priv] will not return */
	}

	ssh_packet_set_timeout(ssh, options.client_alive_interval,
	    options.client_alive_count_max);

	/* Try to send all our hostkeys to the client */
	notify_hostkeys(ssh);

	/* Start session. */
	do_authenticated(ssh, authctxt);

	/* The connection has been terminated. */
	ssh_packet_get_bytes(ssh, &ibytes, &obytes);
	verbose("Transferred: sent %llu, received %llu bytes",
	    (unsigned long long)obytes, (unsigned long long)ibytes);

	verbose("Closing connection to %.500s port %d", remote_ip, remote_port);

#ifdef USE_PAM
	if (options.use_pam)
		finish_pam();
#endif /* USE_PAM */

#ifdef SSH_AUDIT_EVENTS
	PRIVSEP(audit_event(ssh, SSH_CONNECTION_CLOSE));
#endif

	the_active_state = NULL;
	(void)ssh_packet_close(ssh);
	free(ssh);

	if (use_privsep)
		mm_terminate();

	exit(0);
}
