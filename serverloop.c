/* $OpenBSD: serverloop.c,v 1.240 2024/06/17 08:28:31 djm Exp $ */
/*
 * Author: Tatu Ylonen <ylo@cs.hut.fi>
 * Copyright (c) 1995 Tatu Ylonen <ylo@cs.hut.fi>, Espoo, Finland
 *                    All rights reserved
 * Server main loop for handling the interactive session.
 *
 * As far as I am concerned, the code I have written for this software
 * can be used freely for any purpose.  Any derived versions of this
 * software must be clearly marked as such, and if the derived work is
 * incompatible with the protocol description in the RFC file, it must be
 * called by a name other than "ssh" or "Secure Shell".
 *
 * SSH2 support by Markus Friedl.
 * Copyright (c) 2000, 2001 Markus Friedl.  All rights reserved.
 * Copyright (c) 2017-2023 Roumen Petrov.  All rights reserved.
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
#include <sys/wait.h>
#include <sys/socket.h>
#ifdef HAVE_SYS_TIME_H
# include <sys/time.h>
#endif

#include <netinet/in.h>

#include <errno.h>
#include <fcntl.h>
#include <pwd.h>
#include <limits.h>
#ifdef HAVE_POLL_H
# include <poll.h>
#else
# ifdef HAVE_SYS_POLL_H
#  include <sys/poll.h>
# endif
#endif
#include <signal.h>
#include <string.h>
#include <termios.h>
#include <unistd.h>
#include <stdarg.h>

#include "openbsd-compat/sys-queue.h"
#include "xmalloc.h"
#include "packet.h"
#include "ssh-x509.h"
#include "log.h"
#include "misc.h"
#include "servconf.h"
#include "canohost.h"
#include "sshpty.h"
#include "channels.h"
#include "ssh2.h"
#include "cipher.h"
#include "kex.h"
#include "hostfile.h"
#include "auth.h"
#include "session.h"
#include "dispatch.h"
#include "auth-options.h"
#include "serverloop.h"
#include "ssherr.h"

/* read buffer size used in main loop */
#if defined(HAVE_CYGWIN) && !defined(SSHD_IOBUFSZ)
# define SSHD_IOBUFSZ	(64*1024)
#endif
#ifndef SSHD_IOBUFSZ
# define SSHD_IOBUFSZ	(4*1024)
#endif
/*	32k	16k	8k	4k
memory:	1.345	1(*)	0.920	0.867
buffer:	1.357	1.031	0.927	0.891
Relative time for sftp 64M upload where (*) is old basis.
Deviation:
memory:	0.096	0.127	0.134	0.098
buffer:	0.099	0.199	0.133	0.197
*/
#if 0
# define USE_DIRECT_READ
#endif

extern ServerOptions options;

/* XXX */
extern Authctxt *the_authctxt;
extern struct sshauthopt *auth_opts;
extern int use_privsep;

static int no_more_sessions = 0; /* Disallow further sessions. */

static volatile sig_atomic_t child_terminated = 0;	/* The child has terminated. */

/* Cleanup on signals (!use_privsep case only) */
static volatile sig_atomic_t received_sigterm = 0;

/* prototypes */
static void server_init_dispatch(struct ssh *);

/* requested tunnel forwarding interface(s), shared with session.c */
char *tun_fwd_ifnames = NULL;

/* returns 1 if bind to specified port by specified user is permitted */
static int
bind_permitted(int port, uid_t uid)
{
	if (use_privsep)
		return 1; /* allow system to decide */
	if (port < IPPORT_RESERVED && uid != 0)
		return 0;
	return 1;
}

static void
sigchld_handler(int sig)
{
	UNUSED(sig);
	child_terminated = 1;
}

static void
sigterm_handler(int sig)
{
	received_sigterm = sig;
}

static void
client_alive_check(struct ssh *ssh)
{
	char remote_id[512];
	int r, channel_id;

	/* timeout, check to see how many we have had */
	if (options.client_alive_count_max > 0 &&
	    ssh_packet_inc_alive_timeouts(ssh) >
	    options.client_alive_count_max) {
		sshpkt_fmt_connection_id(ssh, remote_id, sizeof(remote_id));
		logit("Timeout, client not responding from %s", remote_id);
		cleanup_exit(255);
	}

	/*
	 * send a bogus global/channel request with "wantreply",
	 * we should get back a failure
	 */
	if ((channel_id = channel_find_open(ssh)) == -1) {
		if ((r = sshpkt_start(ssh, SSH2_MSG_GLOBAL_REQUEST)) != 0 ||
		    (r = sshpkt_put_cstring(ssh, "keepalive@openssh.com"))
		    != 0 ||
		    (r = sshpkt_put_u8(ssh, 1)) != 0) /* boolean: want reply */
			fatal_fr(r, "compose");
	} else {
		channel_request_start(ssh, channel_id,
		    "keepalive@openssh.com", 1);
	}
	if ((r = sshpkt_send(ssh)) != 0)
		fatal_fr(r, "send");
}

/*
 * Sleep in ppoll() until we can do something.
 * Optionally, a maximum time can be specified for the duration of
 * the wait (0 = infinite).
 */
static void
wait_until_can_do_something(struct ssh *ssh,
    struct pollfd **pfdp,
    u_int *npfd_allocp, u_int *npfd_activep, sigset_t *sigsetp,
    int *conn_in_readyp, int *conn_out_readyp)
{
	struct timespec timeout;
	int ret;
	int client_alive_scheduled = 0;
	time_t now;
	static time_t last_client_time = 0, unused_connection_expiry = 0;

	*conn_in_readyp = *conn_out_readyp = 0;

	/* Prepare channel poll. First two pollfd entries are reserved */
	ptimeout_init(&timeout);
	channel_prepare_poll(ssh, pfdp, npfd_allocp, npfd_activep, 2, &timeout);
	now = monotime();

	if (*npfd_activep < 2)
		fatal_f("bad npfd %u", *npfd_activep); /* shouldn't happen */
	if (options.rekey_interval > 0 && !ssh_packet_is_rekeying(ssh))
		ptimeout_deadline_sec(&timeout,
		    ssh_packet_get_rekey_timeout(ssh));

	/*
	 * If no channels are open and UnusedConnectionTimeout is set, then
	 * start the clock to terminate the connection.
	 */
	if (options.unused_connection_timeout != 0) {
		if (channel_still_open(ssh) || unused_connection_expiry == 0) {
			unused_connection_expiry = now +
			    options.unused_connection_timeout;
		}
		ptimeout_deadline_monotime(&timeout, unused_connection_expiry);
	}

	/*
	 * if using client_alive, set the max timeout accordingly,
	 * and indicate that this particular timeout was for client
	 * alive by setting the client_alive_scheduled flag.
	 *
	 * this could be randomized somewhat to make traffic
	 * analysis more difficult, but we're not doing it yet.
	 */
	if (options.client_alive_interval) {
		/* Time we last heard from the client OR sent a keepalive */
		if (last_client_time == 0)
			last_client_time = now;
		ptimeout_deadline_sec(&timeout, options.client_alive_interval);
		/* XXX ? deadline_monotime(last_client_time + alive_interval) */
		client_alive_scheduled = 1;
	}

#if 0
	/* wrong: bad condition XXX */
	if (channel_not_very_much_buffered_data())
#endif
	/* Monitor client connection on reserved pollfd entries */
	(*pfdp)[0].fd = ssh_packet_get_connection_in(ssh);
	(*pfdp)[0].events = POLLIN;
	(*pfdp)[1].fd = ssh_packet_get_connection_out(ssh);
	(*pfdp)[1].events = ssh_packet_have_data_to_write(ssh) ? POLLOUT : 0;

	/*
	 * If child has terminated and there is enough buffer space to read
	 * from it, then read as much as is available and exit.
	 */
	if (child_terminated && ssh_packet_not_very_much_data_to_write(ssh))
		ptimeout_deadline_ms(&timeout, 100);

	/* Wait for something to happen, or the timeout to expire. */
	ret = ppoll(*pfdp, *npfd_activep, ptimeout_get_tsp(&timeout), sigsetp);

	if (ret == -1) {
		u_int p;
		for (p = 0; p < *npfd_activep; p++)
			(*pfdp)[p].revents = 0;
		if (errno != EINTR)
			fatal_f("ppoll: %.100s", strerror(errno));
		return;
	}

	*conn_in_readyp = (*pfdp)[0].revents != 0;
	*conn_out_readyp = (*pfdp)[1].revents != 0;

	now = monotime(); /* need to reset after ppoll() */
	/* ClientAliveInterval probing */
	if (client_alive_scheduled) {
		if (ret == 0 &&
		    now >= last_client_time + options.client_alive_interval) {
			/* ppoll timed out and we're due to probe */
			client_alive_check(ssh);
			last_client_time = now;
		} else if (ret != 0 && *conn_in_readyp) {
			/* Data from peer; reset probe timer. */
			last_client_time = now;
		}
	}

	/* UnusedConnectionTimeout handling */
	if (unused_connection_expiry != 0 &&
	    now > unused_connection_expiry && !channel_still_open(ssh)) {
		char remote_id[512];
		sshpkt_fmt_connection_id(ssh, remote_id, sizeof(remote_id));
		logit("terminating inactive connection from %s", remote_id);
		cleanup_exit(255);
	}
}

/*
 * Processes input from the client and the program.  Input data is stored
 * in buffers and processed later.
 */
static int
process_input(struct ssh *ssh)
{
	int r, connection_in;
#ifndef USE_DIRECT_READ
	/* read into memory buffer */
	ssize_t len;
	char buf[SSHD_IOBUFSZ];

	connection_in = ssh_packet_get_connection_in(ssh);

	/* Read and buffer any input data from the client. */
	len = read(connection_in, buf, sizeof(buf));
	if (len == -1) {
		if (errno == EAGAIN || errno == EINTR || errno == EWOULDBLOCK)
			return 0;
		verbose("Read error from remote host %s port %d: %s",
		    ssh_remote_ipaddr(ssh), ssh_remote_port(ssh),
		    strerror(errno));
		cleanup_exit(255);
	} else if (len == 0) {
		verbose("Connection closed by remote host %s port %d",
		    ssh_remote_ipaddr(ssh), ssh_remote_port(ssh));
		return -1;
	}
	/* Buffer any received data. */
	if ((r = ssh_packet_process_incoming(ssh, buf, len)) != 0)
		fatal_fr(r, "ssh_packet_process_incoming");

	return 0;
#else
	/* direct read into input buffer */
	connection_in = ssh_packet_get_connection_in(ssh);

	r = ssh_packet_process_read(ssh, connection_in, SSHD_IOBUFSZ);
	if (r == 0) return r; /* success */

	if (r == SSH_ERR_SYSTEM_ERROR) {
		if (errno == EAGAIN || errno == EINTR || errno == EWOULDBLOCK)
			return 0;
		if (errno == EPIPE) {
			logit("Connection closed by remote host %s port %d",
			    ssh_remote_ipaddr(ssh), ssh_remote_port(ssh));
			return -1;
		}
		logit("Read error from remote host %s port %d: %s",
		    ssh_remote_ipaddr(ssh), ssh_remote_port(ssh),
		    strerror(errno));
		cleanup_exit(255);
	}
	return -1;
#endif
}

/*
 * Sends data from internal buffers to client program stdin.
 */
static void
process_output(struct ssh *ssh)
{
	int r;

	/* Send any buffered packet data to the client. */
	if ((r = ssh_packet_write_poll(ssh)) != 0) {
		sshpkt_fatal(ssh, r, "%s: ssh_packet_write_poll",
		    __func__);
	}
}

static void
process_buffered_input_packets(struct ssh *ssh)
{
	ssh_dispatch_run_fatal(ssh, DISPATCH_NONBLOCK, NULL);
}

static void
collect_children(struct ssh *ssh)
{
	pid_t pid;
	int status;

	if (child_terminated) {
		debug("Received SIGCHLD.");
		while ((pid = waitpid(-1, &status, WNOHANG)) > 0 ||
		    (pid == -1 && errno == EINTR))
			if (pid > 0)
				session_close_by_pid(ssh, pid, status);
		child_terminated = 0;
	}
}

void
server_loop2(struct ssh *ssh, Authctxt *authctxt)
{
	struct pollfd *pfd = NULL;
	u_int npfd_alloc = 0, npfd_active = 0;
	sigset_t bsigset, osigset;

	UNUSED(authctxt);
	debug("Entering interactive session for SSH2.");

	if (sigemptyset(&bsigset) == -1 || sigaddset(&bsigset, SIGCHLD) == -1)
		error_f("bsigset setup: %s", strerror(errno));
	ssh_signal(SIGCHLD, sigchld_handler);
	child_terminated = 0;

	if (!use_privsep) {
		ssh_signal(SIGTERM, sigterm_handler);
		ssh_signal(SIGINT, sigterm_handler);
		ssh_signal(SIGQUIT, sigterm_handler);
	}

	server_init_dispatch(ssh);

	for (;;) {
		int conn_in_ready, conn_out_ready;

		process_buffered_input_packets(ssh);

		if (!ssh_packet_is_rekeying(ssh) &&
		    ssh_packet_not_very_much_data_to_write(ssh))
			channel_output_poll(ssh);

		/*
		 * Block SIGCHLD while we check for dead children, then pass
		 * the old signal mask through to ppoll() so that it'll wake
		 * up immediately if a child exits after we've called waitpid().
		 */
		if (sigprocmask(SIG_BLOCK, &bsigset, &osigset) == -1)
			error_f("bsigset sigprocmask: %s", strerror(errno));
		collect_children(ssh);
		wait_until_can_do_something(ssh,
		    &pfd, &npfd_alloc, &npfd_active, &osigset,
		    &conn_in_ready, &conn_out_ready);
		if (sigprocmask(SIG_SETMASK, &osigset, NULL) == -1)
			error_f("osigset sigprocmask: %s", strerror(errno));

		if (received_sigterm) {
			logit("Exiting on signal %d", (int)received_sigterm);
			/* Clean up sessions, utmp, etc. */
			cleanup_exit(255);
		}

		channel_after_poll(ssh, pfd, npfd_active);
		if (conn_in_ready &&
		    process_input(ssh) < 0)
			break;
	{	/* A timeout may have triggered rekeying */
		int r = ssh_packet_check_rekey(ssh);
		if (r != 0)
			fatal_fr(r, "cannot start rekeying");
	}
		if (conn_out_ready)
			process_output(ssh);
	}
	collect_children(ssh);
	free(pfd);

	/* free all channels, no more reads and writes */
	channel_free_all(ssh);

	/* free remaining sessions, e.g. remove wtmp entries */
	session_destroy_all(ssh, NULL);
}

static int
server_input_keep_alive(int type, u_int32_t seq, struct ssh *ssh)
{
	debug("Got %d/%u for keepalive", type, seq);
	/*
	 * reset timeout, since we got a sane answer from the client.
	 * even if this was generated by something other than
	 * the bogus CHANNEL_REQUEST we send for keepalives.
	 */
	ssh_packet_set_alive_timeouts(ssh, 0);
	return 0;
}

static Channel *
server_request_direct_tcpip(struct ssh *ssh, int *reason, const char **errmsg)
{
	Channel *c = NULL;
	char *target = NULL, *originator = NULL;
	u_int32_t target_port = 0, originator_port = 0;
	int r;

	if ((r = sshpkt_get_cstring(ssh, &target, NULL)) != 0 ||
	    (r = sshpkt_get_u32(ssh, &target_port)) != 0 ||
	    (r = sshpkt_get_cstring(ssh, &originator, NULL)) != 0 ||
	    (r = sshpkt_get_u32(ssh, &originator_port)) != 0 ||
	    (r = sshpkt_get_end(ssh)) != 0)
		sshpkt_fatal(ssh, r, "%s: parse packet", __func__);
	if (target_port > 0xFFFF) {
		error_f("invalid target port");
		*reason = SSH2_OPEN_ADMINISTRATIVELY_PROHIBITED;
		goto out;
	}
	if (originator_port > 0xFFFF) {
		error_f("invalid originator port");
		*reason = SSH2_OPEN_ADMINISTRATIVELY_PROHIBITED;
		goto out;
	}

	debug_f("originator %s port %u, target %s port %u",
	    originator, (unsigned)originator_port,
	    target, (unsigned)target_port);

	/* XXX fine grained permissions */
	if ((options.allow_tcp_forwarding & FORWARD_LOCAL) != 0 &&
	    auth_opts->permit_port_forwarding_flag &&
	    !options.disable_forwarding) {
		c = channel_connect_to_port(ssh, target, target_port,
		    "direct-tcpip", "direct-tcpip", reason, errmsg);
	} else {
		logit("refused local port forward: "
		    "originator %s port %u, target %s port %u",
		    originator, (unsigned)originator_port,
		    target, (unsigned)target_port);
		if (reason != NULL)
			*reason = SSH2_OPEN_ADMINISTRATIVELY_PROHIBITED;
	}

 out:
	free(originator);
	free(target);
	return c;
}

static Channel *
server_request_direct_streamlocal(struct ssh *ssh)
{
	Channel *c = NULL;
	char *target = NULL, *originator = NULL;
	u_int32_t originator_port = 0;
	struct passwd *pw = the_authctxt->pw;
	int r;

	if (pw == NULL || !the_authctxt->valid)
		fatal_f("no/invalid user");

	if ((r = sshpkt_get_cstring(ssh, &target, NULL)) != 0 ||
	    (r = sshpkt_get_cstring(ssh, &originator, NULL)) != 0 ||
	    (r = sshpkt_get_u32(ssh, &originator_port)) != 0 ||
	    (r = sshpkt_get_end(ssh)) != 0)
		sshpkt_fatal(ssh, r, "%s: parse packet", __func__);
	if (originator_port > 0xFFFF) {
		error_f("invalid originator port");
		goto out;
	}

	debug_f("originator %s port %u, target %s",
	    originator, (unsigned)originator_port, target);

	/* XXX fine grained permissions */
	if ((options.allow_streamlocal_forwarding & FORWARD_LOCAL) != 0 &&
	    auth_opts->permit_port_forwarding_flag &&
	    !options.disable_forwarding && (pw->pw_uid == 0 || use_privsep)) {
		c = channel_connect_to_path(ssh, target,
		    "direct-streamlocal@openssh.com", "direct-streamlocal");
	} else {
		logit("refused streamlocal port forward: "
		    "originator %s port %u, target %s",
		    originator, (unsigned)originator_port, target);
	}

out:
	free(originator);
	free(target);
	return c;
}

static Channel *
server_request_tun(struct ssh *ssh)
{
	Channel *c = NULL;
	u_int32_t mode, tun;
	int r, sock;
	char *tmp, *ifname = NULL;

	if ((r = sshpkt_get_u32(ssh, &mode)) != 0)
		sshpkt_fatal(ssh, r, "%s: parse mode", __func__);
	switch (mode) {
	case SSH_TUNMODE_POINTOPOINT:
	case SSH_TUNMODE_ETHERNET:
		break;
	default:
		ssh_packet_send_debug(ssh, "Unsupported tunnel device mode.");
		return NULL;
	}
	if ((options.permit_tun & mode) == 0) {
		ssh_packet_send_debug(ssh, "Server has rejected tunnel device "
		    "forwarding");
		return NULL;
	}

	if ((r = sshpkt_get_u32(ssh, &tun)) != 0)
		sshpkt_fatal(ssh, r, "%s: parse device", __func__);
	if ((tun > SSH_TUNID_MAX) && (tun != SSH_TUNID_ANY)) {
		debug_f("invalid tun");
		goto done;
	}
	if (auth_opts->force_tun_device != -1) {
		if (tun != SSH_TUNID_ANY &&
		    auth_opts->force_tun_device != (int)tun)
			goto done;
		tun = auth_opts->force_tun_device;
	}
	sock = tun_open(tun, mode, &ifname);
	if (sock < 0)
		goto done;
	debug("Tunnel forwarding using interface %s", ifname);

	c = channel_new(ssh, "tun", SSH_CHANNEL_OPEN, sock, sock, -1,
	    CHAN_TCP_WINDOW_DEFAULT, CHAN_TCP_PACKET_DEFAULT, 0, "tun", 1);
	c->datagram = 1;
#if defined(SSH_TUN_FILTER)
	if (mode == SSH_TUNMODE_POINTOPOINT)
		channel_register_filter(ssh, c->self, sys_tun_infilter,
		    sys_tun_outfilter, NULL, NULL);
#endif

	/*
	 * Update the list of names exposed to the session
	 * XXX remove these if the tunnels are closed (won't matter
	 * much if they are already in the environment though)
	 */
	tmp = tun_fwd_ifnames;
	xasprintf(&tun_fwd_ifnames, "%s%s%s",
	    tun_fwd_ifnames == NULL ? "" : tun_fwd_ifnames,
	    tun_fwd_ifnames == NULL ? "" : ",",
	    ifname);
	free(tmp);
	free(ifname);

 done:
	if (c == NULL)
		ssh_packet_send_debug(ssh, "Failed to open the tunnel device.");
	return c;
}

static Channel *
server_request_session(struct ssh *ssh)
{
	Channel *c;
	int r;

	debug("input_session_request");
	if ((r = sshpkt_get_end(ssh)) != 0)
		sshpkt_fatal(ssh, r, "%s: parse packet", __func__);

	if (no_more_sessions) {
		ssh_packet_disconnect(ssh, "Possible attack: attempt to open a "
		    "session after additional sessions disabled");
	}

	/*
	 * A server session has no fd to read or write until a
	 * CHANNEL_REQUEST for a shell is made, so we set the type to
	 * SSH_CHANNEL_LARVAL.  Additionally, a callback for handling all
	 * CHANNEL_REQUEST messages is registered.
	 */
	c = channel_new(ssh, "session", SSH_CHANNEL_LARVAL,
	    -1, -1, -1, /*window size*/0, CHAN_SES_PACKET_DEFAULT,
	    0, "server-session", 1);
	if (session_open(the_authctxt, c->self) != 1) {
		debug("session open failed, free channel %d", c->self);
		channel_free(ssh, c);
		return NULL;
	}
	channel_register_cleanup(ssh, c->self, session_close_by_channel, 0);
	return c;
}

static int
server_input_channel_open(int type, u_int32_t seq, struct ssh *ssh)
{
	Channel *c = NULL;
	char *ctype = NULL;
	const char *errmsg = NULL;
	int r, reason = SSH2_OPEN_CONNECT_FAILED;
	u_int32_t rchan = 0, rmaxpack = 0, rwindow = 0;

	UNUSED(type);
	UNUSED(seq);
	if ((r = sshpkt_get_cstring(ssh, &ctype, NULL)) != 0 ||
	    (r = sshpkt_get_u32(ssh, &rchan)) != 0 ||
	    (r = sshpkt_get_u32(ssh, &rwindow)) != 0 ||
	    (r = sshpkt_get_u32(ssh, &rmaxpack)) != 0)
		sshpkt_fatal(ssh, r, "%s: parse packet", __func__);
	debug_f("ctype %s rchan %u win %u max %u",
	    ctype, (unsigned)rchan, (unsigned)rwindow, (unsigned)rmaxpack);

	if (strcmp(ctype, "session") == 0) {
		c = server_request_session(ssh);
	} else if (strcmp(ctype, "direct-tcpip") == 0) {
		c = server_request_direct_tcpip(ssh, &reason, &errmsg);
	} else if (strcmp(ctype, "direct-streamlocal@openssh.com") == 0) {
		c = server_request_direct_streamlocal(ssh);
	} else if (strcmp(ctype, "tun@openssh.com") == 0) {
		c = server_request_tun(ssh);
	}
	if (c != NULL) {
		debug_f("confirm %s", ctype);
		c->remote_id = rchan;
		c->have_remote_id = 1;
		c->remote_window = rwindow;
		c->remote_maxpacket = rmaxpack;
		if (c->type != SSH_CHANNEL_CONNECTING) {
			if ((r = sshpkt_start(ssh, SSH2_MSG_CHANNEL_OPEN_CONFIRMATION)) != 0 ||
			    (r = sshpkt_put_u32(ssh, c->remote_id)) != 0 ||
			    (r = sshpkt_put_u32(ssh, c->self)) != 0 ||
			    (r = sshpkt_put_u32(ssh, c->local_window)) != 0 ||
			    (r = sshpkt_put_u32(ssh, c->local_maxpacket)) != 0 ||
			    (r = sshpkt_send(ssh)) != 0) {
				sshpkt_fatal(ssh, r,
				    "%s: send open confirm", __func__);
			}
		}
	} else {
		debug_f("failure %s", ctype);
		if ((r = sshpkt_start(ssh, SSH2_MSG_CHANNEL_OPEN_FAILURE)) != 0 ||
		    (r = sshpkt_put_u32(ssh, rchan)) != 0 ||
		    (r = sshpkt_put_u32(ssh, reason)) != 0 ||
		    (r = sshpkt_put_cstring(ssh, errmsg ? errmsg : "open failed")) != 0 ||
		    (r = sshpkt_put_cstring(ssh, "")) != 0 ||
		    (r = sshpkt_send(ssh)) != 0) {
			sshpkt_fatal(ssh, r,
			    "%s: send open failure", __func__);
		}
	}
	free(ctype);
	return 0;
}

static int
server_input_hostkeys_prove(struct ssh *ssh, struct sshbuf **respp)
{
	struct sshbuf *resp = NULL;
	struct sshbuf *sigbuf = NULL;
	struct sshkey *key = NULL, *key_pub = NULL, *key_prv = NULL;
	char *pkalg = NULL;
	int r, ndx, success = 0;
	const u_char *blob;
	const char *rsa_kexalg = NULL;
	u_char *sig = 0;
	size_t blen, slen;

	if (ssh->kex->hostkey_alg != NULL) {
		int hktype = sshkey_type_from_name(ssh->kex->hostkey_alg);
		if (sshkey_type_plain(hktype) == KEY_RSA)
			rsa_kexalg =  ssh->kex->hostkey_alg;
	}

	if ((resp = sshbuf_new()) == NULL || (sigbuf = sshbuf_new()) == NULL)
		fatal_f("sshbuf_new");

	while (ssh_packet_remaining(ssh) > 0) {
		sshkey_free(key);
		key = NULL;
		free(pkalg);
		pkalg = NULL;
		if ((r = sshpkt_get_string_direct(ssh, &blob, &blen)) != 0 ||
		    (r = parse_key_from_blob(blob, blen, &key, &pkalg)) != 0) {
			error_fr(r, "parse key");
			goto out;
		}
		debug3_f("pkalg %s", pkalg);
		/*
		 * Better check that this is actually one of our hostkeys
		 * before attempting to sign anything with it.
		 */
		if ((ndx = ssh->kex->host_key_index(key, 1, ssh)) == -1) {
			error_f("unknown host %s key", sshkey_type(key));
			goto out;
		}
		debug3_f("ndx %d", ndx);
		/*
		 * XXX refactor: make kex->sign just use an index rather
		 * than passing in public and private keys
		 */
		if ((key_prv = get_hostkey_by_index(ndx)) == NULL &&
		    (key_pub = get_hostkey_public_by_index(ndx, ssh)) == NULL) {
			error_f("can't retrieve hostkey %d", ndx);
			goto out;
		}
		sshbuf_reset(sigbuf);
		free(sig);
		sig = NULL;
		if (sshkey_type_plain(key->type) == KEY_RSA &&
		    !sshkey_is_x509(key)
		) {
			const char *rsa_keyalg = NULL;
			if (rsa_kexalg != NULL)
				rsa_keyalg = rsa_kexalg;
			else if (ssh->kex->flags & KEX_RSA_SHA2_256_SUPPORTED)
				rsa_keyalg = "rsa-sha2-256";
			else if (ssh->kex->flags & KEX_RSA_SHA2_512_SUPPORTED)
				rsa_keyalg = "rsa-sha2-512";
			debug3_f("sign rsa key %d using %s signature", ndx,
			    rsa_keyalg == NULL ? "default" : rsa_keyalg);
			if (rsa_keyalg != NULL) {
				free(pkalg);
				pkalg = xstrdup(rsa_keyalg);
			}
		}
	{	ssh_sign_ctx ctx = { pkalg, key_prv, &ssh->compat, NULL, NULL };

		if ((r = sshbuf_put_cstring(sigbuf,
		    "hostkeys-prove-00@openssh.com")) != 0 ||
		    (r = sshbuf_put_stringb(sigbuf,
		        ssh->kex->session_id)) != 0 ||
		    (r = Xkey_puts(pkalg, key, sigbuf)) != 0 ||
		    (r = ssh->kex->xsign(ssh, &ctx, key_pub, &sig, &slen,
		        sshbuf_ptr(sigbuf), sshbuf_len(sigbuf))) != 0 ||
		    (r = sshbuf_put_string(resp, sig, slen)) != 0) {
			error_fr(r, "assemble signature");
			goto out;
		}
	}
	}
	/* Success */
	*respp = resp;
	resp = NULL; /* don't free it */
	success = 1;
 out:
	free(sig);
	sshbuf_free(resp);
	sshbuf_free(sigbuf);
	sshkey_free(key);
	free(pkalg);
	return success;
}

static int
server_input_global_request(int type, u_int32_t seq, struct ssh *ssh)
{
	char *rtype = NULL;
	u_char want_reply = 0;
	int r, success = 0, allocated_listen_port = 0;
	u_int32_t port = 0;
	struct sshbuf *resp = NULL;
	struct passwd *pw = the_authctxt->pw;
	struct Forward fwd;

	UNUSED(type);
	UNUSED(seq);
	memset(&fwd, 0, sizeof(fwd));
	if (pw == NULL || !the_authctxt->valid)
		fatal_f("no/invalid user");

	if ((r = sshpkt_get_cstring(ssh, &rtype, NULL)) != 0 ||
	    (r = sshpkt_get_u8(ssh, &want_reply)) != 0)
		sshpkt_fatal(ssh, r, "%s: parse packet", __func__);
	debug_f("rtype %s want_reply %d", rtype, (int)want_reply);

	/* -R style forwarding */
	if (strcmp(rtype, "tcpip-forward") == 0) {
		if ((r = sshpkt_get_cstring(ssh, &fwd.listen_host, NULL)) != 0 ||
		    (r = sshpkt_get_u32(ssh, &port)) != 0)
			sshpkt_fatal(ssh, r, "%s: parse tcpip-forward", __func__);
		debug_f("tcpip-forward listen %s port %u",
		    fwd.listen_host, (unsigned)port);
		if (port <= INT_MAX)
			fwd.listen_port = (int)port;
		/* check permissions */
		if (port > INT_MAX ||
		    (options.allow_tcp_forwarding & FORWARD_REMOTE) == 0 ||
		    !auth_opts->permit_port_forwarding_flag ||
		    options.disable_forwarding ||
		    (!want_reply && fwd.listen_port == 0) ||
		    (fwd.listen_port != 0 &&
		    !bind_permitted(fwd.listen_port, pw->pw_uid))) {
			success = 0;
			ssh_packet_send_debug(ssh, "Server has disabled port forwarding.");
		} else {
			/* Start listening on the port */
			success = channel_setup_remote_fwd_listener(ssh, &fwd,
			    &allocated_listen_port, &options.fwd_opts);
		}
		if ((resp = sshbuf_new()) == NULL)
			fatal_f("sshbuf_new");
		if (allocated_listen_port != 0 &&
		    (r = sshbuf_put_u32(resp, allocated_listen_port)) != 0)
			fatal_fr(r, "sshbuf_put_u32");
	} else if (strcmp(rtype, "cancel-tcpip-forward") == 0) {
		if ((r = sshpkt_get_cstring(ssh, &fwd.listen_host, NULL)) != 0 ||
		    (r = sshpkt_get_u32(ssh, &port)) != 0)
			sshpkt_fatal(ssh, r, "%s: parse cancel-tcpip-forward", __func__);

		debug_f("cancel-tcpip-forward addr %s port %u",
		    fwd.listen_host, (unsigned)port);
		if (port <= INT_MAX) {
			fwd.listen_port = (int)port;
			success = channel_cancel_rport_listener(ssh, &fwd);
		}
	} else if (strcmp(rtype, "streamlocal-forward@openssh.com") == 0) {
		if ((r = sshpkt_get_cstring(ssh, &fwd.listen_path, NULL)) != 0)
			sshpkt_fatal(ssh, r, "%s: parse streamlocal-forward@openssh.com", __func__);
		debug_f("streamlocal-forward listen path %s",
		    fwd.listen_path);

		/* check permissions */
		if ((options.allow_streamlocal_forwarding & FORWARD_REMOTE) == 0
		    || !auth_opts->permit_port_forwarding_flag ||
		    options.disable_forwarding ||
		    (pw->pw_uid != 0 && !use_privsep)) {
			success = 0;
			ssh_packet_send_debug(ssh, "Server has disabled "
			    "streamlocal forwarding.");
		} else {
			/* Start listening on the socket */
			success = channel_setup_remote_fwd_listener(ssh,
			    &fwd, NULL, &options.fwd_opts);
		}
	} else if (strcmp(rtype, "cancel-streamlocal-forward@openssh.com") == 0) {
		if ((r = sshpkt_get_cstring(ssh, &fwd.listen_path, NULL)) != 0)
			sshpkt_fatal(ssh, r, "%s: parse cancel-streamlocal-forward@openssh.com", __func__);
		debug_f("cancel-streamlocal-forward path %s",
		    fwd.listen_path);

		success = channel_cancel_rport_listener(ssh, &fwd);
	} else if (strcmp(rtype, "no-more-sessions@openssh.com") == 0) {
		no_more_sessions = 1;
		success = 1;
	} else if (strcmp(rtype, "hostkeys-prove-00@openssh.com") == 0) {
		success = server_input_hostkeys_prove(ssh, &resp);
	}
	/* XXX sshpkt_get_end() */
	if (want_reply) {
		if ((r = sshpkt_start(ssh, success ?
		    SSH2_MSG_REQUEST_SUCCESS : SSH2_MSG_REQUEST_FAILURE)) != 0 ||
		    (success && resp != NULL && (r = sshpkt_putb(ssh, resp)) != 0) ||
		    (r = sshpkt_send(ssh)) != 0 ||
		    (r = ssh_packet_write_wait(ssh)) != 0)
			sshpkt_fatal(ssh, r, "%s: send reply", __func__);
	}
	free(fwd.listen_host);
	free(fwd.listen_path);
	free(rtype);
	sshbuf_free(resp);
	return 0;
}

static int
server_input_channel_req(int type, u_int32_t seq, struct ssh *ssh)
{
	Channel *c;
	int r, success = 0;
	char *rtype = NULL;
	u_char want_reply = 0;
	u_int32_t id = 0;

	UNUSED(type);
	UNUSED(seq);
	if ((r = sshpkt_get_u32(ssh, &id)) != 0 ||
	    (r = sshpkt_get_cstring(ssh, &rtype, NULL)) != 0 ||
	    (r = sshpkt_get_u8(ssh, &want_reply)) != 0)
		sshpkt_fatal(ssh, r, "%s: parse packet", __func__);

	debug("server_input_channel_req: channel %u request %s reply %d",
	    (unsigned)id, rtype, (int)want_reply);

	if (id >= INT_MAX || (c = channel_lookup(ssh, id)) == NULL) {
		ssh_packet_disconnect(ssh, "%s: unknown channel %u",
		    __func__, (unsigned)id);
	}
	if (!strcmp(rtype, "eow@openssh.com")) {
		if ((r = sshpkt_get_end(ssh)) != 0)
			sshpkt_fatal(ssh, r, "%s: parse packet", __func__);
		chan_rcvd_eow(ssh, c);
	} else if ((c->type == SSH_CHANNEL_LARVAL ||
	    c->type == SSH_CHANNEL_OPEN) && strcmp(c->ctype, "session") == 0)
		success = session_input_channel_req(ssh, c, rtype);
	if (want_reply && !(c->flags & CHAN_CLOSE_SENT)) {
		if (!c->have_remote_id)
			fatal_f("channel %d: no remote_id", c->self);
		if ((r = sshpkt_start(ssh, success ?
		    SSH2_MSG_CHANNEL_SUCCESS : SSH2_MSG_CHANNEL_FAILURE)) != 0 ||
		    (r = sshpkt_put_u32(ssh, c->remote_id)) != 0 ||
		    (r = sshpkt_send(ssh)) != 0)
			sshpkt_fatal(ssh, r, "%s: send reply", __func__);
	}
	free(rtype);
	return 0;
}

static void
server_init_dispatch(struct ssh *ssh)
{
	debug("server_init_dispatch");
	ssh_dispatch_init(ssh, &dispatch_protocol_error);
	ssh_dispatch_set(ssh, SSH2_MSG_CHANNEL_CLOSE, &channel_input_oclose);
	ssh_dispatch_set(ssh, SSH2_MSG_CHANNEL_DATA, &channel_input_data);
	ssh_dispatch_set(ssh, SSH2_MSG_CHANNEL_EOF, &channel_input_ieof);
	ssh_dispatch_set(ssh, SSH2_MSG_CHANNEL_EXTENDED_DATA, &channel_input_extended_data);
	ssh_dispatch_set(ssh, SSH2_MSG_CHANNEL_OPEN, &server_input_channel_open);
	ssh_dispatch_set(ssh, SSH2_MSG_CHANNEL_OPEN_CONFIRMATION, &channel_input_open_confirmation);
	ssh_dispatch_set(ssh, SSH2_MSG_CHANNEL_OPEN_FAILURE, &channel_input_open_failure);
	ssh_dispatch_set(ssh, SSH2_MSG_CHANNEL_REQUEST, &server_input_channel_req);
	ssh_dispatch_set(ssh, SSH2_MSG_CHANNEL_WINDOW_ADJUST, &channel_input_window_adjust);
	ssh_dispatch_set(ssh, SSH2_MSG_GLOBAL_REQUEST, &server_input_global_request);
	/* client_alive */
	ssh_dispatch_set(ssh, SSH2_MSG_CHANNEL_SUCCESS, &server_input_keep_alive);
	ssh_dispatch_set(ssh, SSH2_MSG_CHANNEL_FAILURE, &server_input_keep_alive);
	ssh_dispatch_set(ssh, SSH2_MSG_REQUEST_SUCCESS, &server_input_keep_alive);
	ssh_dispatch_set(ssh, SSH2_MSG_REQUEST_FAILURE, &server_input_keep_alive);
	/* rekeying */
	ssh_dispatch_set(ssh, SSH2_MSG_KEXINIT, &kex_input_kexinit);
}
