/* $OpenBSD: clientloop.c,v 1.411 2025/06/16 08:53:04 dtucker Exp $ */
/*
 * Author: Tatu Ylonen <ylo@cs.hut.fi>
 * Copyright (c) 1995 Tatu Ylonen <ylo@cs.hut.fi>, Espoo, Finland
 *                    All rights reserved
 * The main loop for the interactive session (client side).
 *
 * As far as I am concerned, the code I have written for this software
 * can be used freely for any purpose.  Any derived versions of this
 * software must be clearly marked as such, and if the derived work is
 * incompatible with the protocol description in the RFC file, it must be
 * called by a name other than "ssh" or "Secure Shell".
 *
 *
 * Copyright (c) 1999 Theo de Raadt.  All rights reserved.
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
 *
 *
 * SSH2 support added by Markus Friedl.
 * Copyright (c) 1999, 2000, 2001 Markus Friedl.  All rights reserved.
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
#ifdef HAVE_SYS_STAT_H
# include <sys/stat.h>
#endif
#ifdef HAVE_SYS_TIME_H
# include <sys/time.h>
#endif
#include <sys/socket.h>

#include <ctype.h>
#include <errno.h>
#ifdef HAVE_PATHS_H
#include <paths.h>
#endif
#ifdef HAVE_POLL_H
# include <poll.h>
#else
# ifdef HAVE_SYS_POLL_H
#  include <sys/poll.h>
# endif
#endif
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <termios.h>
#include <pwd.h>
#include <unistd.h>
#include <limits.h>

#include "openbsd-compat/sys-queue.h"
#include "xmalloc.h"
#include "ssh.h"
#include "ssh2.h"
#include "packet.h"
#include "ssh-x509.h"
#include "compat.h"
#include "channels.h"
#include "dispatch.h"
#include "cipher.h"
#include "kex.h"
#include "myproposal.h"
#include "log.h"
#include "misc.h"
#include "readconf.h"
#include "clientloop.h"
#include "sshconnect.h"
#include "authfd.h"
#include "atomicio.h"
#include "sshpty.h"
#include "match.h"
#include "msg.h"
#include "ssherr.h"
#include "hostfile.h"

/* read buffer size used in main loop */
#if defined(HAVE_CYGWIN) && !defined(SSH_IOBUFSZ)
# define SSH_IOBUFSZ	(64*1024)
#endif
#ifndef SSH_IOBUFSZ
# define SSH_IOBUFSZ	(8*1024)
#endif
/*	256к	64к	32к	16к	8к	4к
memory:	1.001	0.997	0.995	1.000	1(*)	1.003
buffer:	1.001	0.994	1.003	0.996	0.991	0.998
Relative time for sftp 64M download where (*) is old basis.
Deviation:
memory:	0.244	0.236	0.205	0.121	0.129	0.082
buffer:	0.165	0.080	0.100	0.074	0.124	0.160
*/
#if 0
# define USE_DIRECT_READ
#endif

/* import options */
extern Options options;

/* Control socket */
extern int muxserver_sock; /* XXX use mux_client_cleanup() instead */

/*
 * Name of the host we are connecting to.  This is the name given on the
 * command line, or the Hostname specified for the user-supplied name in a
 * configuration file.
 */
extern char *host;

/*
 * If this field is not NULL, the ForwardAgent socket is this path and different
 * instead of SSH_AUTH_SOCK.
 */
extern char *forward_agent_sock_path;

/*
 * Flag to indicate that we have received a window change signal which has
 * not yet been processed.  This will cause a message indicating the new
 * window size to be sent to the server a little later.  This is volatile
 * because this is updated in a signal handler.
 */
static volatile sig_atomic_t received_window_change_signal = 0;
static volatile sig_atomic_t received_signal = 0;

/* Time when backgrounded control master using ControlPersist should exit */
static time_t control_persist_exit_time = 0;

/* Common data for the client loop code. */
volatile sig_atomic_t quit_pending; /* Set non-zero to quit the loop. */
static int last_was_cr;		/* Last character was a newline. */
static int exit_status;		/* Used to store the command exit status. */
static int connection_in;	/* Connection to server (input). */
static int connection_out;	/* Connection to server (output). */
static int need_rekeying;	/* Set to non-zero if rekeying is requested. */
static int session_closed;	/* In SSH2: login session closed. */
static time_t x11_refuse_time = 0;	/* If >0, refuse x11 opens after this time. */
static time_t server_alive_time = 0;	/* Time to do server_alive_check */
static int hostkeys_update_complete = 0;
static int session_setup_complete = 0;

static void client_init_dispatch(struct ssh *ssh);
int	session_ident = -1;

/* Track escape per proto2 channel */
struct escape_filter_ctx {
	int escape_pending;
	int escape_char;
};

/* Context for channel confirmation replies */
struct channel_reply_ctx {
	const char *request_type;
	int id;
	enum confirm_action action;
};

/* Global request success/failure callbacks */
/* XXX move to struct ssh? */
struct global_confirm {
	TAILQ_ENTRY(global_confirm) entry;
	global_confirm_cb *cb;
	void *ctx;
	int ref_count;
};
TAILQ_HEAD(global_confirms, global_confirm);
static struct global_confirms global_confirms =
    TAILQ_HEAD_INITIALIZER(global_confirms);


static void quit_message(const char *fmt, ...)
    __attribute__((__format__ (printf, 1, 2)));

static void
quit_message(const char *fmt, ...)
{
	char *msg;

{	va_list args;
	va_start(args, fmt);
	xvasprintf(&msg, fmt, args);
	va_end(args);
}

	(void)atomicio(vwrite, STDERR_FILENO, msg, strlen(msg));
	(void)atomicio(vwrite, STDERR_FILENO, "\r\n", 2);

	free(msg);

	quit_pending = 1;
}

/*
 * Signal handler for the window change signal (SIGWINCH).  This just sets a
 * flag indicating that the window has changed.
 */
static void
window_change_handler(int sig)
{
	UNUSED(sig);
	received_window_change_signal = 1;
}

/*
 * Signal handler for signals that cause the program to terminate.  These
 * signals must be trapped to restore terminal modes.
 */
static void
signal_handler(int sig)
{
	received_signal = sig;
	quit_pending = 1;
}

/*
 * Sets control_persist_exit_time to the absolute time when the
 * backgrounded control master should exit due to expiry of the
 * ControlPersist timeout.  Sets it to 0 if we are not a backgrounded
 * control master process, or if there is no ControlPersist timeout.
 */
static void
set_control_persist_exit_time(struct ssh *ssh)
{
	if (muxserver_sock == -1 || !options.control_persist
	    || options.control_persist_timeout == 0) {
		/* not using a ControlPersist timeout */
		control_persist_exit_time = 0;
	} else if (channel_still_open(ssh)) {
		/* some client connections are still open */
		if (control_persist_exit_time > 0)
			debug2_f("cancel scheduled exit");
		control_persist_exit_time = 0;
	} else if (control_persist_exit_time <= 0) {
		/* a client connection has recently closed */
		control_persist_exit_time = monotime() +
			(time_t)options.control_persist_timeout;
		debug2_f("schedule exit in %d seconds",
		    options.control_persist_timeout);
	}
	/* else we are already counting down to the timeout */
}

#define SSH_X11_VALID_DISPLAY_CHARS ":/.-_"
static int
client_x11_display_valid(const char *display)
{
	size_t i, dlen;

	if (display == NULL)
		return 0;

	dlen = strlen(display);
	for (i = 0; i < dlen; i++) {
		if (!isalnum((u_char)display[i]) &&
		    strchr(SSH_X11_VALID_DISPLAY_CHARS, display[i]) == NULL) {
			debug("Invalid character '%c' in DISPLAY", display[i]);
			return 0;
		}
	}
	return 1;
}

#define SSH_X11_PROTO		"MIT-MAGIC-COOKIE-1"
#define X11_TIMEOUT_SLACK	60
int
client_x11_get_proto(struct ssh *ssh, const char *display,
    const char *xauth_path, u_int trusted, u_int timeout,
    char **_proto, char **_data)
{
	char *cmd, line[512], xdisplay[512];
	char xauthfile[PATH_MAX], xauthdir[PATH_MAX];
	static char proto[512], data[512];
	FILE *f;
	int got_data = 0, generated = 0, do_unlink = 0, r;
	struct stat st;
	u_int now, x11_timeout_real;

	*_proto = proto;
	*_data = data;
	proto[0] = data[0] = xauthfile[0] = xauthdir[0] = '\0';

	if (!client_x11_display_valid(display)) {
		if (display != NULL)
			logit("DISPLAY \"%s\" invalid; disabling X11 forwarding",
			    display);
		return -1;
	}
	if (xauth_path != NULL && stat(xauth_path, &st) == -1) {
		debug("No xauth program.");
		xauth_path = NULL;
	}

	if (xauth_path != NULL) {
		/*
		 * Handle FamilyLocal case where $DISPLAY does
		 * not match an authorization entry.  For this we
		 * just try "xauth list unix:displaynum.screennum".
		 * XXX: "localhost" match to determine FamilyLocal
		 *      is not perfect.
		 */
		if (strncmp(display, "localhost:", 10) == 0) {
			if ((r = snprintf(xdisplay, sizeof(xdisplay), "unix:%s",
			    display + 10)) < 0 ||
			    (size_t)r >= sizeof(xdisplay)) {
				error_f("display name too long");
				return -1;
			}
			display = xdisplay;
		}
		if (trusted == 0) {
			/*
			 * Generate an untrusted X11 auth cookie.
			 *
			 * The authentication cookie should briefly outlive
			 * ssh's willingness to forward X11 connections to
			 * avoid nasty fail-open behaviour in the X server.
			 */
			mktemp_proto(xauthdir, sizeof(xauthdir));
			if (mkdtemp(xauthdir) == NULL) {
				error_f("mkdtemp: %s", strerror(errno));
				return -1;
			}
			do_unlink = 1;
			if ((r = snprintf(xauthfile, sizeof(xauthfile),
			    "%s/xauthfile", xauthdir)) < 0 ||
			    (size_t)r >= sizeof(xauthfile)) {
				error_f("xauthfile path too long");
				rmdir(xauthdir);
				return -1;
			}

			if (timeout == 0) {
				/* auth doesn't time out */
				xasprintf(&cmd, "%s -f %s generate %s %s "
				    "untrusted 2>%s",
				    xauth_path, xauthfile, display,
				    SSH_X11_PROTO, _PATH_DEVNULL);
			} else {
				/* Add some slack to requested expiry */
				if (timeout < UINT_MAX - X11_TIMEOUT_SLACK)
					x11_timeout_real = timeout +
					    X11_TIMEOUT_SLACK;
				else {
					/* Don't overflow on long timeouts */
					x11_timeout_real = UINT_MAX;
				}
				xasprintf(&cmd, "%s -f %s generate %s %s "
				    "untrusted timeout %u 2>%s",
				    xauth_path, xauthfile, display,
				    SSH_X11_PROTO, x11_timeout_real,
				    _PATH_DEVNULL);
			}
			debug2_f("xauth command: %s", cmd);

			if (timeout != 0 && x11_refuse_time == 0) {
				now = monotime() + 1;
				if (SSH_TIME_T_MAX - timeout < now)
					x11_refuse_time = SSH_TIME_T_MAX;
				else
					x11_refuse_time = now + timeout;
				channel_set_x11_refuse_time(ssh,
				    x11_refuse_time);
			}
			if (system(cmd) == 0)
				generated = 1;
			free(cmd);
		}

		/*
		 * When in untrusted mode, we read the cookie only if it was
		 * successfully generated as an untrusted one in the step
		 * above.
		 */
		if (trusted || generated) {
			xasprintf(&cmd,
			    "%s %s%s list %s 2>" _PATH_DEVNULL,
			    xauth_path,
			    generated ? "-f " : "" ,
			    generated ? xauthfile : "",
			    display);
			debug2_f("%s", cmd);
			f = popen(cmd, "r");
			if (f && fgets(line, sizeof(line), f) &&
			    sscanf(line, "%*s %511s %511s", proto, data) == 2)
				got_data = 1;
			if (f)
				pclose(f);
			free(cmd);
		}
	}

	if (do_unlink) {
		unlink(xauthfile);
		rmdir(xauthdir);
	}

	/* Don't fall back to fake X11 data for untrusted forwarding */
	if (!trusted && !got_data) {
		error("Warning: untrusted X11 forwarding setup failed: "
		    "xauth key data not generated");
		return -1;
	}

	/*
	 * If we didn't get authentication data, just make up some
	 * data.  The forwarding code will check the validity of the
	 * response anyway, and substitute this data.  The X11
	 * server, however, will ignore this fake data and use
	 * whatever authentication mechanisms it was using otherwise
	 * for the local connection.
	 */
	if (!got_data) {
		u_int8_t rnd[16];
		u_int i;

		logit("Warning: No xauth data; "
		    "using fake authentication data for X11 forwarding.");
		strlcpy(proto, SSH_X11_PROTO, sizeof proto);
		arc4random_buf(rnd, sizeof(rnd));
		for (i = 0; i < sizeof(rnd); i++) {
			snprintf(data + 2 * i, sizeof data - 2 * i, "%02x",
			    rnd[i]);
		}
	}

	return 0;
}

/*
 * Checks if the client window has changed, and sends a packet about it to
 * the server if so.  The actual change is detected elsewhere (by a software
 * interrupt on Unix); this just checks the flag and sends a message if
 * appropriate.
 */

static void
client_check_window_change(struct ssh *ssh)
{
	if (!received_window_change_signal)
		return;
	received_window_change_signal = 0;
	debug2_f("changed");
	channel_send_window_changes(ssh);
}

static int
client_global_request_reply(int type, u_int32_t seq, struct ssh *ssh)
{
	struct global_confirm *gc;

	if ((gc = TAILQ_FIRST(&global_confirms)) == NULL)
		return 0;
	if (gc->cb != NULL)
		gc->cb(ssh, type, seq, gc->ctx);
	if (--gc->ref_count <= 0) {
		TAILQ_REMOVE(&global_confirms, gc, entry);
		freezero(gc, sizeof(*gc));
	}

	ssh_packet_set_alive_timeouts(ssh, 0);
	return 0;
}

static void
schedule_server_alive_check(void)
{
	if (options.server_alive_interval > 0)
		server_alive_time = monotime() + options.server_alive_interval;
}

static void
server_alive_check(struct ssh *ssh)
{
	int r;

	if (ssh_packet_inc_alive_timeouts(ssh) > options.server_alive_count_max) {
		logit("Timeout, server %s not responding.", host);
		cleanup_exit(255);
	}
	if ((r = sshpkt_start(ssh, SSH2_MSG_GLOBAL_REQUEST)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, "keepalive@openssh.com")) != 0 ||
	    (r = sshpkt_put_u8(ssh, 1)) != 0 ||		/* boolean: want reply */
	    (r = sshpkt_send(ssh)) != 0)
		fatal_fr(r, "send packet");
	/* Insert an empty placeholder to maintain ordering */
	client_register_global_confirm(NULL, NULL);
	schedule_server_alive_check();
}

/*
 * Waits until the client can do something (some data becomes available on
 * one of the file descriptors).
 */
static void
client_wait_until_can_do_something(struct ssh *ssh, struct pollfd **pfdp,
    u_int *npfd_allocp, u_int *npfd_activep,
    sigset_t *sigsetp, int *conn_in_readyp, int *conn_out_readyp)
{
	struct timespec timeout;
	int ret;
	u_int p;

	*conn_in_readyp = *conn_out_readyp = 0;

	/* Prepare channel poll. First two pollfd entries are reserved */
	ptimeout_init(&timeout);
	channel_prepare_poll(ssh, pfdp, npfd_allocp, npfd_activep, 2, &timeout);
	if (*npfd_activep < 2)
		fatal_f("bad npfd %u", *npfd_activep); /* shouldn't happen */

	/* channel_prepare_poll could have closed the last channel */
	if (session_closed && !channel_still_open(ssh) &&
	    !ssh_packet_have_data_to_write(ssh)) {
		/* clear events since we did not call poll() */
		for (p = 0; p < *npfd_activep; p++)
			(*pfdp)[p].revents = 0;
		return;
	}

	/* Monitor server connection on reserved pollfd entries */
	(*pfdp)[0].fd = connection_in;
	(*pfdp)[0].events = POLLIN;
	(*pfdp)[1].fd = connection_out;
	(*pfdp)[1].events = (ssh_packet_have_data_to_write(ssh)) ? POLLOUT : 0;

	/*
	 * Wait for something to happen.  This will suspend the process until
	 * some polled descriptor can be read, written, or has some other
	 * event pending, or a timeout expires.
	 */
	set_control_persist_exit_time(ssh);
	if (control_persist_exit_time > 0)
		ptimeout_deadline_monotime(&timeout, control_persist_exit_time);
	if (options.server_alive_interval > 0)
		ptimeout_deadline_monotime(&timeout, server_alive_time);
	if (options.rekey_interval > 0 && !ssh_packet_is_rekeying(ssh))
		ptimeout_deadline_sec(&timeout,
		    ssh_packet_get_rekey_timeout(ssh));

	ret = ppoll(*pfdp, *npfd_activep, ptimeout_get_tsp(&timeout), sigsetp);

	if (ret == -1) {
		/*
		 * We have to clear the events because we return.
		 * We have to return, because the mainloop checks for the flags
		 * set by the signal handlers.
		 */
		for (p = 0; p < *npfd_activep; p++)
			(*pfdp)[p].revents = 0;
		if (errno == EINTR)
			return;
		/* Note: we might still have data in the buffers. */
		quit_message("ppoll: %s", strerror(errno));
		return;
	}

	*conn_in_readyp = (*pfdp)[0].revents != 0;
	*conn_out_readyp = (*pfdp)[1].revents != 0;

	if (options.server_alive_interval > 0 && !*conn_in_readyp &&
	    monotime() >= server_alive_time) {
		/*
		 * ServerAlive check is needed. We can't rely on the poll
		 * timing out since traffic on the client side such as port
		 * forwards can keep waking it up.
		 */
		server_alive_check(ssh);
	}
}

static void
client_suspend_self(struct sshbuf *bin, struct sshbuf *bout, struct sshbuf *berr)
{
	/* Flush stdout and stderr buffers. */
	if (sshbuf_len(bout) > 0)
		atomicio(vwrite, fileno(stdout), sshbuf_mutable_ptr(bout),
		    sshbuf_len(bout));
	if (sshbuf_len(berr) > 0)
		atomicio(vwrite, fileno(stderr), sshbuf_mutable_ptr(berr),
		    sshbuf_len(berr));

	leave_raw_mode(options.request_tty == REQUEST_TTY_FORCE);

	sshbuf_reset(bin);
	sshbuf_reset(bout);
	sshbuf_reset(berr);

	/* Send the suspend signal to the program itself. */
	kill(getpid(), SIGTSTP);

	/* Reset window sizes in case they have changed */
	received_window_change_signal = 1;

	enter_raw_mode(options.request_tty == REQUEST_TTY_FORCE);
}

/*
 * Read input from the server, and add any such data to the buffer of
 * the packet subsystem.
 */
/* Read as much as possible. */
static void
client_process_net_input(struct ssh *ssh)
{
#ifndef USE_DIRECT_READ
	/* read into memory buffer */
	char buf[SSH_IOBUFSZ];
	int len;

	len = read(connection_in, buf, sizeof(buf));
	if (len == 0) {
		/*
		 * Received EOF.  The remote host has closed the
		 * connection.
		 */
		quit_message("Connection to %s closed by remote host.",
		    host);
		return;
	}
	/*
	 * There is a kernel bug on Solaris that causes select to
	 * sometimes wake up even though there is no data available.
	 */
	if (len == -1 &&
	    (errno == EAGAIN || errno == EINTR || errno == EWOULDBLOCK))
		len = 0;

	if (len == -1) {
		/*
		 * An error has encountered.  Perhaps there is a
		 * network problem.
		 */
		quit_message("Read from remote host %s: %s",
		    host, strerror(errno));
		return;
	}
	ssh_packet_process_incoming(ssh, buf, len);
#else
	/* direct read into input buffer */
	int r;

	r = ssh_packet_process_read(ssh, connection_in, SSH_IOBUFSZ);
	if (r == 0) return; /* success */

	if (r == SSH_ERR_SYSTEM_ERROR) {
		if (errno == EAGAIN || errno == EINTR || errno == EWOULDBLOCK)
			return;
		if (errno == EPIPE) {
			quit_message("Connection to %s closed by remote host.",
			    host);
			return;
		}
	}
	quit_message("Read from remote host %s: %s", host, ssh_err(r));
#endif
}

static void
client_status_confirm(struct ssh *ssh, int type, Channel *c, void *ctx)
{
	struct channel_reply_ctx *cr = (struct channel_reply_ctx *)ctx;
	char errmsg[256];
	int r, tochan;

	/*
	 * If a TTY was explicitly requested, then a failure to allocate
	 * one is fatal.
	 */
	if (cr->action == CONFIRM_TTY &&
	    (options.request_tty == REQUEST_TTY_FORCE ||
	    options.request_tty == REQUEST_TTY_YES))
		cr->action = CONFIRM_CLOSE;

	/* XXX suppress on mux _client_ quietmode */
	tochan = options.log_level >= SYSLOG_LEVEL_ERROR &&
	    c->ctl_chan != -1 && c->extended_usage == CHAN_EXTENDED_WRITE;

	if (type == SSH2_MSG_CHANNEL_SUCCESS) {
		debug2("%s request accepted on channel %d",
		    cr->request_type, c->self);
	} else if (type == SSH2_MSG_CHANNEL_FAILURE) {
		if (tochan) {
			snprintf(errmsg, sizeof(errmsg),
			    "%s request failed\r\n", cr->request_type);
		} else {
			snprintf(errmsg, sizeof(errmsg),
			    "%s request failed on channel %d",
			    cr->request_type, c->self);
		}
		/* If error occurred on primary session channel, then exit */
		if (cr->action == CONFIRM_CLOSE && c->self == session_ident)
			fatal("%s", errmsg);
		/*
		 * If error occurred on mux client, append to
		 * their stderr.
		 */
		if (tochan) {
			debug3_f("channel %d: mux request: %s", c->self,
			    cr->request_type);
			if ((r = sshbuf_put(c->extended, errmsg,
			    strlen(errmsg))) != 0)
				fatal_fr(r, "sshbuf_put");
		} else
			error("%s", errmsg);
		if (cr->action == CONFIRM_TTY) {
			/*
			 * If a TTY allocation error occurred, then arrange
			 * for the correct TTY to leave raw mode.
			 */
			if (c->self == session_ident)
				leave_raw_mode(0);
			else
				mux_tty_alloc_failed(ssh, c);
		} else if (cr->action == CONFIRM_CLOSE) {
			chan_read_failed(ssh, c);
			chan_write_failed(ssh, c);
		}
	}
	free(cr);
}

static void
client_abandon_status_confirm(struct ssh *ssh, Channel *c, void *ctx)
{
	UNUSED(ssh);
	UNUSED(c);
	free(ctx);
}

void
client_expect_confirm(struct ssh *ssh, int id, const char *request,
    enum confirm_action action)
{
	struct channel_reply_ctx *cr = xcalloc(1, sizeof(*cr));

	cr->request_type = request;
	cr->action = action;

	channel_register_status_confirm(ssh, id, client_status_confirm,
	    client_abandon_status_confirm, cr);
}

void
client_register_global_confirm(global_confirm_cb *cb, void *ctx)
{
	struct global_confirm *gc, *last_gc;

	/* Coalesce identical callbacks */
	last_gc = TAILQ_LAST(&global_confirms, global_confirms);
	if (last_gc && last_gc->cb == cb && last_gc->ctx == ctx) {
		if (++last_gc->ref_count >= INT_MAX)
			fatal_f("last_gc->ref_count = %d",
			    last_gc->ref_count);
		return;
	}

	gc = xcalloc(1, sizeof(*gc));
	gc->cb = cb;
	gc->ctx = ctx;
	gc->ref_count = 1;
	TAILQ_INSERT_TAIL(&global_confirms, gc, entry);
}

static int
can_update_hostkeys(void)
{
	if (hostkeys_update_complete)
		return 0;
	if (options.update_hostkeys == SSH_UPDATE_HOSTKEYS_ASK &&
	    options.batch_mode)
		return 0; /* won't ask in batchmode, so don't even try */
	if (!options.update_hostkeys || options.num_user_hostfiles <= 0)
		return 0;
	return 1;
}

static void
client_repledge(void)
{
	debug3_f("enter");

	/* Might be able to tighten pledge now that session is established */
	if (options.control_master || options.control_path != NULL ||
	    options.forward_x11 || options.fork_after_authentication ||
	    can_update_hostkeys() ||
	    (session_ident != -1 && !session_setup_complete)) {
		/* Can't tighten */
		return;
	}
	/*
	 * LocalCommand and UpdateHostkeys have finished, so can get rid of
	 * filesystem.
	 *
	 * XXX protocol allows a server can to change hostkeys during the
	 *     connection at rekey time that could trigger a hostkeys update
	 *     but AFAIK no implementations support this. Could improve by
	 *     forcing known_hosts to be read-only or via unveil(2).
	 */
	if (options.num_local_forwards != 0 ||
	    options.num_remote_forwards != 0 ||
	    options.num_permitted_remote_opens != 0 ||
	    options.enable_escape_commandline != 0) {
		/* rfwd needs inet */
		debug("pledge: network");
		if (pledge("stdio unix inet dns proc tty", NULL) == -1)
			fatal_f("pledge(): %s", strerror(errno));
	} else if (options.forward_agent != 0) {
		/* agent forwarding needs to open $SSH_AUTH_SOCK at will */
		debug("pledge: agent");
		if (pledge("stdio unix proc tty", NULL) == -1)
			fatal_f("pledge(): %s", strerror(errno));
	} else {
		debug("pledge: fork");
		if (pledge("stdio proc tty", NULL) == -1)
			fatal_f("pledge(): %s", strerror(errno));
	}
	/* XXX further things to do:
	 *
	 * - might be able to get rid of proc if we kill ~^Z
	 * - ssh -N (no session)
	 * - stdio forwarding
	 * - sessions without tty
	 */
}

static void
process_cmdline(struct ssh *ssh)
{
	void (*handler)(int);
	char *s, *cmd;
	int ok, delete = 0, local = 0, remote = 0, dynamic = 0;
	struct Forward fwd;

	memset(&fwd, 0, sizeof(fwd));

	leave_raw_mode(options.request_tty == REQUEST_TTY_FORCE);
	handler = ssh_signal(SIGINT, SIG_IGN);
	cmd = s = read_passphrase("\r\nssh> ", RP_ECHO);
	if (s == NULL)
		goto out;
	while (isspace((u_char)*s))
		s++;
	if (*s == '-')
		s++;	/* Skip cmdline '-', if any */
	if (*s == '\0')
		goto out;

	if (*s == 'h' || *s == 'H' || *s == '?') {
		logit("Commands:");
		logit("      -L[bind_address:]port:host:hostport    "
		    "Request local forward");
		logit("      -R[bind_address:]port:host:hostport    "
		    "Request remote forward");
		logit("      -D[bind_address:]port                  "
		    "Request dynamic forward");
		logit("      -KL[bind_address:]port                 "
		    "Cancel local forward");
		logit("      -KR[bind_address:]port                 "
		    "Cancel remote forward");
		logit("      -KD[bind_address:]port                 "
		    "Cancel dynamic forward");
		if (!options.permit_local_command)
			goto out;
		logit("      !args                                  "
		    "Execute local command");
		goto out;
	}

	if (*s == '!' && options.permit_local_command) {
		s++;
		ssh_local_cmd(s);
		goto out;
	}

	if (*s == 'K') {
		delete = 1;
		s++;
	}
	if (*s == 'L')
		local = 1;
	else if (*s == 'R')
		remote = 1;
	else if (*s == 'D')
		dynamic = 1;
	else {
		logit("Invalid command.");
		goto out;
	}

	while (isspace((u_char)*++s))
		;

	/* XXX update list of forwards in options */
	if (delete) {
		/* We pass 1 for dynamicfwd to restrict to 1 or 2 fields. */
		if (!parse_forward(&fwd, s, 1, 0)) {
			logit("Bad forwarding close specification.");
			goto out;
		}
		if (remote)
			ok = channel_request_rforward_cancel(ssh, &fwd) == 0;
		else if (dynamic)
			ok = channel_cancel_lport_listener(ssh, &fwd,
			    0, &options.fwd_opts) > 0;
		else
			ok = channel_cancel_lport_listener(ssh, &fwd,
			    CHANNEL_CANCEL_PORT_STATIC,
			    &options.fwd_opts) > 0;
		if (!ok) {
			logit("Unknown port forwarding.");
			goto out;
		}
		logit("Canceled forwarding.");
	} else {
		/* -R specs can be both dynamic or not, so check both. */
		if (remote) {
			if (!parse_forward(&fwd, s, 0, remote) &&
			    !parse_forward(&fwd, s, 1, remote)) {
				logit("Bad remote forwarding specification.");
				goto out;
			}
		} else if (!parse_forward(&fwd, s, dynamic, remote)) {
			logit("Bad local forwarding specification.");
			goto out;
		}
		if (local || dynamic) {
			if (!channel_setup_local_fwd_listener(ssh, &fwd,
			    &options.fwd_opts)) {
				logit("Port forwarding failed.");
				goto out;
			}
		} else {
			if (channel_request_remote_forwarding(ssh, &fwd) < 0) {
				logit("Port forwarding failed.");
				goto out;
			}
		}
		logit("Forwarding port.");
	}

out:
	ssh_signal(SIGINT, handler);
	enter_raw_mode(options.request_tty == REQUEST_TTY_FORCE);
	free(cmd);
	free(fwd.listen_host);
	free(fwd.listen_path);
	free(fwd.connect_host);
	free(fwd.connect_path);
}

/* reasons to suppress output of an escape command in help output */
#define SUPPRESS_NEVER		0	/* never suppress, always show */
#define SUPPRESS_MUXCLIENT	1	/* don't show in mux client sessions */
#define SUPPRESS_MUXMASTER	2	/* don't show in mux master sessions */
#define SUPPRESS_SYSLOG		4	/* don't show when logging to syslog */
#define SUPPRESS_NOCMDLINE	8	/* don't show when cmdline disabled*/
struct escape_help_text {
	const char *cmd;
	const char *text;
	unsigned int flags;
};
static struct escape_help_text esc_txt[] = {
    {".",  "terminate session", SUPPRESS_MUXMASTER},
    {".",  "terminate connection (and any multiplexed sessions)",
	SUPPRESS_MUXCLIENT},
    {"B",  "send a BREAK to the remote system", SUPPRESS_NEVER},
    {"C",  "open a command line", SUPPRESS_MUXCLIENT|SUPPRESS_NOCMDLINE},
    {"R",  "request rekey", SUPPRESS_NEVER},
    {"V/v",  "decrease/increase verbosity (LogLevel)", SUPPRESS_MUXCLIENT},
    {"^Z", "suspend ssh", SUPPRESS_MUXCLIENT},
    {"#",  "list forwarded connections", SUPPRESS_NEVER},
    {"&",  "background ssh (when waiting for connections to terminate)",
	SUPPRESS_MUXCLIENT},
    {"?", "this message", SUPPRESS_NEVER},
};

static void
print_escape_help(struct sshbuf *b, int escape_char, int mux_client,
    int using_stderr)
{
	unsigned int i, suppress_flags;
	int r;

	if ((r = sshbuf_putf(b,
	    "%c?\r\nSupported escape sequences:\r\n", escape_char)) != 0)
		fatal_fr(r, "sshbuf_putf");

	suppress_flags =
	    (mux_client ? SUPPRESS_MUXCLIENT : 0) |
	    (mux_client ? 0 : SUPPRESS_MUXMASTER) |
	    (using_stderr ? 0 : SUPPRESS_SYSLOG) |
	    (options.enable_escape_commandline == 0 ? SUPPRESS_NOCMDLINE : 0);

	for (i = 0; i < sizeof(esc_txt)/sizeof(esc_txt[0]); i++) {
		if (esc_txt[i].flags & suppress_flags)
			continue;
		if ((r = sshbuf_putf(b, " %c%-3s - %s\r\n",
		    escape_char, esc_txt[i].cmd, esc_txt[i].text)) != 0)
			fatal_fr(r, "sshbuf_putf");
	}

	if ((r = sshbuf_putf(b,
	    " %c%c   - send the escape character by typing it twice\r\n"
	    "(Note that escapes are only recognized immediately after "
	    "newline.)\r\n", escape_char, escape_char)) != 0)
		fatal_fr(r, "sshbuf_putf");
}

/*
 * Process the characters one by one.
 */
static int
process_escapes(struct ssh *ssh, Channel *c,
    struct sshbuf *bin, struct sshbuf *bout, struct sshbuf *berr,
    char *buf, int len)
{
	pid_t pid;
	int r, bytes = 0;
	u_int i;
	u_char ch;
	char *s;
	struct escape_filter_ctx *efc;

	if (c->filter_ctx == NULL || len <= 0)
		return 0;

	efc = (struct escape_filter_ctx *)c->filter_ctx;

	for (i = 0; i < (u_int)len; i++) {
		/* Get one character at a time. */
		ch = buf[i];

		if (efc->escape_pending) {
			/* We have previously seen an escape character. */
			/* Clear the flag now. */
			efc->escape_pending = 0;

			/* Process the escaped character. */
			switch (ch) {
			case '.':
				/* Terminate the connection. */
				if ((r = sshbuf_putf(berr, "%c.\r\n",
				    efc->escape_char)) != 0)
					fatal_fr(r, "sshbuf_putf");
				if (c->ctl_chan != -1) {
					channel_abandon(ssh, c);
					return 0;
				} else
					quit_pending = 1;
				return -1;

			case 'Z' - 64:
				/* XXX support this for mux clients */
				if (c->ctl_chan != -1) {
					char b[16];
 noescape:
					if (ch == 'Z' - 64)
						snprintf(b, sizeof b, "^Z");
					else
						snprintf(b, sizeof b, "%c", ch);
					if ((r = sshbuf_putf(berr,
					    "%c%s escape not available to "
					    "multiplexed sessions\r\n",
					    efc->escape_char, b)) != 0)
						fatal_fr(r, "sshbuf_putf");
					continue;
				}
				/* Suspend the program. Inform the user */
				if ((r = sshbuf_putf(berr,
				    "%c^Z [suspend ssh]\r\n",
				    efc->escape_char)) != 0)
					fatal_fr(r, "sshbuf_putf");

				/* Restore terminal modes and suspend. */
				client_suspend_self(bin, bout, berr);

				/* We have been continued. */
				continue;

			case 'B':
				if ((r = sshbuf_putf(berr,
				    "%cB\r\n", efc->escape_char)) != 0)
					fatal_fr(r, "sshbuf_putf");
				channel_request_start(ssh, c->self, "break", 0);
				if ((r = sshpkt_put_u32(ssh, 1000)) != 0 ||
				    (r = sshpkt_send(ssh)) != 0)
					fatal_fr(r, "send packet");
				continue;

			case 'R':
				if (ssh_compat_fellows(ssh, SSH_BUG_NOREKEY))
					logit("Server does not "
					    "support re-keying");
				else
					need_rekeying = 1;
				continue;

			case 'V':
				/* FALLTHROUGH */
			case 'v':
				if (c->ctl_chan != -1)
					goto noescape;
				if (!log_is_on_stderr()) {
					if ((r = sshbuf_putf(berr,
					    "%c%c [Logging to syslog]\r\n",
					    efc->escape_char, ch)) != 0)
						fatal_fr(r, "sshbuf_putf");
					continue;
				}
				if (ch == 'V' && options.log_level >
				    SYSLOG_LEVEL_QUIET)
					log_change_level(--options.log_level);
				if (ch == 'v' && options.log_level <
				    SYSLOG_LEVEL_DEBUG3)
					log_change_level(++options.log_level);
				if ((r = sshbuf_putf(berr,
				    "%c%c [LogLevel %s]\r\n",
				    efc->escape_char, ch,
				    log_level_name(options.log_level))) != 0)
					fatal_fr(r, "sshbuf_putf");
				continue;

			case '&':
				if (c->ctl_chan != -1)
					goto noescape;
				/*
				 * Detach the program (continue to serve
				 * connections, but put in background and no
				 * more new connections).
				 */
				/* Restore tty modes. */
				leave_raw_mode(
				    options.request_tty == REQUEST_TTY_FORCE);

				/* Stop listening for new connections. */
				channel_stop_listening(ssh);

				if ((r = sshbuf_putf(berr, "%c& "
				    "[backgrounded]\n", efc->escape_char)) != 0)
					fatal_fr(r, "sshbuf_putf");

				/* Fork into background. */
				pid = fork();
				if (pid == -1) {
					error("fork: %.100s", strerror(errno));
					continue;
				}
				if (pid != 0) {	/* This is the parent. */
					/* The parent just exits. */
					exit(0);
				}
				/* The child continues serving connections. */
				/* fake EOF on stdin */
				if ((r = sshbuf_put_u8(bin, 4)) != 0)
					fatal_fr(r, "sshbuf_put_u8");
				return -1;
			case '?':
				print_escape_help(berr, efc->escape_char,
				    (c->ctl_chan != -1),
				    log_is_on_stderr());
				continue;

			case '#':
				if ((r = sshbuf_putf(berr, "%c#\r\n",
				    efc->escape_char)) != 0)
					fatal_fr(r, "sshbuf_putf");
				s = channel_open_message(ssh);
				if ((r = sshbuf_put(berr, s, strlen(s))) != 0)
					fatal_fr(r, "sshbuf_put");
				free(s);
				continue;

			case 'C':
				if (c->ctl_chan != -1)
					goto noescape;
				if (options.enable_escape_commandline == 0) {
					if ((r = sshbuf_putf(berr,
					    "commandline disabled\r\n")) != 0)
						fatal_fr(r, "sshbuf_putf");
					continue;
				}
				process_cmdline(ssh);
				continue;

			default:
				if (ch != efc->escape_char) {
					if ((r = sshbuf_put_u8(bin,
					    efc->escape_char)) != 0)
						fatal_fr(r, "sshbuf_put_u8");
					bytes++;
				}
				/* Escaped characters fall through here */
				break;
			}
		} else {
			/*
			 * The previous character was not an escape char.
			 * Check if this is an escape.
			 */
			if (last_was_cr && ch == efc->escape_char) {
				/*
				 * It is. Set the flag and continue to
				 * next character.
				 */
				efc->escape_pending = 1;
				continue;
			}
		}

		/*
		 * Normal character.  Record whether it was a newline,
		 * and append it to the buffer.
		 */
		last_was_cr = (ch == '\r' || ch == '\n');
		if ((r = sshbuf_put_u8(bin, ch)) != 0)
			fatal_fr(r, "sshbuf_put_u8");
		bytes++;
	}
	return bytes;
}

/*
 * Get packets from the connection input buffer, and process them as long as
 * there are packets available.
 *
 * Any unknown packets received during the actual
 * session cause the session to terminate.  This is
 * intended to make debugging easier since no
 * confirmations are sent.  Any compatible protocol
 * extensions must be negotiated during the
 * preparatory phase.
 */

static void
client_process_buffered_input_packets(struct ssh *ssh)
{
	ssh_dispatch_run_fatal(ssh, DISPATCH_NONBLOCK, &quit_pending);
}

/* scan buf[] for '~' before sending data to the peer */

/* Helper: allocate a new escape_filter_ctx and fill in its escape char */
void *
client_new_escape_filter_ctx(int escape_char)
{
	struct escape_filter_ctx *ret;

	ret = xcalloc(1, sizeof(*ret));
	ret->escape_pending = 0;
	ret->escape_char = escape_char;
	return (void *)ret;
}

/* Free the escape filter context on channel free */
void
client_filter_cleanup(struct ssh *ssh, int cid, void *ctx)
{
	UNUSED(ssh);
	UNUSED(cid);
	free(ctx);
}

int
client_simple_escape_filter(struct ssh *ssh, Channel *c, char *buf, int len)
{
	if (c->extended_usage != CHAN_EXTENDED_WRITE)
		return 0;

	return process_escapes(ssh, c, c->input, c->output, c->extended,
	    buf, len);
}

static void
client_channel_closed(struct ssh *ssh, int id, int force, void *arg)
{
	UNUSED(force);
	UNUSED(arg);
	channel_cancel_cleanup(ssh, id);
	session_closed = 1;
	leave_raw_mode(options.request_tty == REQUEST_TTY_FORCE);
}

/*
 * Implements the interactive session with the server.  This is called after
 * the user has been authenticated, and a command has been started on the
 * remote host.  If escape_char != SSH_ESCAPECHAR_NONE, it is the character
 * used as an escape character for terminating or suspending the session.
 */
int
client_loop(struct ssh *ssh, int have_pty, int escape_char_arg,
    int ssh2_chan_id)
{
	struct pollfd *pfd = NULL;
	u_int npfd_alloc = 0, npfd_active = 0;
	double start_time, total_time;
	int r;
	u_int64_t ibytes, obytes;
	sigset_t bsigset, osigset;

	debug("Entering interactive session.");
	session_ident = ssh2_chan_id;

	if (options.control_master &&
	    !option_clear_or_none(options.control_path)) {
		debug("pledge: id");
		if (pledge("stdio rpath wpath cpath unix inet dns recvfd sendfd proc exec id tty",
		    NULL) == -1)
			fatal_f("pledge(): %s", strerror(errno));

	} else if (options.forward_x11 || options.permit_local_command) {
		debug("pledge: exec");
		if (pledge("stdio rpath wpath cpath unix inet dns proc exec tty",
		    NULL) == -1)
			fatal_f("pledge(): %s", strerror(errno));

	} else if (options.update_hostkeys) {
		debug("pledge: filesystem");
		if (pledge("stdio rpath wpath cpath unix inet dns proc tty",
		    NULL) == -1)
			fatal_f("pledge(): %s", strerror(errno));

	} else if (!option_clear_or_none(options.proxy_command) ||
	    options.fork_after_authentication) {
		debug("pledge: proc");
		if (pledge("stdio cpath unix inet dns proc tty", NULL) == -1)
			fatal_f("pledge(): %s", strerror(errno));

	} else {
		debug("pledge: network");
		if (pledge("stdio unix inet dns proc tty", NULL) == -1)
			fatal_f("pledge(): %s", strerror(errno));
	}

	/* might be able to tighten now */
	client_repledge();

	start_time = monotime_double();

	/* Initialize variables. */
	last_was_cr = 1;
	exit_status = -1;
	connection_in = ssh_packet_get_connection_in(ssh);
	connection_out = ssh_packet_get_connection_out(ssh);

	quit_pending = 0;

	client_init_dispatch(ssh);

	/*
	 * Set signal handlers, (e.g. to restore non-blocking mode)
	 * but don't overwrite SIG_IGN, matches behaviour from rsh(1)
	 */
	if (ssh_signal(SIGHUP, SIG_IGN) != SIG_IGN)
		ssh_signal(SIGHUP, signal_handler);
	if (ssh_signal(SIGINT, SIG_IGN) != SIG_IGN)
		ssh_signal(SIGINT, signal_handler);
	if (ssh_signal(SIGQUIT, SIG_IGN) != SIG_IGN)
		ssh_signal(SIGQUIT, signal_handler);
	if (ssh_signal(SIGTERM, SIG_IGN) != SIG_IGN)
		ssh_signal(SIGTERM, signal_handler);
	ssh_signal(SIGWINCH, window_change_handler);

	if (have_pty)
		enter_raw_mode(options.request_tty == REQUEST_TTY_FORCE);

	if (session_ident != -1) {
		if (escape_char_arg != SSH_ESCAPECHAR_NONE) {
			channel_register_filter(ssh, session_ident,
			    client_simple_escape_filter, NULL,
			    client_filter_cleanup,
			    client_new_escape_filter_ctx(
			    escape_char_arg));
		}
		channel_register_cleanup(ssh, session_ident,
		    client_channel_closed, 0);
	}

	schedule_server_alive_check();

	if (sigemptyset(&bsigset) == -1 ||
	    sigaddset(&bsigset, SIGHUP) == -1 ||
	    sigaddset(&bsigset, SIGINT) == -1 ||
	    sigaddset(&bsigset, SIGQUIT) == -1 ||
	    sigaddset(&bsigset, SIGTERM) == -1)
		error_f("bsigset setup: %s", strerror(errno));

	/* Main loop of the client for the interactive session mode. */
	while (!quit_pending) {
		int conn_in_ready, conn_out_ready;

		/* Process buffered packets sent by the server. */
		client_process_buffered_input_packets(ssh);

		if (session_closed && !channel_still_open(ssh))
			break;

		if (ssh_packet_is_rekeying(ssh)) {
			debug("rekeying in progress");
		} else if (need_rekeying) {
			/* manual rekey request */
			debug("need rekeying");
			if ((r = kex_start_rekex(ssh)) != 0)
				fatal_fr(r, "kex_start_rekex");
			need_rekeying = 0;
		} else {
			/*
			 * Make packets from buffered channel data, and
			 * enqueue them for sending to the server.
			 */
			if (ssh_packet_not_very_much_data_to_write(ssh))
				channel_output_poll(ssh);

			/*
			 * Check if the window size has changed, and buffer a
			 * message about it to the server if so.
			 */
			client_check_window_change(ssh);
		}
		/*
		 * Wait until we have something to do (something becomes
		 * available on one of the descriptors).
		 */
		if (sigprocmask(SIG_BLOCK, &bsigset, &osigset) == -1)
			error_f("bsigset sigprocmask: %s", strerror(errno));
		if (quit_pending)
			break;
		client_wait_until_can_do_something(ssh, &pfd, &npfd_alloc,
		    &npfd_active, &osigset,
		    &conn_in_ready, &conn_out_ready);
		if (sigprocmask(SIG_SETMASK, &osigset, NULL) == -1)
			error_f("osigset sigprocmask: %s", strerror(errno));

		if (quit_pending)
			break;

		/* Do channel operations. */
		channel_after_poll(ssh, pfd, npfd_active);

		/* Buffer input from the connection.  */
		if (conn_in_ready) {
			schedule_server_alive_check();
			client_process_net_input(ssh);
		}

		if (quit_pending)
			break;

		/* A timeout may have triggered rekeying */
		if ((r = ssh_packet_check_rekey(ssh)) != 0)
			fatal_fr(r, "cannot start rekeying");

		/*
		 * Send as much buffered packet data as possible to the
		 * sender.
		 */
		if (conn_out_ready) {
			if ((r = ssh_packet_write_poll(ssh)) != 0) {
				sshpkt_fatal(ssh, r,
				    "%s: ssh_packet_write_poll", __func__);
			}
		}

		/*
		 * If we are a backgrounded control master, and the
		 * timeout has expired without any active client
		 * connections, then quit.
		 */
		if (control_persist_exit_time > 0) {
			if (monotime() >= control_persist_exit_time) {
				debug("ControlPersist timeout expired");
				break;
			}
		}
	}
	free(pfd);

	/* Terminate the session. */

	/*
	 * In interactive mode (with pseudo tty) display a message indicating
	 * that the connection has been closed.
	 */
	if (have_pty && options.log_level >= SYSLOG_LEVEL_INFO)
		quit_message("Connection to %s closed.", host);


	/* Stop watching for window change. */
	ssh_signal(SIGWINCH, SIG_DFL);

	if ((r = sshpkt_start(ssh, SSH2_MSG_DISCONNECT)) != 0 ||
	    (r = sshpkt_put_u32(ssh, SSH2_DISCONNECT_BY_APPLICATION)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, "disconnected by user")) != 0 ||
	    (r = sshpkt_put_cstring(ssh, "")) != 0 ||	/* language tag */
	    (r = sshpkt_send(ssh)) != 0 ||
	    (r = ssh_packet_write_wait(ssh)) != 0)
		fatal_fr(r, "send disconnect");

	channel_free_all(ssh);

	if (have_pty)
		leave_raw_mode(options.request_tty == REQUEST_TTY_FORCE);

	/*
	 * If there was no shell or command requested, there will be no remote
	 * exit status to be returned.  In that case, clear error code if the
	 * connection was deliberately terminated at this end.
	 */
	if (options.session_type == SESSION_TYPE_NONE && received_signal == SIGTERM) {
		received_signal = 0;
		exit_status = 0;
	}

	if (received_signal) {
		verbose("Killed by signal %d.", (int) received_signal);
		cleanup_exit(128 + received_signal); /*shell style*/
	}

	/* Report bytes transferred, and transfer rates. */
	total_time = monotime_double() - start_time;
	ssh_packet_get_bytes(ssh, &ibytes, &obytes);
	verbose("Transferred: sent %llu, received %llu bytes, in %.1f seconds",
	    (unsigned long long)obytes, (unsigned long long)ibytes, total_time);
	if (total_time > 0)
		verbose("Bytes per second: sent %.1f, received %.1f",
		    obytes / total_time, ibytes / total_time);
	/* Return the exit status of the program. */
	debug("Exit status %d", exit_status);
	return exit_status;
}

/*********/

static Channel *
client_request_forwarded_tcpip(struct ssh *ssh, const char *request_type,
    int rchan, u_int rwindow, u_int rmaxpack)
{
	Channel *c = NULL;
	struct sshbuf *b = NULL;
	char *listen_address, *originator_address;
	u_int32_t listen_port, originator_port;
	int r;

	/* Get rest of the packet */
	if ((r = sshpkt_get_cstring(ssh, &listen_address, NULL)) != 0 ||
	    (r = sshpkt_get_u32(ssh, &listen_port)) != 0 ||
	    (r = sshpkt_get_cstring(ssh, &originator_address, NULL)) != 0 ||
	    (r = sshpkt_get_u32(ssh, &originator_port)) != 0 ||
	    (r = sshpkt_get_end(ssh)) != 0)
		fatal_fr(r, "parse packet");

	debug_f("listen %s port %d, originator %s port %d",
	    listen_address, (int)listen_port, originator_address, (int)originator_port);

	if (listen_port > 0xffff)
		error_f("invalid listen port");
	else if (originator_port > 0xffff)
		error_f("invalid originator port");
	else {
		c = channel_connect_by_listen_address(ssh,
		    listen_address, listen_port, "forwarded-tcpip",
		    originator_address);
	}

	if (c != NULL && c->type == SSH_CHANNEL_MUX_CLIENT) {
		if ((b = sshbuf_new()) == NULL) {
			error_f("alloc reply");
			goto out;
		}
		/* reconstruct and send to muxclient */
		if ((r = sshbuf_put_u8(b, 0)) != 0 ||	/* padlen */
		    (r = sshbuf_put_u8(b, SSH2_MSG_CHANNEL_OPEN)) != 0 ||
		    (r = sshbuf_put_cstring(b, request_type)) != 0 ||
		    (r = sshbuf_put_u32(b, rchan)) != 0 ||
		    (r = sshbuf_put_u32(b, rwindow)) != 0 ||
		    (r = sshbuf_put_u32(b, rmaxpack)) != 0 ||
		    (r = sshbuf_put_cstring(b, listen_address)) != 0 ||
		    (r = sshbuf_put_u32(b, listen_port)) != 0 ||
		    (r = sshbuf_put_cstring(b, originator_address)) != 0 ||
		    (r = sshbuf_put_u32(b, originator_port)) != 0 ||
		    (r = sshbuf_put_stringb(c->output, b)) != 0) {
			error_fr(r, "compose for muxclient");
			goto out;
		}
	}

 out:
	sshbuf_free(b);
	free(originator_address);
	free(listen_address);
	return c;
}

static Channel *
client_request_forwarded_streamlocal(struct ssh *ssh,
    const char *request_type, int rchan)
{
	Channel *c = NULL;
	char *listen_path;
	int r;

	UNUSED(request_type);
	UNUSED(rchan);
	/* Get the remote path. */
	if ((r = sshpkt_get_cstring(ssh, &listen_path, NULL)) != 0 ||
	    (r = sshpkt_get_string(ssh, NULL, NULL)) != 0 ||	/* reserved */
	    (r = sshpkt_get_end(ssh)) != 0)
		fatal_fr(r, "parse packet");

	debug_f("request: %s", listen_path);

	c = channel_connect_by_listen_path(ssh, listen_path,
	    "forwarded-streamlocal@openssh.com", "forwarded-streamlocal");
	free(listen_path);
	return c;
}

static Channel *
client_request_x11(struct ssh *ssh, const char *request_type, int rchan)
{
	Channel *c = NULL;
	char *originator;
	u_int32_t originator_port;
	int r, sock;

	UNUSED(request_type);
	UNUSED(rchan);
	if (!options.forward_x11) {
		error("Warning: ssh server tried X11 forwarding.");
		error("Warning: this is probably a break-in attempt by a "
		    "malicious server.");
		return NULL;
	}
	if (x11_refuse_time != 0 && monotime() >= x11_refuse_time) {
		verbose("Rejected X11 connection after ForwardX11Timeout "
		    "expired");
		return NULL;
	}
	if ((r = sshpkt_get_cstring(ssh, &originator, NULL)) != 0 ||
	    (r = sshpkt_get_u32(ssh, &originator_port)) != 0 ||
	    (r = sshpkt_get_end(ssh)) != 0)
		fatal_fr(r, "parse packet");
	/* XXX check permission */
	/* XXX range check originator port? */
	debug_f("request from %s %u", originator, (unsigned)originator_port);
	free(originator);
	sock = x11_connect_display(ssh);
	if (sock < 0)
		return NULL;
	c = channel_new(ssh, "x11-connection",
	    SSH_CHANNEL_X11_OPEN, sock, sock, -1,
	    CHAN_TCP_WINDOW_DEFAULT, CHAN_X11_PACKET_DEFAULT, 0, "x11",
	    CHANNEL_NONBLOCK_SET);
	c->force_drain = 1;
	return c;
}

static Channel *
client_request_agent(struct ssh *ssh, const char *request_type, int rchan)
{
	Channel *c = NULL;
	int r, sock;

	UNUSED(request_type);
	UNUSED(rchan);
	if (!options.forward_agent) {
		error("Warning: ssh server tried agent forwarding.");
		error("Warning: this is probably a break-in attempt by a "
		    "malicious server.");
		return NULL;
	}
	if (forward_agent_sock_path == NULL) {
		r = ssh_get_authentication_socket(&sock);
	} else {
		r = ssh_get_authentication_socket_path(forward_agent_sock_path, &sock);
	}
	if (r != 0) {
		if (r != SSH_ERR_AGENT_NOT_PRESENT)
			error_fr(r, "ssh_get_authentication_socket");
		return NULL;
	}
	c = channel_new(ssh, "agent-connection",
	    SSH_CHANNEL_OPEN, sock, sock, -1,
	    CHAN_X11_WINDOW_DEFAULT, CHAN_TCP_PACKET_DEFAULT, 0,
	    "authentication agent connection", CHANNEL_NONBLOCK_SET);
	c->force_drain = 1;
	return c;
}

char *
client_request_tun_fwd(struct ssh *ssh, int tun_mode,
    int local_tun, int remote_tun, channel_open_fn *cb, void *cbctx)
{
	Channel *c;
	int r, fd;
	char *ifname = NULL;

	if (tun_mode == SSH_TUNMODE_NO)
		return 0;

	debug("Requesting tun unit %d in mode %d", local_tun, tun_mode);

	/* Open local tunnel device */
	if ((fd = tun_open(local_tun, tun_mode, &ifname)) == -1) {
		error("Tunnel device open failed.");
		return NULL;
	}
	debug("Tunnel forwarding using interface %s", ifname);

	c = channel_new(ssh, "tun-connection", SSH_CHANNEL_OPENING, fd, fd, -1,
	    CHAN_TCP_WINDOW_DEFAULT, CHAN_TCP_PACKET_DEFAULT, 0, "tun",
	    CHANNEL_NONBLOCK_SET);
	c->datagram = 1;

#if defined(SSH_TUN_FILTER)
	if (options.tun_open == SSH_TUNMODE_POINTOPOINT)
		channel_register_filter(ssh, c->self, sys_tun_infilter,
		    sys_tun_outfilter, NULL, NULL);
#endif

	if (cb != NULL)
		channel_register_open_confirm(ssh, c->self, cb, cbctx);

	if ((r = sshpkt_start(ssh, SSH2_MSG_CHANNEL_OPEN)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, "tun@openssh.com")) != 0 ||
	    (r = sshpkt_put_u32(ssh, c->self)) != 0 ||
	    (r = sshpkt_put_u32(ssh, c->local_window_max)) != 0 ||
	    (r = sshpkt_put_u32(ssh, c->local_maxpacket)) != 0 ||
	    (r = sshpkt_put_u32(ssh, tun_mode)) != 0 ||
	    (r = sshpkt_put_u32(ssh, remote_tun)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		sshpkt_fatal(ssh, r, "%s: send reply", __func__);

	return ifname;
}

/* XXXX move to generic input handler */
static int
client_input_channel_open(int type, u_int32_t seq, struct ssh *ssh)
{
	Channel *c = NULL;
	char *ctype = NULL;
	int r;
	size_t len;
	u_int32_t rchan, rmaxpack, rwindow;

	UNUSED(type);
	UNUSED(seq);
	if ((r = sshpkt_get_cstring(ssh, &ctype, &len)) != 0 ||
	    (r = sshpkt_get_u32(ssh, &rchan)) != 0 ||
	    (r = sshpkt_get_u32(ssh, &rwindow)) != 0 ||
	    (r = sshpkt_get_u32(ssh, &rmaxpack)) != 0)
		goto out;

	debug_f("ctype %s rchan %d win %d max %d",
	    ctype, (int)rchan, (int)rwindow, (int)rmaxpack);

	if (strcmp(ctype, "forwarded-tcpip") == 0) {
		c = client_request_forwarded_tcpip(ssh, ctype, rchan, rwindow,
		    rmaxpack);
	} else if (strcmp(ctype, "forwarded-streamlocal@openssh.com") == 0) {
		c = client_request_forwarded_streamlocal(ssh, ctype, rchan);
	} else if (strcmp(ctype, "x11") == 0) {
		c = client_request_x11(ssh, ctype, rchan);
	} else if (strcmp(ctype, "auth-agent@openssh.com") == 0) {
		c = client_request_agent(ssh, ctype, rchan);
	}
	if (c != NULL && c->type == SSH_CHANNEL_MUX_CLIENT) {
		debug3("proxied to downstream: %s", ctype);
	} else if (c != NULL) {
		debug("confirm %s", ctype);
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
			    (r = sshpkt_send(ssh)) != 0)
				sshpkt_fatal(ssh, r, "%s: send reply", __func__);
		}
	} else {
		debug("failure %s", ctype);
		if ((r = sshpkt_start(ssh, SSH2_MSG_CHANNEL_OPEN_FAILURE)) != 0 ||
		    (r = sshpkt_put_u32(ssh, rchan)) != 0 ||
		    (r = sshpkt_put_u32(ssh, SSH2_OPEN_ADMINISTRATIVELY_PROHIBITED)) != 0 ||
		    (r = sshpkt_put_cstring(ssh, "open failed")) != 0 ||
		    (r = sshpkt_put_cstring(ssh, "")) != 0 ||
		    (r = sshpkt_send(ssh)) != 0)
			sshpkt_fatal(ssh, r, "%s: send failure", __func__);
	}

 out:
	free(ctype);
	return r;
}

static int
client_input_channel_req(int type, u_int32_t seq, struct ssh *ssh)
{
	Channel *c = NULL;
	char *rtype = NULL;
	u_char reply;
	int id;
	int r, success = 0;

{	u_int32_t val;
	if ((r = sshpkt_get_u32(ssh, &val)) != 0)
		return r;
	id = val; /*safe cast*/
}
	/* channel_by_id() filter bad id */
	c = channel_lookup(ssh, id);
	/* channel_proxy_upstream() filter NULL channel */
	if (channel_proxy_upstream(c, type, seq, ssh))
		return 0;
	if ((r = sshpkt_get_cstring(ssh, &rtype, NULL)) != 0 ||
	    (r = sshpkt_get_u8(ssh, &reply)) != 0)
		goto out;

	debug_f("channel %d rtype %s reply %d", id, rtype, (int)reply);

	if (c == NULL) {
		error_f("channel %d: unknown channel", id);
	} else if (strcmp(rtype, "eow@openssh.com") == 0) {
		if ((r = sshpkt_get_end(ssh)) != 0)
			goto out;
		chan_rcvd_eow(ssh, c);
	} else if (strcmp(rtype, "exit-status") == 0) {
		u_int32_t exitval;
		if ((r = sshpkt_get_u32(ssh, &exitval)) != 0)
			goto out;
		debug3_f("remote exit with code %d", (int)exitval);
		if (c->ctl_chan != -1) {
			mux_exit_message(ssh, c, exitval);
			success = 1;
		} else if (id == session_ident) {
			/* Record exit value of local session */
			success = 1;
			exit_status = exitval;
		} else {
			/* Probably for a mux channel that has already closed */
			debug_f("no sink for exit-status on channel %d", id);
		}
		if ((r = sshpkt_get_end(ssh)) != 0)
			goto out;
	} else if (strcmp(rtype, "exit-signal") == 0) {
		char *signame = NULL;
		int exitval;

		if ((r = sshpkt_get_cstring(ssh, &signame, NULL)) != 0 ||
		    (r = sshpkt_get_u8(ssh, NULL/*core dumped*/)) != 0 ||
		    (r = sshpkt_get_cstring(ssh, NULL/*error message*/, NULL)) != 0 ||
		    (r = sshpkt_get_cstring(ssh, NULL/*language*/, NULL)) != 0 ||
		    (r = sshpkt_get_end(ssh)) != 0
		) {
			free(signame);
			goto out;
		}

		exitval = ssh_signame2code(signame);
		debug3_f("remote killed by signal '%s'", signame);
		free(signame);

		if (exitval >= 0) exitval += 128; /*shell style*/

		if (c->ctl_chan != -1) {
			mux_exit_message(ssh, c, exitval);
			success = 1;
		} else if (id == session_ident) {
			/* Record exit value of local session */
			success = 1;
			exit_status = exitval;
		} else {
			/* Probably for a mux channel that has already closed */
			debug_f("no sink for exit-signal on channel %d", id);
		}
	}
	if (reply && c != NULL && !(c->flags & CHAN_CLOSE_SENT)) {
		if (!c->have_remote_id)
			fatal_f("channel %d: no remote_id", c->self);
		if ((r = sshpkt_start(ssh, success ?
		    SSH2_MSG_CHANNEL_SUCCESS : SSH2_MSG_CHANNEL_FAILURE)) != 0 ||
		    (r = sshpkt_put_u32(ssh, c->remote_id)) != 0 ||
		    (r = sshpkt_send(ssh)) != 0)
			sshpkt_fatal(ssh, r, "%s: send failure", __func__);
	}

 out:
	free(rtype);
	return r;
}

struct hostkeys_update_ctx {
	/* The hostname and (optionally) IP address string for the server */
	char *host_str, *ip_str;

	/*
	 * Keys received from the server and a flag for each indicating
	 * whether they already exist in known_hosts.
	 * keys_match is filled in by hostkeys_find() and later (for new
	 * keys) by client_global_hostkeys_prove_confirm().
	 */
	char **algs;
	struct sshkey **keys;
	u_int *keys_match;	/* mask of HKF_MATCH_* from hostfile.h */
	int *keys_verified;	/* flag for new keys verified by server */
	size_t nkeys, nnew, nincomplete; /* total, new keys, incomplete match */

	/*
	 * Keys that are in known_hosts, but were not present in the update
	 * from the server (i.e. scheduled to be deleted).
	 * Filled in by hostkeys_find().
	 */
	struct sshkey **old_keys;
	size_t nold;

	/* Various special cases. */
	int complex_hostspec;	/* wildcard or manual pattern-list host name */
	int ca_available;	/* saw CA key for this host */
	int old_key_seen;	/* saw old key with other name/addr */
	int other_name_seen;	/* saw key with other name/addr */
};

static void
hostkeys_update_ctx_free(struct hostkeys_update_ctx *ctx)
{
	size_t i;

	if (ctx == NULL)
		return;
	for (i = 0; i < ctx->nkeys; i++)
		free(ctx->algs[i]);
	free(ctx->algs);
	for (i = 0; i < ctx->nkeys; i++)
		sshkey_free(ctx->keys[i]);
	free(ctx->keys);
	free(ctx->keys_match);
	free(ctx->keys_verified);
	for (i = 0; i < ctx->nold; i++)
		sshkey_free(ctx->old_keys[i]);
	free(ctx->old_keys);
	free(ctx->host_str);
	free(ctx->ip_str);
	free(ctx);
}

/*
 * Returns non-zero if a known_hosts hostname list is not of a form that
 * can be handled by UpdateHostkeys. These include wildcard hostnames and
 * hostnames lists that do not follow the form host[,ip].
 */
static int
hostspec_is_complex(const char *hosts)
{
	char *cp;

	/* wildcard */
	if (strchr(hosts, '*') != NULL || strchr(hosts, '?') != NULL)
		return 1;
	/* single host/ip = ok */
	if ((cp = strchr(hosts, ',')) == NULL)
		return 0;
	/* more than two entries on the line */
	if (strchr(cp + 1, ',') != NULL)
		return 1;
	/* XXX maybe parse cp+1 and ensure it is an IP? */
	return 0;
}

/* callback to search for ctx->keys in known_hosts */
static int
hostkeys_find(struct hostkey_foreach_line *l, void *_ctx)
{
	struct hostkeys_update_ctx *ctx = (struct hostkeys_update_ctx *)_ctx;
	size_t i;
	struct sshkey **tmp;

	if (l->key == NULL)
		return 0;
	if (l->status != HKF_STATUS_MATCHED) {
		/* Record if one of the keys appears on a non-matching line */
		for (i = 0; i < ctx->nkeys; i++) {
			if (sshkey_equal(l->key, ctx->keys[i])) {
				ctx->other_name_seen = 1;
				debug3_f("found %s key under different "
				    "name/addr at %s:%ld",
				    sshkey_ssh_name(ctx->keys[i]),
				    l->path, l->linenum);
				return 0;
			}
		}
		return 0;
	}
	/* Don't proceed if revocation or CA markers are present */
	/* XXX relax this */
	if (l->marker != MRK_NONE) {
		debug3_f("hostkeys file %s:%ld has CA/revocation marker",
		    l->path, l->linenum);
		ctx->complex_hostspec = 1;
		return 0;
	}

	/* If CheckHostIP is enabled, then check for mismatched hostname/addr */
	if (ctx->ip_str != NULL && strchr(l->hosts, ',') != NULL) {
		if ((l->match & HKF_MATCH_HOST) == 0) {
			/* Record if address matched a different hostname. */
			ctx->other_name_seen = 1;
			debug3_f("found address %s against different hostname "
			    "at %s:%ld", ctx->ip_str, l->path, l->linenum);
			return 0;
		} else if ((l->match & HKF_MATCH_IP) == 0) {
			/* Record if hostname matched a different address. */
			ctx->other_name_seen = 1;
			debug3_f("found hostname %s against different address "
			    "at %s:%ld", ctx->host_str, l->path, l->linenum);
		}
	}

	/*
	 * UpdateHostkeys is skipped for wildcard host names and hostnames
	 * that contain more than two entries (ssh never writes these).
	 */
	if (hostspec_is_complex(l->hosts)) {
		debug3_f("hostkeys file %s:%ld complex host specification",
		    l->path, l->linenum);
		ctx->complex_hostspec = 1;
		return 0;
	}

	/* Mark off keys we've already seen for this host */
	for (i = 0; i < ctx->nkeys; i++) {
		if (!sshkey_equal(l->key, ctx->keys[i]))
			continue;
		debug3_f("found %s key at %s:%ld",
		    sshkey_ssh_name(ctx->keys[i]), l->path, l->linenum);
		ctx->keys_match[i] |= l->match;
		return 0;
	}
	/* This line contained a key that not offered by the server */
	debug3_f("deprecated %s key at %s:%ld", sshkey_ssh_name(l->key),
	    l->path, l->linenum);
	if ((tmp = recallocarray(ctx->old_keys, ctx->nold, ctx->nold + 1,
	    sizeof(*ctx->old_keys))) == NULL)
		fatal_f("recallocarray failed nold = %zu", ctx->nold);
	ctx->old_keys = tmp;
	ctx->old_keys[ctx->nold++] = l->key;
	l->key = NULL;

	return 0;
}

/* callback to search for ctx->old_keys in known_hosts under other names */
static int
hostkeys_check_old(struct hostkey_foreach_line *l, void *_ctx)
{
	struct hostkeys_update_ctx *ctx = (struct hostkeys_update_ctx *)_ctx;
	size_t i;
	int hashed;

	/* only care about lines that *don't* match the active host spec */
	if (l->status == HKF_STATUS_MATCHED || l->key == NULL)
		return 0;

	hashed = l->match & (HKF_MATCH_HOST_HASHED|HKF_MATCH_IP_HASHED);
	for (i = 0; i < ctx->nold; i++) {
		if (!sshkey_equal(l->key, ctx->old_keys[i]))
			continue;
		debug3_f("found deprecated %s key at %s:%ld as %s",
		    sshkey_ssh_name(ctx->old_keys[i]), l->path, l->linenum,
		    hashed ? "[HASHED]" : l->hosts);
		ctx->old_key_seen = 1;
		break;
	}
	return 0;
}

/*
 * Check known_hosts files for deprecated keys under other names. Returns 0
 * on success or -1 on failure. Updates ctx->old_key_seen if deprecated keys
 * exist under names other than the active hostname/IP.
 */
static int
check_old_keys_othernames(struct hostkeys_update_ctx *ctx)
{
	size_t i;
	int r;

	debug2_f("checking for %zu deprecated keys", ctx->nold);
	for (i = 0; i < options.num_user_hostfiles; i++) {
		debug3_f("searching %s for %s / %s",
		    options.user_hostfiles[i], ctx->host_str,
		    ctx->ip_str ? ctx->ip_str : "(none)");
		if ((r = hostkeys_foreach(options.user_hostfiles[i],
		    hostkeys_check_old, ctx, ctx->host_str, ctx->ip_str,
		    HKF_WANT_PARSE_KEY, 0)) != 0) {
			if (r == SSH_ERR_SYSTEM_ERROR && errno == ENOENT) {
				debug_f("hostkeys file %s does not exist",
				    options.user_hostfiles[i]);
				continue;
			}
			error_fr(r, "hostkeys_foreach failed for %s",
			    options.user_hostfiles[i]);
			return -1;
		}
	}
	return 0;
}

static void
hostkey_change_preamble(LogLevel loglevel)
{
	do_log2(loglevel, "The server has updated its host keys.");
	do_log2(loglevel, "These changes were verified by the server's "
	    "existing trusted key.");
}

static void
update_known_hosts(struct hostkeys_update_ctx *ctx)
{
	int r, was_raw = 0, first = 1;
	int asking = options.update_hostkeys == SSH_UPDATE_HOSTKEYS_ASK;
	LogLevel loglevel = asking ?  SYSLOG_LEVEL_INFO : SYSLOG_LEVEL_VERBOSE;
	struct sshkey *key;
	int is_x509;
	char *fp;
	size_t i;
	struct stat sb;

	for (i = 0; i < ctx->nkeys; i++) {
		if (!ctx->keys_verified[i])
			continue;
		key = ctx->keys[i];
		is_x509 = sshkey_is_x509(key);
		if (is_x509) {
			fp = x509key_subject(key);
			if (fp == NULL)
				fatal_f("x509key_subject failed");
			free(fp);
			continue;
		} else {
			fp = sshkey_fingerprint(key,
			    options.fingerprint_hash, SSH_FP_DEFAULT);
			if (fp == NULL)
				fatal_f("sshkey_fingerprint failed");
		}
		if (first && asking)
			hostkey_change_preamble(loglevel);
		if (is_x509)
			do_log2(loglevel, "Learned new hostkey: %s", fp);
		else
			do_log2(loglevel, "Learned new hostkey: %s %s",
			    sshkey_type(key), fp);
		first = 0;
		free(fp);
	}
	for (i = 0; i < ctx->nold; i++) {
		key = ctx->old_keys[i];
		is_x509 = sshkey_is_x509(key);
		if (is_x509) {
			fp = x509key_subject(key);
			if (fp == NULL)
				fatal_f("x509key_subject failed");
		} else {
			fp = sshkey_fingerprint(key,
			    options.fingerprint_hash, SSH_FP_DEFAULT);
			if (fp == NULL)
				fatal_f("sshkey_fingerprint failed");
		}
		if (first && asking)
			hostkey_change_preamble(loglevel);
		if (is_x509)
			do_log2(loglevel, "Deprecating obsolete hostkey: %s", fp);
		else
			do_log2(loglevel, "Deprecating obsolete hostkey: %s %s",
			    sshkey_type(key), fp);
		first = 0;
		free(fp);
	}
	if (options.update_hostkeys == SSH_UPDATE_HOSTKEYS_ASK) {
		if (get_saved_tio() != NULL) {
			leave_raw_mode(1);
			was_raw = 1;
		}
		if (!ask_permission("Accept updated hostkeys?"))
			options.update_hostkeys = 0;
		if (was_raw)
			enter_raw_mode(1);
	}
	if (options.update_hostkeys == 0)
		return;
	/*
	 * Now that all the keys are verified, we can go ahead and replace
	 * them in known_hosts (assuming SSH_UPDATE_HOSTKEYS_ASK didn't
	 * cancel the operation).
	 */
	for (i = 0; i < options.num_user_hostfiles; i++) {
		char *known_hosts_file = options.user_hostfiles[i];
		/*
		 * NB. keys are only added to hostfiles[0], for the rest we
		 * just delete the hostname entries.
		 */
		if (stat(known_hosts_file, &sb) == -1) {
			if (errno == ENOENT) {
				debug_f("known hosts file %s does not "
				    "exist", known_hosts_file);
			} else {
				error_f("known hosts file %s "
				    "inaccessible: %s",
				    known_hosts_file, strerror(errno));
			}
			continue;
		}
		if ((r = hostfile_replace_entries(known_hosts_file,
		    ctx->host_str, ctx->ip_str,
		    i == 0 ? ctx->keys : NULL, i == 0 ? ctx->nkeys : 0,
		    options.hash_known_hosts, options.fingerprint_hash)) != 0) {
			error_fr(r, "hostfile_replace_entries failed for %s",
			    known_hosts_file);
		}
	}
}

static void
client_global_hostkeys_prove_confirm(struct ssh *ssh, int type,
    u_int32_t seq, void *_ctx)
{
	struct hostkeys_update_ctx *ctx = (struct hostkeys_update_ctx *)_ctx;
	size_t i, ndone;
	struct sshbuf *signdata;
	int r;
	const char *rsa_kexalg = NULL;
	char *rsa_keyalg = NULL;
	const u_char *sig;
	size_t siglen;

	UNUSED(seq);
	if (ctx->nnew == 0)
		fatal_f("ctx->nnew == 0"); /* sanity */
	if (type != SSH2_MSG_REQUEST_SUCCESS) {
		error("Server failed to confirm ownership of "
		    "private host keys");
		hostkeys_update_ctx_free(ctx);
		return;
	}

	if (ssh->kex->hostkey_alg != NULL) {
		int hktype = sshkey_type_from_name(ssh->kex->hostkey_alg);
		if (sshkey_type_plain(hktype) == KEY_RSA)
			rsa_kexalg =  ssh->kex->hostkey_alg;
	}

	if ((signdata = sshbuf_new()) == NULL)
		fatal_f("sshbuf_new failed");
	/* Don't want to accidentally accept an unbound signature */
	if (sshbuf_len(ssh->kex->session_id) == 0)
		fatal_f("zero length session_id");
	/*
	 * Expect a signature for each of the ctx->nnew private keys we
	 * haven't seen before. They will be in the same order as the
	 * ctx->keys where the corresponding ctx->keys_match[i] == 0.
	 */
	for (ndone = i = 0; i < ctx->nkeys; i++) {
		struct sshkey *key;
		const char *pkalg;

		if (ctx->keys_match[i])
			continue;

		key = ctx->keys[i];
		pkalg = sshkey_ssh_name(key);
		sshbuf_reset(signdata);
		/* Extract and verify signature */
		if ((r = sshpkt_get_string_direct(ssh, &sig, &siglen)) != 0) {
			error_fr(r, "parse sig");
			goto out;
		}
		/* Prepare data to be signed: session ID, unique string, key */
		if ((sshkey_type_plain(key->type) == KEY_RSA) &&
		    !sshkey_is_x509(key)
		) {
			free(rsa_keyalg);
			r = sshkey_sigtype(sig, siglen, &rsa_keyalg);
			if (r != 0) {
				error_fr(r, "server gave unintelligible signature "
				    "for %s key %zu", pkalg, i);
				goto out;
			}
			pkalg = rsa_keyalg;
			/* warn for untrusted signature only
			 * if host-key is not rsa based
			 */
			if (rsa_kexalg == NULL &&
			    match_pattern_list(rsa_keyalg,
				"rsa-sha2-256,rsa-sha2-512", 0) != 1) {
				debug("server uses untrusted RSA signature"
				    " algorithm %s for hostkey prove %zu",
				    rsa_keyalg, i);
			}
		}
		if ((r = sshbuf_put_cstring(signdata,
			"hostkeys-prove-00@openssh.com")) != 0 ||
		    (r = sshbuf_put_stringb(signdata,
			ssh->kex->session_id)) != 0 ||
		    (r = Xkey_puts(pkalg, key, signdata)) != 0)
			fatal_fr(r, "compose signdata");
	{	ssh_verify_ctx verify_ctx = { pkalg, key, &ssh->compat };

		r = Xkey_verify(&verify_ctx, sig, siglen, sshbuf_ptr(signdata), sshbuf_len(signdata));
		if (r != 0) {
			error_f("server gave bad signature for %s key %zu", pkalg, i);
			goto out;
		}
	}
		/* Key is good. Mark it as 'seen' */
		ctx->keys_verified[i] = 1;
		ndone++;
	}
	/* Shouldn't happen */
	if (ndone != ctx->nnew)
		fatal_f("ndone != ctx->nnew (%zu / %zu)", ndone, ctx->nnew);
	if ((r = sshpkt_get_end(ssh)) != 0) {
		error_f("protocol error");
		goto out;
	}

	/* Make the edits to known_hosts */
	update_known_hosts(ctx);
 out:
 	sshbuf_free(signdata);
	free(rsa_keyalg);
	hostkeys_update_ctx_free(ctx);
	hostkeys_update_complete = 1;
	client_repledge();
}

/*
 * Handle hostkeys-00@openssh.com global request to inform the client of all
 * the server's hostkeys. The keys are checked against the user's
 * HostkeyAlgorithms preference before they are accepted.
 */
static int
client_input_hostkeys(struct ssh *ssh)
{
	const u_char *blob = NULL;
	size_t i, len = 0;
	struct sshbuf *buf = NULL;
	struct sshkey *key = NULL, **tmp;
	char *pkalg = NULL, **algtmp;
	int r, prove_sent = 0;
	char *fp;
	static int hostkeys_seen = 0; /* XXX use struct ssh */
	extern struct sockaddr_storage hostaddr; /* XXX from ssh.c */
	struct hostkeys_update_ctx *ctx = NULL;
	u_int want;

	if (hostkeys_seen)
		fatal_f("server already sent hostkeys");
	hostkeys_seen = 1;
	if (!can_update_hostkeys())
		return 1;

	ctx = xcalloc(1, sizeof(*ctx));
	while (ssh_packet_remaining(ssh) > 0) {
		sshkey_free(key);
		key = NULL;
		free(pkalg);
		pkalg = NULL;
		if ((r = sshpkt_get_string_direct(ssh, &blob, &len)) != 0) {
			error_fr(r, "parse key");
			goto out;
		}
		if ((r = parse_key_from_blob(blob, len, &key, &pkalg)) != 0) {
			do_log2_fr(r, r == SSH_ERR_KEY_TYPE_UNKNOWN ?
			    SYSLOG_LEVEL_DEBUG1 : SYSLOG_LEVEL_ERROR,
			    "parse key");
			continue;
		}
		fp = sshkey_fingerprint(key, options.fingerprint_hash,
		    SSH_FP_DEFAULT);
		debug3_f("received key %s %s", pkalg, fp);
		free(fp);

		/* Check that the key is accepted in HostkeyAlgorithms */
		/* NOTE: Before key exchange option HostKeyAlgorithms
		   is either assembled (if not set by configuration)
		   or set to default. See ssh_kex2() in sshconnect2.c */
		if (match_pattern_list(pkalg, options.hostkeyalgorithms, 0) != 1) {
			debug3_f("%s key not permitted by HostkeyAlgorithms",
			    pkalg);
			continue;
		}
		/* Skip certs */
		if (sshkey_is_cert(key)) {
			debug3_f("%s key is a certificate; skipping",
			    pkalg);
			continue;
		}
	{	/* Exclude equal keys */
		int found = 0;
		for (i = 0; i < ctx->nkeys; i++) {
			if (sshkey_equal(key, ctx->keys[i])) {
				debug3_f("host key is equal but algorithm is %s ",
				    pkalg);
				found = 1;
				break;
			}
		}
		if (found) continue;
	}
		/* Key is good, record it */
		tmp = recallocarray(ctx->keys, ctx->nkeys, ctx->nkeys + 1, sizeof(*ctx->keys));
		if (tmp == NULL)
			fatal_f("recallocarray failed nkeys = %zu", ctx->nkeys);
		algtmp = reallocarray(ctx->algs, ctx->nkeys + 1, sizeof(*ctx->algs));
		if (algtmp == NULL)
			fatal_f("reallocarray failed nalgs = %zu", ctx->nkeys);
		ctx->algs = algtmp;
		ctx->algs[ctx->nkeys] = pkalg;
		pkalg = NULL;
		ctx->keys = tmp;
		ctx->keys[ctx->nkeys++] = key;
		key = NULL;
	}

	if (ctx->nkeys == 0) {
		debug_f("server sent no hostkeys");
		goto out;
	}

	if ((ctx->keys_match = calloc(ctx->nkeys,
	    sizeof(*ctx->keys_match))) == NULL ||
	    (ctx->keys_verified = calloc(ctx->nkeys,
	    sizeof(*ctx->keys_verified))) == NULL)
		fatal_f("calloc failed");

	get_hostfile_hostname_ipaddr(host,
	    options.check_host_ip ? (struct sockaddr *)&hostaddr : NULL,
	    options.port, &ctx->host_str,
	    options.check_host_ip ? &ctx->ip_str : NULL);

	/* Find which keys we already know about. */
	for (i = 0; i < options.num_user_hostfiles; i++) {
		debug_f("searching %s for %s / %s",
		    options.user_hostfiles[i], ctx->host_str,
		    ctx->ip_str ? ctx->ip_str : "(none)");
		if ((r = hostkeys_foreach(options.user_hostfiles[i],
		    hostkeys_find, ctx, ctx->host_str, ctx->ip_str,
		    HKF_WANT_PARSE_KEY, 0)) != 0) {
			if (r == SSH_ERR_SYSTEM_ERROR && errno == ENOENT) {
				debug_f("hostkeys file %s does not exist",
				    options.user_hostfiles[i]);
				continue;
			}
			error_fr(r, "hostkeys_foreach failed for %s",
			    options.user_hostfiles[i]);
			goto out;
		}
	}

	/* Figure out if we have any new keys to add */
	ctx->nnew = ctx->nincomplete = 0;
	want = HKF_MATCH_HOST | ( options.check_host_ip ? HKF_MATCH_IP : 0);
	for (i = 0; i < ctx->nkeys; i++) {
		if (ctx->keys_match[i] == 0)
			ctx->nnew++;
		if ((ctx->keys_match[i] & want) != want)
			ctx->nincomplete++;
	}

	debug3_f("%zu server keys: %zu new, %zu retained, "
	    "%zu incomplete match. %zu to remove", ctx->nkeys, ctx->nnew,
	    ctx->nkeys - ctx->nnew - ctx->nincomplete,
	    ctx->nincomplete, ctx->nold);

	if (ctx->nnew == 0 && ctx->nold == 0) {
		debug_f("no new or deprecated keys from server");
		goto out;
	}

	/* Various reasons why we cannot proceed with the update */
	if (ctx->complex_hostspec) {
		debug_f("CA/revocation marker, manual host list or wildcard "
		    "host pattern found, skipping UserKnownHostsFile update");
		goto out;
	}
	if (ctx->other_name_seen) {
		debug_f("host key found matching a different name/address, "
		    "skipping UserKnownHostsFile update");
		goto out;
	}
	/*
	 * If removing keys, check whether they appear under different
	 * names/addresses and refuse to proceed if they do. This avoids
	 * cases such as hosts with multiple names becoming inconsistent
	 * with regards to CheckHostIP entries.
	 * XXX UpdateHostkeys=force to override this (and other) checks?
	 */
	if (ctx->nold != 0) {
		if (check_old_keys_othernames(ctx) != 0)
			goto out; /* error already logged */
		if (ctx->old_key_seen) {
			debug_f("key(s) for %s%s%s exist under other names; "
			    "skipping UserKnownHostsFile update",
			    ctx->host_str, ctx->ip_str == NULL ? "" : ",",
			    ctx->ip_str == NULL ? "" : ctx->ip_str);
			goto out;
		}
	}

	if (ctx->nnew == 0) {
		/*
		 * We have some keys to remove or fix matching for.
		 * We can proceed to do this without requiring a fresh proof
		 * from the server.
		 */
		update_known_hosts(ctx);
		goto out;
	}
	/*
	 * We have received previously-unseen keys from the server.
	 * Ask the server to confirm ownership of the private halves.
	 */
	debug3_f("asking server to prove ownership for %zu keys", ctx->nnew);
	if ((r = sshpkt_start(ssh, SSH2_MSG_GLOBAL_REQUEST)) != 0 ||
	    (r = sshpkt_put_cstring(ssh,
	    "hostkeys-prove-00@openssh.com")) != 0 ||
	    (r = sshpkt_put_u8(ssh, 1)) != 0) /* bool: want reply */
		fatal_fr(r, "prepare hostkeys-prove");
	if ((buf = sshbuf_new()) == NULL)
		fatal_f("sshbuf_new");
	for (i = 0; i < ctx->nkeys; i++) {
		if (ctx->keys_match[i])
			continue;
		sshbuf_reset(buf);
		if ((r = Xkey_putb(ctx->algs[i], ctx->keys[i], buf)) != 0 ||
		    (r = sshpkt_put_stringb(ssh, buf)) != 0)
			fatal_fr(r, "assemble hostkeys-prove");
	}
	if ((r = sshpkt_send(ssh)) != 0)
		fatal_fr(r, "send hostkeys-prove");
	client_register_global_confirm(
	    client_global_hostkeys_prove_confirm, ctx);
	ctx = NULL;  /* will be freed in callback */
	prove_sent = 1;

	/* Success */
 out:
	hostkeys_update_ctx_free(ctx);
	free(pkalg);
	sshkey_free(key);
	sshbuf_free(buf);
	if (!prove_sent) {
		/* UpdateHostkeys handling completed */
		hostkeys_update_complete = 1;
		client_repledge();
	}
	/*
	 * NB. Return success for all cases. The server doesn't need to know
	 * what the client does with its hosts file.
	 */
	return 1;
}

static int
client_input_global_request(int type, u_int32_t seq, struct ssh *ssh)
{
	char *rtype;
	u_char want_reply;
	int r, success = 0;

	UNUSED(type);
	UNUSED(seq);
	if ((r = sshpkt_get_cstring(ssh, &rtype, NULL)) != 0 ||
	    (r = sshpkt_get_u8(ssh, &want_reply)) != 0)
		goto out;
	debug_f("rtype %s want_reply %d", rtype, (int)want_reply);
	if (strcmp(rtype, "hostkeys-00@openssh.com") == 0)
		success = client_input_hostkeys(ssh);
	if (want_reply) {
		if ((r = sshpkt_start(ssh, success ? SSH2_MSG_REQUEST_SUCCESS :
		    SSH2_MSG_REQUEST_FAILURE)) != 0 ||
		    (r = sshpkt_send(ssh)) != 0 ||
		    (r = ssh_packet_write_wait(ssh)) != 0)
			goto out;
	}

 out:
	free(rtype);
	return r;
}

static void
client_send_env(struct ssh *ssh, int id, const char *name, const char *val)
{
	int r;

	debug("channel %d: setting env %s = \"%s\"", id, name, val);
	channel_request_start(ssh, id, "env", 0);
	if ((r = sshpkt_put_cstring(ssh, name)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, val)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		fatal_fr(r, "send setenv");
}

void
client_session2_setup(struct ssh *ssh, int id, int want_tty, int want_subsystem,
    const char *term, struct termios *tiop, int in_fd, struct sshbuf *cmd,
    char **env)
{
	u_int i, j;
	int matched, r;
	char *name, *val;
	Channel *c = NULL;

	debug2_f("id %d", id);

	if ((c = channel_lookup(ssh, id)) == NULL)
		fatal_f("channel %d: unknown channel", id);

	ssh_packet_set_interactive(ssh, want_tty,
	    options.ip_qos_interactive, options.ip_qos_bulk);

	if (want_tty) {
		struct winsize ws;

		/* Store window size in the packet. */
		if (ioctl(in_fd, TIOCGWINSZ, &ws) == -1)
			memset(&ws, 0, sizeof(ws));

		channel_request_start(ssh, id, "pty-req", 1);
		client_expect_confirm(ssh, id, "PTY allocation", CONFIRM_TTY);
		if ((r = sshpkt_put_cstring(ssh, term != NULL ? term : ""))
		    != 0 ||
		    (r = sshpkt_put_u32(ssh, ws.ws_col)) != 0 ||
		    (r = sshpkt_put_u32(ssh, ws.ws_row)) != 0 ||
		    (r = sshpkt_put_u32(ssh, ws.ws_xpixel)) != 0 ||
		    (r = sshpkt_put_u32(ssh, ws.ws_ypixel)) != 0)
			fatal_fr(r, "build pty-req");
		if (tiop == NULL)
			tiop = get_saved_tio();
		ssh_tty_make_modes(ssh, -1, tiop);
		if ((r = sshpkt_send(ssh)) != 0)
			fatal_fr(r, "send pty-req");
		/* XXX wait for reply */
		c->client_tty = 1;
	}

	/* Transfer any environment variables from client to server */
	if (options.num_send_env != 0 && env != NULL) {
		debug("Sending environment.");
		for (i = 0; env[i] != NULL; i++) {
			/* Split */
			name = xstrdup(env[i]);
			if ((val = strchr(name, '=')) == NULL) {
				free(name);
				continue;
			}
			*val++ = '\0';

			matched = 0;
			for (j = 0; j < options.num_send_env; j++) {
				matched = match_pattern_list(name, options.send_env[j], 0);
				if (matched != 0) break;
			}
			if (matched != 1) {
				debug3("%s env %s",
				    (matched == -1 ? "Ignored" : "Skipped"),
				    name);
				free(name);
				continue;
			}
			client_send_env(ssh, id, name, val);
			free(name);
		}
	}
	for (i = 0; i < options.num_setenv; i++) {
		/* Split */
		name = xstrdup(options.setenv[i]);
		if ((val = strchr(name, '=')) == NULL) {
			free(name);
			continue;
		}
		*val++ = '\0';
		client_send_env(ssh, id, name, val);
		free(name);
	}

{	size_t len = sshbuf_len(cmd);
	if (len > 0) {
		if (len > 900)
			len = 900;
		if (want_subsystem) {
			debug("Sending subsystem: %.*s",
			    (int)len, sshbuf_ptr(cmd));
			channel_request_start(ssh, id, "subsystem", 1);
			client_expect_confirm(ssh, id, "subsystem",
			    CONFIRM_CLOSE);
		} else {
			debug("Sending command: %.*s",
			    (int)len, sshbuf_ptr(cmd));
			channel_request_start(ssh, id, "exec", 1);
			client_expect_confirm(ssh, id, "exec", CONFIRM_CLOSE);
		}
		if ((r = sshpkt_put_stringb(ssh, cmd)) != 0 ||
		    (r = sshpkt_send(ssh)) != 0)
			fatal_fr(r, "send command");
	} else {
		channel_request_start(ssh, id, "shell", 1);
		client_expect_confirm(ssh, id, "shell", CONFIRM_CLOSE);
		if ((r = sshpkt_send(ssh)) != 0)
			fatal_fr(r, "send shell");
	}

	session_setup_complete = 1;
	client_repledge();
}
}

static void
client_init_dispatch(struct ssh *ssh)
{
	ssh_dispatch_init(ssh, &dispatch_protocol_error);

	ssh_dispatch_set(ssh, SSH2_MSG_CHANNEL_CLOSE, &channel_input_oclose);
	ssh_dispatch_set(ssh, SSH2_MSG_CHANNEL_DATA, &channel_input_data);
	ssh_dispatch_set(ssh, SSH2_MSG_CHANNEL_EOF, &channel_input_ieof);
	ssh_dispatch_set(ssh, SSH2_MSG_CHANNEL_EXTENDED_DATA, &channel_input_extended_data);
	ssh_dispatch_set(ssh, SSH2_MSG_CHANNEL_OPEN, &client_input_channel_open);
	ssh_dispatch_set(ssh, SSH2_MSG_CHANNEL_OPEN_CONFIRMATION, &channel_input_open_confirmation);
	ssh_dispatch_set(ssh, SSH2_MSG_CHANNEL_OPEN_FAILURE, &channel_input_open_failure);
	ssh_dispatch_set(ssh, SSH2_MSG_CHANNEL_REQUEST, &client_input_channel_req);
	ssh_dispatch_set(ssh, SSH2_MSG_CHANNEL_WINDOW_ADJUST, &channel_input_window_adjust);
	ssh_dispatch_set(ssh, SSH2_MSG_CHANNEL_SUCCESS, &channel_input_status_confirm);
	ssh_dispatch_set(ssh, SSH2_MSG_CHANNEL_FAILURE, &channel_input_status_confirm);
	ssh_dispatch_set(ssh, SSH2_MSG_GLOBAL_REQUEST, &client_input_global_request);

	/* rekeying */
	ssh_dispatch_set(ssh, SSH2_MSG_KEXINIT, &kex_input_kexinit);

	/* global request reply messages */
	ssh_dispatch_set(ssh, SSH2_MSG_REQUEST_FAILURE, &client_global_request_reply);
	ssh_dispatch_set(ssh, SSH2_MSG_REQUEST_SUCCESS, &client_global_request_reply);
}

void
client_stop_mux(void)
{
	if (options.control_path != NULL && muxserver_sock != -1)
		unlink(options.control_path);
	/*
	 * If we are in persist mode, or don't have a shell, signal that we
	 * should close when all active channels are closed.
	 */
	if (options.control_persist || options.session_type == SESSION_TYPE_NONE) {
		session_closed = 1;
		setproctitle("[stopped mux]");
	}
}

/* client specific fatal cleanup */
void
cleanup_exit(int i)
{
	leave_raw_mode(options.request_tty == REQUEST_TTY_FORCE);
	if (options.control_path != NULL && muxserver_sock != -1)
		unlink(options.control_path);
	ssh_kill_proxy_command();
	_exit(i);
}
