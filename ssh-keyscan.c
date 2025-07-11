/* $OpenBSD: ssh-keyscan.c,v 1.165 2024/12/06 15:17:15 djm Exp $ */
/*
 * Copyright 1995, 1996 by David Mazieres <dm@lcs.mit.edu>.
 *
 * Modification and redistribution in source and binary forms is
 * permitted provided that due credit is given to the author and the
 * OpenBSD project by leaving this copyright notice intact.
 *
 * Copyright (c) 2002-2022 Roumen Petrov.  All rights reserved.
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
#include "openbsd-compat/sys-queue.h"
#include <sys/resource.h>
#ifdef HAVE_SYS_TIME_H
# include <sys/time.h>
#endif

#include <netinet/in.h>
#include <arpa/inet.h>

#ifdef WITH_OPENSSL
#include <openssl/bn.h>
#include "evp-compat.h"
#endif

#include <limits.h>
#include <netdb.h>
#include <errno.h>
#ifdef HAVE_POLL_H
# include <poll.h>
#else
# ifdef HAVE_SYS_POLL_H
#  include <sys/poll.h>
# endif
#endif
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <string.h>
#include <unistd.h>

#include "xmalloc.h"
#include "ssh.h"
#include "sshbuf.h"
#include "ssh-x509.h"
#include "match.h"
#include "version.h"
#include "cipher.h"
#include "digest.h"
#include "kex.h"
#include "myproposal.h"
#include "packet.h"
#include "dispatch.h"
#include "log.h"
#include "atomicio.h"
#include "misc.h"
#include "hostfile.h"
#include "ssherr.h"
#include "ssh_api.h"
#include "dns.h"
#include "addr.h"

static char *def_kex = NULL;
static char *def_cipher = NULL;
static char *def_mac = NULL;

/* Flag indicating whether IPv4 or IPv6.  This can be set on the command line.
   Default value is AF_UNSPEC means both IPv4 and IPv6. */
int IPv4or6 = AF_UNSPEC;

int ssh_port = SSH_DEFAULT_PORT;

char *keynames_filter = NULL;

int hash_hosts = 0;		/* Hash hostname on output */

static int print_dns_rr = 0;	/* Print DNS RR records(CERT or SSHFP) instead of known_hosts */
static int print_generic = 0;	/* Use generic format for DNS RR records */

int found_one = 0;		/* Successfully found a key */

static int hashalg = -1;	/* Hash for SSHFP records or -1 for all */

static int quiet = 0;		/* Don't print key comment lines */

#define MAXMAXFD 256

/* The number of seconds after which to give up on a TCP connection */
int timeout = 5;

int maxfd;
#define MAXCON (maxfd - 10)

extern char *__progname;
struct pollfd *read_wait;
int ncon;

/*
 * Keep a connection structure for each file descriptor.  The state
 * associated with file descriptor n is held in fdcon[n].
 */
typedef struct Connection {
	u_char c_status;	/* State of connection on this file desc. */
#define CS_UNUSED 0		/* File descriptor unused */
#define CS_CON 1		/* Waiting to connect/read greeting */
	int c_fd;		/* Quick lookup: c->c_fd == c - fdcon */
	const char *c_keyname;
	sig_atomic_t c_done;	/* SSH2 done */
	char *c_namebase;	/* Address to free for c_name and c_namelist */
	char *c_name;		/* Hostname of connection for errors */
	char *c_namelist;	/* Pointer to other possible addresses */
	char *c_output_name;	/* Hostname of connection for output */
	struct ssh *c_ssh;	/* SSH-connection */
	struct timespec c_ts;	/* Time at which connection gets aborted */
	TAILQ_ENTRY(Connection) c_link;	/* List of connections in timeout order. */
} con;

TAILQ_HEAD(conlist, Connection) tq;	/* Timeout Queue */
con *fdcon;

static void keyprint(con *c, struct sshkey *key);

static int
fdlim_get(int hard)
{
#if defined(HAVE_GETRLIMIT) && defined(RLIMIT_NOFILE)
	struct rlimit rlfd;
	rlim_t lim;

	if (getrlimit(RLIMIT_NOFILE, &rlfd) == -1)
		return -1;
	lim = hard ? rlfd.rlim_max : rlfd.rlim_cur;
	if (lim == RLIM_INFINITY)
		lim = SSH_SYSFDMAX;
#else
	long lim = SSH_SYSFDMAX;
	UNUSED(hard);
#endif
	if (lim <= 0) return -1;
	return MINIMUM(lim, INT_MAX);
}

static int
fdlim_set(int lim)
{
	if (lim <= 0)
		return (-1);
#if defined(HAVE_SETRLIMIT) && defined(RLIMIT_NOFILE) && defined(HAVE_GETRLIMIT)
{	struct rlimit rlfd;

	if (getrlimit(RLIMIT_NOFILE, &rlfd) == -1)
		return (-1);
	rlfd.rlim_cur = lim;
	if (setrlimit(RLIMIT_NOFILE, &rlfd) == -1)
		return (-1);
}
#elif defined (HAVE_SETDTABLESIZE)
	setdtablesize(lim);
#endif
	return (0);
}

/*
 * This is an strsep function that returns a null field for adjacent
 * separators.  This is the same as the 4.4BSD strsep, but different from the
 * one in the GNU libc.
 */
static char *
xstrsep(char **str, const char *delim)
{
	char *s, *e;

	if (!**str)
		return (NULL);

	s = *str;
	e = s + strcspn(s, delim);

	if (*e != '\0')
		*e++ = '\0';
	*str = e;

	return (s);
}

/*
 * Get the next non-null token (like GNU strsep).  Strsep() will return a
 * null token for two adjacent separators, so we may have to loop.
 */
static char *
strnnsep(char **stringp, const char *delim)
{
	char *tok;

	do {
		tok = xstrsep(stringp, delim);
	} while (tok && *tok == '\0');
	return (tok);
}


static int
key_print_wrapper(struct sshkey *hostkey, struct ssh *ssh)
{
	con *c;

	if ((c = ssh_get_app_data(ssh)) != NULL)
		keyprint(c, hostkey);
	/* always abort key exchange */
	return -1;
}

static int
ssh2_capable(int remote_major, int remote_minor)
{
	switch (remote_major) {
	case 1:
		if (remote_minor == 99)
			return 1;
		break;
	case 2:
		return 1;
	default:
		break;
	}
	return 0;
}

static void
keygrab_ssh2(con *c)
{
	char *myproposal[PROPOSAL_MAX] = { KEX_CLIENT };
	int r;

	myproposal[PROPOSAL_KEX_ALGS] = def_kex;
	myproposal[PROPOSAL_ENC_ALGS_CTOS] =
	myproposal[PROPOSAL_ENC_ALGS_STOC] = def_cipher;
	myproposal[PROPOSAL_MAC_ALGS_CTOS] =
	myproposal[PROPOSAL_MAC_ALGS_STOC] = def_mac;

	myproposal[PROPOSAL_SERVER_HOST_KEY_ALGS] = (char*)c->c_keyname;
	if ((r = kex_setup(c->c_ssh, myproposal)) != 0) {
		free(c->c_ssh);
		fprintf(stderr, "kex_setup: %s\n", ssh_err(r));
		exit(1);
	}
	ssh_set_verify_host_key_callback(c->c_ssh, key_print_wrapper);
	/*
	 * do the key-exchange until an error occurs or until
	 * the key_print_wrapper() callback sets c_done.
	 */
	ssh_dispatch_run(c->c_ssh, DISPATCH_BLOCK, &c->c_done);
}

static void
keyprint_one(const char *host, con *c, struct sshkey *key)
{
	char *hostport, *hashed = NULL;
	const char *known_host;

	++found_one;

	if (print_dns_rr) {
		export_dns_rr(host, key, stdout, print_generic, hashalg);
		return;
	}

	hostport = put_host_port(host, ssh_port);
	lowercase(hostport);
	if (hash_hosts && (hashed = host_hash(hostport, NULL, 0)) == NULL)
		fatal("host_hash failed");
	known_host = hash_hosts ? hashed : hostport;

	if (fprintf(stdout, "%s ", known_host) < 0)
		goto out;
	/* sshkey_write prints X.509 certificate in blob format :-( */
	if (sshkey_is_x509(key)) {
		if (!Xkey_write_subject(c->c_keyname, key, stdout))
			goto out;
	} else {
		if (sshkey_write(key, stdout) != 0)
			goto out;
	}
	(void)fputs("\n", stdout);

out:
	free(hashed);
	free(hostport);
}

static void
keyprint(con *c, struct sshkey *key)
{
	char *hosts = c->c_output_name ? c->c_output_name : c->c_name;
	char *host, *ohosts;

	if (key == NULL)
		return;
	if (!hash_hosts && ssh_port == SSH_DEFAULT_PORT) {
		keyprint_one(hosts, c, key);
		return;
	}
	ohosts = hosts = xstrdup(hosts);
	while ((host = strsep(&hosts, ",")) != NULL)
		keyprint_one(host, c, key);
	free(ohosts);
}

static int
tcpconnect(char *host)
{
	struct addrinfo hints, *ai, *aitop;
	char strport[NI_MAXSERV];
	int gaierr, s = -1;

	snprintf(strport, sizeof strport, "%d", ssh_port);
	memset(&hints, 0, sizeof(hints));
	hints.ai_family = IPv4or6;
	hints.ai_socktype = SOCK_STREAM;
	if ((gaierr = getaddrinfo(host, strport, &hints, &aitop)) != 0) {
		error("getaddrinfo %s: %s", host, ssh_gai_strerror(gaierr));
		return -1;
	}
	for (ai = aitop; ai; ai = ai->ai_next) {
		s = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
		if (s == -1) {
			error("socket: %s", strerror(errno));
			continue;
		}
		if (set_nonblock(s) == -1)
			fatal_f("set_nonblock(%d)", s);
		if (connect(s, ai->ai_addr, ai->ai_addrlen) == -1 &&
		    errno != EINPROGRESS)
			error("connect (`%s'): %s", host, strerror(errno));
		else
			break;
		close(s);
		s = -1;
	}
	freeaddrinfo(aitop);
	return s;
}

static int
conalloc(const char *iname, const char *oname, const char *keyname)
{
	char *namebase, *name, *namelist;
	int s;

	namebase = namelist = xstrdup(iname);

	do {
		name = xstrsep(&namelist, ",");
		if (!name) {
			free(namebase);
			return (-1);
		}
	} while ((s = tcpconnect(name)) == -1);

	if (s >= maxfd)
		fatal_f("fdno %d too high", s);
	if (fdcon[s].c_status)
		fatal_f("attempt to reuse fdno %d", s);

	debug3_f("oname %s keyname %s", oname, keyname);
	fdcon[s].c_fd = s;
	fdcon[s].c_status = CS_CON;
	fdcon[s].c_namebase = namebase;
	fdcon[s].c_name = name;
	fdcon[s].c_namelist = namelist;
	fdcon[s].c_output_name = xstrdup(oname);
	fdcon[s].c_keyname = keyname;
	monotime_ts(&fdcon[s].c_ts);
	fdcon[s].c_ts.tv_sec += timeout;
	TAILQ_INSERT_TAIL(&tq, &fdcon[s], c_link);
	read_wait[s].fd = s;
	read_wait[s].events = POLLIN;
	ncon++;
	return (s);
}

static void
confree(int s)
{
	if (s >= maxfd || fdcon[s].c_status == CS_UNUSED)
		fatal_f("attempt to free bad fdno %d", s);
	free(fdcon[s].c_namebase);
	free(fdcon[s].c_output_name);
	fdcon[s].c_status = CS_UNUSED;
	fdcon[s].c_keyname = NULL;
	if (fdcon[s].c_ssh) {
		ssh_packet_close(fdcon[s].c_ssh);
		free(fdcon[s].c_ssh);
		fdcon[s].c_ssh = NULL;
	} else
		close(s);
	TAILQ_REMOVE(&tq, &fdcon[s], c_link);
	read_wait[s].fd = -1;
	read_wait[s].events = 0;
	ncon--;
}

static int
conrecycle(int s)
{
	con *c = &fdcon[s];
	int ret;

	ret = conalloc(c->c_namelist, c->c_output_name, c->c_keyname);
	confree(s);
	return (ret);
}

static void
congreet(int s)
{
	int n = 0, remote_major = 0, remote_minor = 0;
	char buf[256], *cp;
	char remote_version[sizeof buf];
	size_t bufsiz;
	con *c = &fdcon[s];

	/* send client banner */
	n = snprintf(buf, sizeof buf, "SSH-%d.%d-%s %s\r\n",
	    PROTOCOL_MAJOR_2, PROTOCOL_MINOR_2, SSH_VERSION, "PKIX["PACKAGE_VERSION"] keyscan");
	if (n < 0 || (size_t)n >= sizeof(buf)) {
		error("snprintf: buffer too small");
		confree(s);
		return;
	}
	if (atomicio(vwrite, s, buf, n) != (size_t)n) {
		error("write (%s): %s", c->c_name, strerror(errno));
		confree(s);
		return;
	}

	/*
	 * Read the server banner as per RFC4253 section 4.2.  The "SSH-"
	 * protocol identification string may be preceded by an arbitrarily
	 * large banner which we must read and ignore.  Loop while reading
	 * newline-terminated lines until we have one starting with "SSH-".
	 * The ID string cannot be longer than 255 characters although the
	 * preceding banner lines may (in which case they'll be discarded
	 * in multiple iterations of the outer loop).
	 */
	for (;;) {
		memset(buf, '\0', sizeof(buf));
		bufsiz = sizeof(buf);
		cp = buf;
		while (bufsiz-- &&
		    (n = atomicio(read, s, cp, 1)) == 1 && *cp != '\n') {
			if (*cp == '\r')
				*cp = '\n';
			cp++;
		}
		if (n != 1 || strncmp(buf, "SSH-", 4) == 0)
			break;
	}
	if (n == 0) {
		switch (errno) {
		case EPIPE:
			error("%s: Connection closed by remote host", c->c_name);
			break;
		case ECONNREFUSED:
			break;
		default:
			error("read (%s): %s", c->c_name, strerror(errno));
			break;
		}
		conrecycle(s);
		return;
	}
	if (cp >= buf + sizeof(buf)) {
		error("%s: greeting exceeds allowable length", c->c_name);
		confree(s);
		return;
	}
	if (*cp != '\n' && *cp != '\r') {
		error("%s: bad greeting", c->c_name);
		confree(s);
		return;
	}
	*cp = '\0';
	if ((c->c_ssh = ssh_packet_set_connection(NULL, s, s)) == NULL)
		fatal("ssh_packet_set_connection failed");
	ssh_packet_set_timeout(c->c_ssh, timeout, 1);
	ssh_set_app_data(c->c_ssh, c);	/* back link */
	if (sscanf(buf, "SSH-%d.%d-%[^\n]\n",
	    &remote_major, &remote_minor, remote_version) == 3)
		ssh_set_compatibility(c->c_ssh, remote_version);
	else
		ssh_set_compatibility(c->c_ssh, NULL);
	if (!ssh2_capable(remote_major, remote_minor)) {
		debug("%s doesn't support ssh2", c->c_name);
		confree(s);
		return;
	}
	if (!quiet)
		fprintf(stderr, "%c %s:%d (%s) %s\n", print_dns_rr ? ';' : '#',
		    c->c_name, ssh_port, fdcon[s].c_keyname, chop(buf));
	keygrab_ssh2(c);
	confree(s);
}

static void
conread(int s)
{
	con *c = &fdcon[s];

	if (c->c_status != CS_CON)
		fatal("conread: invalid status %d", c->c_status);

	congreet(s);
}

static void
conloop(void)
{
	struct timespec seltime, now;
	con *c;
	int i;

	monotime_ts(&now);
	c = TAILQ_FIRST(&tq);

	if (c && timespeccmp(&c->c_ts, &now, >))
		timespecsub(&c->c_ts, &now, &seltime);
	else
		timespecclear(&seltime);

	while (ppoll(read_wait, maxfd, &seltime, NULL) == -1) {
		if (errno == EAGAIN || errno == EINTR || errno == EWOULDBLOCK)
			continue;
		error("ppoll: %s", strerror(errno));
		break;
	}

	for (i = 0; i < maxfd; i++) {
		if (read_wait[i].revents & (POLLHUP|POLLERR|POLLNVAL))
			confree(i);
		else if (read_wait[i].revents & POLLIN)
			conread(i);
	}

	c = TAILQ_FIRST(&tq);
	while (c && timespeccmp(&c->c_ts, &now, <)) {
		int s = c->c_fd;

		c = TAILQ_NEXT(c, c_link);
		conrecycle(s);
	}
}

static void
do_one_host(char *host)
{
	char *name = strnnsep(&host, " \t\n");
	const char *keyname;
	const char *filter = keynames_filter != NULL ? keynames_filter : "*";
	char *alglist;

	if (name == NULL)
		return;

	/* Do not free as some list element are used later on connection as keyname!
	 * NOTE: sshkey_alg_list() initialize internally list with default X.509
	 * algorithms, i.e call fill_default_xkalg().
	 */
	alglist = sshkey_alg_list(0, 1, 1, ',');

	for (
	    keyname = strtok(alglist, ",");
	    keyname != NULL;
	    keyname = strtok(NULL, ",")
	) {
		while (ncon >= MAXCON)
			conloop();
		if (match_pattern_list(keyname, filter, 0) != 1 ) {
			debug_f("%s host key not permitted by filter", keyname);
			continue;
		}
		conalloc(name, *host ? host : name, keyname);
	}
}

static void
do_host(char *host)
{
	char daddr[128];
	struct xaddr addr, end_addr;
	u_int masklen;

	if (host == NULL)
		return;
	if (addr_pton_cidr(host, &addr, &masklen) != 0) {
		/* Assume argument is a hostname */
		do_one_host(host);
	} else {
		/* Argument is a CIDR range */
		debug("CIDR range %s", host);
		end_addr = addr;
		if (addr_host_to_all1s(&end_addr, masklen) != 0)
			goto badaddr;
		/*
		 * Note: we deliberately include the all-zero/ones addresses.
		 */
		for (;;) {
			if (addr_ntop(&addr, daddr, sizeof(daddr)) != 0) {
 badaddr:
				error("Invalid address %s", host);
				return;
			}
			debug("CIDR expand: address %s", daddr);
			do_one_host(daddr);
			if (addr_cmp(&addr, &end_addr) == 0)
				break;
			addr_increment(&addr);
		}
	}
}

static void
usage(void)
{
	fprintf(stderr,
	    "usage: %s [-46cDdHqv] [-f file] [-O option] [-p port] [-T timeout]\n"
	    "\t\t   [-t type] [host | addrlist namelist]\n",
	    __progname);
	exit(1);
}

int
main(int argc, char **argv)
{
	int debug_flag = 0, log_level = SYSLOG_LEVEL_INFO;
	int opt, fopt_count = 0, j;
	char *cp, *line = NULL;
	size_t linesize = 0;
	FILE *fp;

	extern int optind;
	extern char *optarg;

	ssh_malloc_init();	/* must be called before any mallocs */
	__progname = ssh_get_progname(argv[0]);
	seed_rng();
	TAILQ_INIT(&tq);

	/* Ensure that fds 0, 1 and 2 are open or directed to /dev/null */
	sanitise_stdfd();

	if (argc <= 1)
		usage();

	while ((opt = getopt(argc, argv, "DdHqv46O:p:T:t:f:")) != -1) {
		switch (opt) {
		case 'H':
			hash_hosts = 1;
			break;
		case 'D':
			print_dns_rr = 1;
			print_generic = 0;
			break;
		case 'd':
			print_dns_rr = 1;
			print_generic = 1;
			break;
		case 'p':
			ssh_port = a2port(optarg);
			if (ssh_port <= 0) {
				fprintf(stderr, "Bad port '%s'\n", optarg);
				exit(1);
			}
			break;
		case 'T':
		{	long t = convtime(optarg);
			if ((t == -1) || (t == 0)) {
				fprintf(stderr, "Bad timeout '%s'\n", optarg);
				usage();
			}
		#if SIZEOF_LONG_INT > SIZEOF_INT
			if (t > INT_MAX) {
				fprintf(stderr, "Timeout too high '%s'\n", optarg);
				exit(1);
			}
		#endif
			timeout = (int)t; /*safe cast*/
		}	break;
		case 'q':
			quiet = 1;
			break;
		case 'v':
			if (!debug_flag) {
				debug_flag = 1;
				log_level = SYSLOG_LEVEL_DEBUG1;
			}
			else if (log_level < SYSLOG_LEVEL_DEBUG3)
				log_level++;
			else
				fatal("Too high debugging level.");
			break;
		case 'f':
			if (strcmp(optarg, "-") == 0)
				optarg = NULL;
			argv[fopt_count++] = optarg;
			break;
		case 'O':
			/* Maybe other misc options in the future too */
			if (strncmp(optarg, "hashalg=", 8) != 0)
				fatal("Unsupported -O option");
			hashalg = ssh_digest_alg_by_name(optarg + 8);
			if (hashalg == -1)
				fatal("Unsupported hash algorithm");
			break;
		case 't':
			keynames_filter = xstrdup(optarg);
			if (!sshkey_names_valid2(keynames_filter, 1, 0)) {
				fatal("Bad hostkey key algorithms '%s'",
					keynames_filter);
			}
			break;
		case '4':
			IPv4or6 = AF_INET;
			break;
		case '6':
			IPv4or6 = AF_INET6;
			break;
		default:
			usage();
		}
	}
	if (optind == argc && !fopt_count)
		usage();

	log_init(__progname, log_level, SYSLOG_FACILITY_USER, 1);

	maxfd = fdlim_get(1);
	if (maxfd < 0)
		fatal("%s: fdlim_get: bad value", __progname);
	if (maxfd > MAXMAXFD)
		maxfd = MAXMAXFD;
	if (MAXCON <= 0)
		fatal("%s: not enough file descriptors", __progname);
	if (maxfd > fdlim_get(0))
		fdlim_set(maxfd);
	fdcon = xcalloc(maxfd, sizeof(con));
	read_wait = xcalloc(maxfd, sizeof(struct pollfd));
	for (j = 0; j < maxfd; j++)
		read_wait[j].fd = -1;

	/* default KEX and etc. name lists */
{	char *all;

	all = kex_alg_list(',');
	def_kex = match_filter_allowlist(KEX_CLIENT_KEX, all);
	free(all);

	all = cipher_alg_list(',', 0);
	def_cipher = match_filter_allowlist(KEX_CLIENT_ENCRYPT, all);
	free(all);

	all = mac_alg_list(',');
	def_mac = match_filter_allowlist(KEX_CLIENT_MAC, all);
	free(all);
}

	ssh_signal(SIGPIPE, SIG_IGN);
	for (j = 0; j < fopt_count; j++) {
		if (argv[j] == NULL)
			fp = stdin;
		else if ((fp = fopen(argv[j], "r")) == NULL)
			fatal("%s: %s: %s", __progname, argv[j], strerror(errno));

		while (getline(&line, &linesize, fp) != -1) {
			/* Chomp off trailing whitespace and comments */
			if ((cp = strchr(line, '#')) == NULL)
				cp = line + strlen(line) - 1;
			while (cp >= line) {
				if (*cp == ' ' || *cp == '\t' ||
				    *cp == '\n' || *cp == '#')
					*cp-- = '\0';
				else
					break;
			}

			/* Skip empty lines */
			if (*line == '\0')
				continue;

			do_host(line);
		}

		if (ferror(fp))
			fatal("%s: %s: %s", __progname,
			    fp == stdin ? "<stdin>" : argv[j], strerror(errno));

		if (fp != stdin)
			fclose(fp);
	}
	free(line);

	while (optind < argc)
		do_host(argv[optind++]);

	while (ncon > 0)
		conloop();

	return found_one > 0 ? 0 : 1;
}
