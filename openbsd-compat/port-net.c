/*
 * Copyright (c) 2005 Reyk Floeter <reyk@openbsd.org>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include "includes.h"

#include <sys/types.h>
#include <sys/ioctl.h>

#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/ip.h>

#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <string.h>
#include <unistd.h>

#include "openbsd-compat/sys-queue.h"
#include "xmalloc.h"
#include "log.h"
#include "misc.h"
#include "sshbuf.h"
#include "channels.h"
#include "ssherr.h"

/*
 * This file contains various portability code for network support,
 * including tun/tap forwarding and routing domains.
 */

#if defined(SYS_RDOMAIN_LINUX) || defined(SSH_TUN_LINUX)
#include <linux/if.h>
#endif

#if defined(SYS_RDOMAIN_LINUX)
char *
sys_get_rdomain(int fd)
{
	char dev[IFNAMSIZ + 1];
	socklen_t len = sizeof(dev) - 1;

	if (getsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, dev, &len) == -1) {
		error_f("cannot determine VRF for fd=%d : %s",
		    fd, strerror(errno));
		return NULL;
	}
	dev[len] = '\0';
	return strdup(dev);
}

int
sys_set_rdomain(int fd, const char *name)
{
	if (setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE,
	    name, strlen(name)) == -1) {
		error_f("setsockopt(%d, SO_BINDTODEVICE, %s): %s",
		    fd, name, strerror(errno));
		return -1;
	}
	return 0;
}

int
sys_valid_rdomain(const char *name)
{
	int fd;

	/*
	 * This is a pretty crappy way to test. It would be better to
	 * check whether "name" represents a VRF device, but apparently
	 * that requires an rtnetlink transaction.
	 */
	if ((fd = socket(AF_INET, SOCK_STREAM, 0)) == -1)
		return 0;
	if (setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE,
	    name, strlen(name)) == -1) {
		close(fd);
		return 0;
	}
	close(fd);
	return 1;
}
#elif defined(SYS_RDOMAIN_XXX)
/* XXX examples */
char *
sys_get_rdomain(int fd)
{
	return NULL;
}

int
sys_set_rdomain(int fd, const char *name)
{
	return -1;
}

int
valid_rdomain(const char *name)
{
	return 0;
}

void
sys_set_process_rdomain(const char *name)
{
	fatal_f("not supported");
}
#endif /* defined(SYS_RDOMAIN_XXX) */

/*
 * This is the portable version of the SSH tunnel forwarding, it
 * uses some preprocessor definitions for various platform-specific
 * settings.
 *
 * SSH_TUN_LINUX	Use the (newer) Linux tun/tap device
 * SSH_TUN_FREEBSD	Use the FreeBSD tun/tap device
 * SSH_TUN_DARWIN	Use the Darwin utun device
 * SSH_TUN_COMPAT_AF	Translate the OpenBSD address family
 * SSH_TUN_PREPEND_AF	Prepend/remove the address family
 */

/*
 * System-specific tunnel open function
 */

#if defined(SSH_TUN_LINUX)
#include <linux/if_tun.h>
#ifdef __ANDROID__
#define TUN_CTRL_DEV "/dev/tun"
#else
#define TUN_CTRL_DEV "/dev/net/tun"
#endif

int
sys_tun_open(int tun, int mode, char **ifname)
{
	struct ifreq ifr;
	int fd = -1;
	const char *name = NULL;

	if (ifname != NULL)
		*ifname = NULL;
	if ((fd = open(TUN_CTRL_DEV, O_RDWR)) == -1) {
		debug_f("failed to open tunnel control device \"%s\": %s",
		    TUN_CTRL_DEV, strerror(errno));
		return (-1);
	}

	memset(&ifr, 0, sizeof(ifr));

	if (mode == SSH_TUNMODE_ETHERNET) {
		ifr.ifr_flags = IFF_TAP;
		name = "tap%d";
	} else {
		ifr.ifr_flags = IFF_TUN;
		name = "tun%d";
	}
	ifr.ifr_flags |= IFF_NO_PI;

	if (tun != SSH_TUNID_ANY) {
		if (tun > SSH_TUNID_MAX) {
			debug_f("invalid tunnel id %x: %s", tun,
			    strerror(errno));
			goto failed;
		}
		snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), name, tun);
	}

	if (ioctl(fd, TUNSETIFF, &ifr) == -1) {
		debug_f("failed to configure tunnel (mode %d): %s", mode,
		    strerror(errno));
		goto failed;
	}

	if (tun == SSH_TUNID_ANY)
		debug_f("tunnel mode %d fd %d", mode, fd);
	else
		debug_f("%s mode %d fd %d", ifr.ifr_name, mode, fd);

	if (ifname != NULL)
		*ifname = xstrdup(ifr.ifr_name);

	return (fd);

 failed:
	close(fd);
	return (-1);
}
#endif /* SSH_TUN_LINUX */

#ifdef SSH_TUN_FREEBSD
#include <sys/socket.h>
#include <net/if.h>

#ifdef HAVE_NET_IF_TUN_H
#include <net/if_tun.h>
#endif

int
sys_tun_open(int tun, int mode, char **ifname)
{
	struct ifreq ifr;
	char name[100];
	int fd = -1, sock;
	const char *tunbase = "tun";

	if (ifname != NULL)
		*ifname = NULL;

	if (mode == SSH_TUNMODE_ETHERNET) {
#ifdef SSH_TUN_NO_L2
		debug_f("no layer 2 tunnelling support");
		return (-1);
#else
		tunbase = "tap";
#endif
	}

	/* Open the tunnel device */
	if (tun <= SSH_TUNID_MAX) {
		snprintf(name, sizeof(name), "/dev/%s%d", tunbase, tun);
		fd = open(name, O_RDWR);
	} else if (tun == SSH_TUNID_ANY) {
		for (tun = 100; tun >= 0; tun--) {
			snprintf(name, sizeof(name), "/dev/%s%d",
			    tunbase, tun);
			if ((fd = open(name, O_RDWR)) >= 0)
				break;
		}
	} else {
		debug_f("invalid tunnel %u", tun);
		return (-1);
	}

	if (fd == -1) {
		debug_f("%s open failed: %s", name, strerror(errno));
		return (-1);
	}

	/* Turn on tunnel headers */
#if defined(TUNSIFHEAD) && !defined(SSH_TUN_PREPEND_AF)
{	int flag = 1;
	if (mode != SSH_TUNMODE_ETHERNET &&
	    ioctl(fd, TUNSIFHEAD, &flag) == -1) {
		debug_f("ioctl(%d, TUNSIFHEAD, 1): %s", fd, strerror(errno));
		close(fd);
	}
}
#endif

	debug_f("%s mode %d fd %d", name, mode, fd);

	/* Set the tunnel device operation mode */
	snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "%s%d", tunbase, tun);
	if ((sock = socket(PF_UNIX, SOCK_STREAM, 0)) == -1)
		goto failed;

	if (ioctl(sock, SIOCGIFFLAGS, &ifr) == -1)
		goto failed;
	if ((ifr.ifr_flags & IFF_UP) == 0) {
		ifr.ifr_flags |= IFF_UP;
		if (ioctl(sock, SIOCSIFFLAGS, &ifr) == -1)
			goto failed;
	}

	if (ifname != NULL)
		*ifname = xstrdup(ifr.ifr_name);

	close(sock);
	return (fd);

 failed:
	if (fd >= 0)
		close(fd);
	if (sock >= 0)
		close(sock);
	debug_f("failed to set %s mode %d: %s", name, mode, strerror(errno));
	return (-1);
}
#endif /* SSH_TUN_FREEBSD */

#ifdef SSH_TUN_DARWIN
#include <sys/sys_domain.h>
#include <sys/kern_control.h>
#include <net/if_utun.h>

int
sys_tun_open(int tun, int mode, char **ifname)
{
	struct ctl_info info;
	struct sockaddr_ctl addr;
	int fd;

	if (ifname != NULL)
		*ifname = NULL;

	if (tun != SSH_TUNID_ANY && tun > SSH_TUNID_MAX) {
		debug_f("invalid tunnel %u", tun);
		return (-1);
	}

	if (mode == SSH_TUNMODE_ETHERNET) {
		debug_f("no layer 2 tunnelling support");
		return (-1);
	}

	fd = socket(PF_SYSTEM, SOCK_DGRAM, SYSPROTO_CONTROL);
	if (fd == -1) {
		debug_f("failed to create control socket: %s",
		    strerror(errno));
		return (-1);
	}

	memset(&info, 0, sizeof(info));
	strlcpy(info.ctl_name, UTUN_CONTROL_NAME, sizeof(info.ctl_name));
	if (ioctl(fd, CTLIOCGINFO, &info) == -1) {
		debug_f("failed to lookup utun control id: %s",
		    strerror(errno));
		goto failed;
	}

	memset(&addr, 0, sizeof(addr));
	addr.sc_id = info.ctl_id;
	addr.sc_len = sizeof(addr);
	addr.sc_family = AF_SYSTEM;
	addr.ss_sysaddr = AF_SYS_CONTROL;
	if (tun != SSH_TUNID_ANY)
		addr.sc_unit = tun + 1;

	if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) == -1) {
		debug_f("failed to connect to utun device: %s",
		    strerror(errno));
		goto failed;
	}

	if (ifname != NULL) {
		char buf[20];
		snprintf(buf, sizeof(buf), "tun%d", addr.sc_unit);
		*ifname = xstrdup(buf);
	}

	return (fd);

 failed:
	close(fd);
	return (-1);
}
#endif /* SSH_TUN_DARWIN */

/*
 * System-specific channel filters
 */

#if defined(SSH_TUN_FILTER)
/*
 * The tunnel forwarding protocol prepends the address family of forwarded
 * IP packets using OpenBSD's numbers.
 */
#define OPENBSD_AF_INET		2
#define OPENBSD_AF_INET6	24

#if defined(SSH_TUN_PREPEND_AF)
/* read buffer size */
/* NOTE keep synchronised with channels.c */
#if defined(HAVE_CYGWIN) && !defined(CHAN_RBUF)	/* unused */
# define CHAN_RBUF	(64*1024)
#endif
# ifndef CHAN_RBUF
#  define CHAN_RBUF	(4*1024)
# endif
#endif

int
sys_tun_infilter(struct ssh *ssh, struct Channel *c, char *buf, int _len)
{
	int r;
	size_t len;
	char *ptr = buf;
#if defined(SSH_TUN_PREPEND_AF)
	char rbuf[CHAN_RBUF];
	struct ip iph;
#endif
#if defined(SSH_TUN_PREPEND_AF) || defined(SSH_TUN_COMPAT_AF)
	u_int32_t af;
#endif

	UNUSED(ssh);
	/* XXX update channel input filter API to use unsigned length */
	if (_len < 0)
		return -1;
	len = _len;

#if defined(SSH_TUN_PREPEND_AF)
	if (len <= sizeof(iph) || len > sizeof(rbuf) - 4)
		return -1;
	/* Determine address family from packet IP header. */
	memcpy(&iph, buf, sizeof(iph));
	af = iph.ip_v == 6 ? OPENBSD_AF_INET6 : OPENBSD_AF_INET;
	/* Prepend address family to packet using OpenBSD constants */
	memcpy(rbuf + 4, buf, len);
	len += 4;
	POKE_U32(rbuf, af);
	ptr = rbuf;
#elif defined(SSH_TUN_COMPAT_AF)
	/* Convert existing address family header to OpenBSD value */
	if (len <= 4)
		return -1;
	af = PEEK_U32(buf);
	/* Put it back */
	POKE_U32(buf, af == AF_INET6 ? OPENBSD_AF_INET6 : OPENBSD_AF_INET);
#endif

	if ((r = sshbuf_put_string(c->input, ptr, len)) != 0)
		fatal_fr(r, "buffer error");
	return (0);
}

u_char *
sys_tun_outfilter(struct ssh *ssh, struct Channel *c,
    u_char **data, size_t *dlen)
{
	u_char *buf;
	u_int32_t af;
	int r;

	UNUSED(ssh);
	/* XXX new API is incompatible with this signature. */
	if ((r = sshbuf_get_string(c->output, data, dlen)) != 0)
		fatal_fr(r, "buffer error");
	if (*dlen < sizeof(af))
		return (NULL);
	buf = *data;

#if defined(SSH_TUN_PREPEND_AF)
	/* skip address family */
	*dlen -= sizeof(af);
	buf = *data + sizeof(af);
#elif defined(SSH_TUN_COMPAT_AF)
	/* translate address family */
	af = (PEEK_U32(buf) == OPENBSD_AF_INET6) ? AF_INET6 : AF_INET;
	POKE_U32(buf, af);
#endif
	return (buf);
}
#endif /* SSH_TUN_FILTER */
