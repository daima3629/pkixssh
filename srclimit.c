/*
 * Copyright (c) 2020 Darren Tucker <dtucker@openbsd.org>
 * Copyright (c) 2021 Roumen Petrov.  All rights reserved.
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

#include <sys/socket.h>
#include <sys/types.h>

#include <limits.h>
#include <netdb.h>
#include <stdio.h>
#include <string.h>

#include "addr.h"
#include "canohost.h"
#include "log.h"
#include "misc.h"
#include "srclimit.h"
#include "xmalloc.h"

static int max_persource = -1, max_children, ipv4_masklen, ipv6_masklen;

/* Per connection state, used to enforce unauthenticated connection limit. */
static struct child_info {
	int id;
	struct xaddr addr;
} *child;

void
srclimit_init(int max, int persource, int ipv4len, int ipv6len)
{
	int i;

	max_children = max;
	ipv4_masklen = ipv4len;
	ipv6_masklen = ipv6len;
	max_persource = persource;
	if (max_persource < 0) return; /* no limit */

	debug_f("max connections %d, per source %d, masks %d,%d",
	    max, persource, ipv4len, ipv6len);
	if (max <= 0)
		fatal_f("invalid number of sockets: %d", max);
	child = xcalloc(max_children, sizeof(*child));
	for (i = 0; i < max_children; i++)
		child[i].id = -1;
}

/* returns 1 if connection allowed, 0 if not allowed. */
int
srclimit_check_allow(int sock, int id)
{
	struct xaddr xa, xb, xmask;
	struct sockaddr_storage addr;
	int i, bits, first_unused, count;

	if (max_persource < 0) return 1; /* no limit */

	debug_f("sock %d id %d limit %d", sock, id, max_persource);
{
	struct sockaddr *sa = (struct sockaddr *)&addr;
	socklen_t addrlen = sizeof(addr);

	if (getpeername(sock, sa, &addrlen) != 0)
		return 1;	/* not remote socket? */
	if (addr_sa_to_xaddr(sa, addrlen, &xa) != 0)
		return 1;	/* unknown address family? */
}

	/* Mask address off address to desired size. */
	bits = xa.af == AF_INET ? ipv4_masklen : ipv6_masklen;
	if (addr_netmask(xa.af, bits, &xmask) != 0 ||
	    addr_and(&xb, &xa, &xmask) != 0) {
		debug3_f("invalid mask %d bits", bits);
		return 1; /*allowed?*/
	}

	first_unused = max_children;
	count = 0;
	/* Count matching entries and find first unused one. */
	for (i = 0; i < max_children; i++) {
		if (child[i].id == -1) {
			if (i < first_unused) {
				first_unused = i;
				break;
			}
		} else
			if (addr_cmp(&child[i].addr, &xb) == 0)
				count++;
	}
	if (first_unused == max_children) { /* no free slot found */
		debug3_f("no free slot");
		return 0;
	}

{	char xas[NI_MAXHOST];
	if (addr_ntop(&xa, xas, sizeof(xas)) != 0)
		debug3_f("addr ntop failed");
		/* return 1; allowed!? */
	else
		strlcpy(xas, "<unknown>", sizeof(xas));
	debug3_f("new unauthenticated connection from %s/%d, at %d of %d",
	    xas, bits, count, max_persource);
}

	if (count >= max_persource)
		return 0;

	/* Connection allowed, store masked address. */
	child[first_unused].id = id;
	memcpy(&child[first_unused].addr, &xb, sizeof(xb));
	return 1;
}

void
srclimit_done(int id)
{
	int i;

	if (max_persource < 0) return; /* no limit */

	debug_f("id %d", id);
	/* Clear corresponding state entry. */
	for (i = 0; i < max_children; i++) {
		if (child[i].id == id) {
			child[i].id = -1;
			return;
		}
	}
}
