/* OPENBSD ORIGINAL: lib/libc/string/explicit_bzero.c */
/*	$OpenBSD: explicit_bzero.c,v 1.1 2014/01/22 21:06:45 tedu Exp $ */
/*
 * Public domain.
 * Written by Ted Unangst
 *
 * Copyright (c) 2016-2022 Roumen Petrov.  All rights reserved.
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF MIND, USE, DATA OR PROFITS, WHETHER
 * IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING
 * OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include "includes.h"

#include <string.h>

/*
 * explicit_bzero - don't let the compiler optimize away function call
 */

#ifndef HAVE_EXPLICIT_BZERO

#ifdef HAVE_EXPLICIT_MEMSET

void
explicit_bzero(void *p, size_t n)
{
	(void)explicit_memset(p, 0, n);
}

#elif defined(HAVE_MEMSET_S)

# if !HAVE_DECL_MEMSET_S
void *memset_s(const void *, size_t, int, size_t);
# endif

void
explicit_bzero(void *p, size_t n)
{
	if (n == 0)
		return;
	(void)memset_s(p, n, 0, n);
}

#else

/* Use memset as bzero is marked as legacy in POSIX.1-2001
 * and removed on POSIX.1-2008 */
typedef void *(*memset_t)(void *,int,size_t);
static volatile memset_t ssh_memset = memset;

void
explicit_bzero(void *p, size_t n)
{
	ssh_memset(p, 0, n);
}

#endif

#else

typedef int explicit_bzero_empty_translation_unit;

#endif /* HAVE_EXPLICIT_BZERO */
