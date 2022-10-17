/*	$OpenBSD: arc4random.c,v 1.58 2022/07/31 13:41:45 tb Exp $	*/
/*
 * Copyright (c) 1996, David Mazieres <dm@uun.org>
 * Copyright (c) 2008, Damien Miller <djm@openbsd.org>
 * Copyright (c) 2013, Markus Friedl <markus@openbsd.org>
 * Copyright (c) 2014, Theo de Raadt <deraadt@openbsd.org>
 * Copyright (c) 2014-2022, Roumen Petrov.  All rights reserved.
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

#include <fcntl.h>
#include <signal.h>
#ifdef HAVE_STDINT_H
# include <stdint.h>
#endif
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#ifdef OPENSSL_FIPS
#include <log.h>
#include <openssl/err.h>
#endif


/*
 * If we're not using a native getentropy, use the one from bsd-getentropy.c
 * under a different name, so that if in future these binaries are run on
 * a system that has a native getentropy OpenSSL cannot call the wrong one.
 */
#ifndef HAVE_GETENTROPY
extern int _ssh_compat_getentropy(void *s, size_t len);
# define getentropy(x, y) (_ssh_compat_getentropy((x), (y)))
#endif

#ifdef OPENSSL_FIPS
/* for FIPS build always use functions from "compat" library */
# undef HAVE_ARC4RANDOM
# undef HAVE_ARC4RANDOM_STIR
# undef HAVE_ARC4RANDOM_BUF
# undef HAVE_ARC4RANDOM_UNIFORM
#endif

#if !defined(HAVE_ARC4RANDOM) || !defined(HAVE_ARC4RANDOM_STIR)

#ifdef WITH_OPENSSL
#include <openssl/rand.h>
#include <openssl/err.h>
#endif

#ifdef OPENSSL_FIPS
# ifdef HAVE_OPENSSL_FIPS_H
#  include <openssl/fips.h> /* for FIPS_mode() */
# endif
/* define to avoid use of 'efficient' arc4random_buf() */
# define HAVE_ARC4RANDOM_BUF

/* Size of key to use */
#define SEED_SIZE 20
static int rc4_ready = 0;

void      fips_arc4random_stir(void);
uint32_t  fips_arc4random(void);
void      save_arc4random_stir(void);
uint32_t  save_arc4random(void);

/* FIXME: based on readhat/fedora fips patch */
void
fips_arc4random_stir(void) {
	unsigned char rand_buf[SEED_SIZE];

	if (RAND_bytes(rand_buf, sizeof(rand_buf)) <= 0)
		fatal("Couldn't obtain random bytes (error %ld)",
		    ERR_get_error());
	rc4_ready = 1;
}
uint32_t
fips_arc4random(void) {
	unsigned int r = 0;
	void *rp = &r;

	if (!rc4_ready) {
		fips_arc4random_stir();
	}
	RAND_bytes(rp, sizeof(r));

	return(r);
}

void
arc4random_stir(void) {
	if (FIPS_mode())
		fips_arc4random_stir();
	else
		save_arc4random_stir();
}

uint32_t
arc4random(void) {
	return FIPS_mode()
		? fips_arc4random()
		: save_arc4random();
}

# define arc4random_stir	save_arc4random_stir
# define arc4random		save_arc4random
#endif /*def OPENSSL_FIPS*/


#include "log.h"

#define KEYSTREAM_ONLY
#include "chacha_private.h"

/* OpenSSH isn't multithreaded */
#define _ARC4_LOCK()
#define _ARC4_UNLOCK()
#define _ARC4_ATFORK(f)

#define KEYSZ	32
#define IVSZ	8
#define BLOCKSZ	64
#define RSBUFSZ	(16*BLOCKSZ)

#define REKEY_BASE	(1024*1024) /* NB. should be a power of 2 */

static struct _rs {
	size_t		rs_have;	/* valid bytes at end of rs_buf */
	size_t		rs_count;	/* bytes till reseed */
} *rs = NULL;

/* Maybe be preserved in fork children, if _rs_allocate() decides. */
static struct _rsx {
	chacha_ctx	rs_chacha;	/* chacha context for random keystream */
	u_char		rs_buf[RSBUFSZ];	/* keystream blocks */
} *rsx = NULL;

static volatile sig_atomic_t _rs_forked;

#if 0 /* UNUSED */
static inline void
_rs_forkhandler(void)
{
	_rs_forked = 1;
}
#endif

static inline void
_rs_forkdetect(void)
{
	static pid_t _rs_pid = 0;
	pid_t pid = getpid();

	if (_rs_pid == 0 || _rs_pid == 1 || _rs_pid != pid || _rs_forked) {
		_rs_pid = pid;
		_rs_forked = 0;
		if (rs != NULL)
			memset(rs, 0, sizeof(*rs));
	}
}

static inline int
_rs_allocate(struct _rs **rsp, struct _rsx **rsxp)
{
	if ((*rsp = mmap(NULL, sizeof(**rsp), PROT_READ|PROT_WRITE,
	    MAP_ANON|MAP_PRIVATE, -1, 0)) == MAP_FAILED)
		return (-1);

	if ((*rsxp = mmap(NULL, sizeof(**rsxp), PROT_READ|PROT_WRITE,
	    MAP_ANON|MAP_PRIVATE, -1, 0)) == MAP_FAILED) {
		munmap(*rsp, sizeof(**rsp));
		*rsp = NULL;
		return (-1);
	}

	_ARC4_ATFORK(_rs_forkhandler);
	return (0);
}


static inline void _rs_rekey(u_char *dat, size_t datlen);

static inline void
_rs_init(u_char *buf, size_t n)
{
	if (n < KEYSZ + IVSZ)
		return;

	if (rs == NULL) {
		if (_rs_allocate(&rs, &rsx) == -1)
			_exit(1);
	}

	chacha_keysetup(&rsx->rs_chacha, buf, KEYSZ * 8);
	chacha_ivsetup(&rsx->rs_chacha, buf + KEYSZ);
}

static void
_rs_stir(void)
{
	u_char rnd[KEYSZ + IVSZ];
	uint32_t rekey_fuzz = 0;

#ifdef WITH_OPENSSL
	if (RAND_bytes(rnd, sizeof(rnd)) <= 0)
		fatal("Couldn't obtain random bytes (error 0x%lx)",
		    (unsigned long)ERR_get_error());
#else
	if (getentropy(rnd, sizeof rnd) == -1)
		fatal("getentropy failed");
#endif

	if (rs == NULL)
		_rs_init(rnd, sizeof(rnd));
	else
		_rs_rekey(rnd, sizeof(rnd));
	explicit_bzero(rnd, sizeof(rnd));	/* discard source seed */

	/* invalidate rs_buf */
	rs->rs_have = 0;
	memset(rsx->rs_buf, 0, sizeof(rsx->rs_buf));

	/* rekey interval should not be predictable */
	chacha_encrypt_bytes(&rsx->rs_chacha, (uint8_t *)&rekey_fuzz,
	    (uint8_t *)&rekey_fuzz, sizeof(rekey_fuzz));
	rs->rs_count = REKEY_BASE + (rekey_fuzz % REKEY_BASE);
}

static inline void
_rs_stir_if_needed(size_t len)
{
	_rs_forkdetect();
	if (rs == NULL || rs->rs_count <= len)
		_rs_stir();
	if (rs->rs_count <= len)
		rs->rs_count = 0;
	else
		rs->rs_count -= len;
}

static inline void
_rs_rekey(u_char *dat, size_t datlen)
{
#ifndef KEYSTREAM_ONLY
	memset(rsx->rs_buf, 0, sizeof(rsx->rs_buf));
#endif
	/* fill rs_buf with the keystream */
	chacha_encrypt_bytes(&rsx->rs_chacha, rsx->rs_buf,
	    rsx->rs_buf, sizeof(rsx->rs_buf));
	/* mix in optional user provided data */
	if (dat) {
		size_t i, m;

		m = MINIMUM(datlen, KEYSZ + IVSZ);
		for (i = 0; i < m; i++)
			rsx->rs_buf[i] ^= dat[i];
	}
	/* immediately reinit for backtracking resistance */
	_rs_init(rsx->rs_buf, KEYSZ + IVSZ);
	memset(rsx->rs_buf, 0, KEYSZ + IVSZ);
	rs->rs_have = sizeof(rsx->rs_buf) - KEYSZ - IVSZ;
}

static inline void
_rsx_to_buf(void *buf, size_t len)
{
	u_char *keystream;

	keystream = rsx->rs_buf + sizeof(rsx->rs_buf) - rs->rs_have;
	memcpy(buf, keystream, len);
	memset(keystream, 0, len);
	rs->rs_have -= len;
}

# if !defined(HAVE_ARC4RANDOM_BUF) && !defined(HAVE_ARC4RANDOM)
static inline void
_rs_random_buf(void *_buf, size_t n)
{
	u_char *buf = (u_char *)_buf;
	size_t m;

	_rs_stir_if_needed(n);
	while (n > 0) {
		if (rs->rs_have > 0) {
			m = MINIMUM(n, rs->rs_have);
			_rsx_to_buf(buf, m);
			buf += m;
			n -= m;
		}
		if (rs->rs_have == 0)
			_rs_rekey(NULL, 0);
	}
}
# endif /*!defined(HAVE_ARC4RANDOM_BUF) && !defined(HAVE_ARC4RANDOM)*/

# ifndef HAVE_ARC4RANDOM
static void
_rs_random_u32(uint32_t *val)
{
	size_t m = sizeof(*val);

	_rs_stir_if_needed(m);
	if (rs->rs_have < m)
		_rs_rekey(NULL, 0);
	_rsx_to_buf(val, m);
}
# endif /*ndef HAVE_ARC4RANDOM*/

# ifndef HAVE_ARC4RANDOM_STIR
void
arc4random_stir(void)
{
#  if (defined(HAVE_ARC4RANDOM) && defined(HAVE_ARC4RANDOM_UNIFORM)) \
      || defined(OPENSSL_FIPS)
   /* platforms that have arc4random_uniform() and not
    * arc4random_stir() should not need the latter.
    * also exclude in FIPS build as there is no need to call
    * arc4random_stir() before using arc4random_buf().
    */
#  else
	_ARC4_LOCK();
	_rs_stir();
	_ARC4_UNLOCK();
#  endif
}
# endif /*ndef HAVE_ARC4RANDOM_STIR*/

# ifndef HAVE_ARC4RANDOM
uint32_t
arc4random(void)
{
	uint32_t val;

	_ARC4_LOCK();
	_rs_random_u32(&val);
	_ARC4_UNLOCK();
	return val;
}
DEF_WEAK(arc4random);
# endif /*ndef HAVE_ARC4RANDOM*/

/*
 * If we are providing arc4random, then we can provide a more efficient
 * arc4random_buf().
 */
# if !defined(HAVE_ARC4RANDOM_BUF) && !defined(HAVE_ARC4RANDOM)
void
arc4random_buf(void *buf, size_t n)
{
	_ARC4_LOCK();
	_rs_random_buf(buf, n);
	_ARC4_UNLOCK();
}
DEF_WEAK(arc4random_buf);
# endif /*!defined(HAVE_ARC4RANDOM_BUF) && !defined(HAVE_ARC4RANDOM)*/

#ifdef OPENSSL_FIPS
/* redefine to use arc4random_buf() based on arc4random() */
# define HAVE_ARC4RANDOM
# undef HAVE_ARC4RANDOM_BUF
#endif

#endif /*!defined(HAVE_ARC4RANDOM) || !defined(HAVE_ARC4RANDOM_STIR)*/

/* arc4random_buf() that uses platform arc4random() */
#if !defined(HAVE_ARC4RANDOM_BUF) && defined(HAVE_ARC4RANDOM)
void
arc4random_buf(void *_buf, size_t n)
{
	size_t i;
	uint32_t r = 0;
	char *buf = (char *)_buf;

	for (i = 0; i < n; i++) {
		if (i % 4 == 0)
			r = arc4random();
		buf[i] = r & 0xff;
		r >>= 8;
	}
	explicit_bzero(&r, sizeof(r));
}
#endif /* !defined(HAVE_ARC4RANDOM_BUF) && defined(HAVE_ARC4RANDOM) */
