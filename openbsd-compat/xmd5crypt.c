/*
 * ----------------------------------------------------------------------------
 * "THE BEER-WARE LICENSE" (Revision 42):
 * <phk@login.dknet.dk> wrote this file.  As long as you retain this
 * notice you can do whatever you want with this stuff. If we meet some
 * day, and you think this stuff is worth it, you can buy me a beer in
 * return.   Poul-Henning Kamp
 * ----------------------------------------------------------------------------
 *
 * Copyright (c) 2020 Roumen Petrov.  All rights reserved.
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

#if defined(HAVE_MD5_PASSWORDS) && !defined(HAVE_MD5_CRYPT)
#include <sys/types.h>

#include <string.h>

#include <openssl/evp.h>
#include "evp-compat.h"

#include "md5crypt.h"
#include "log.h"

/* 0 ... 63 => ascii - 64 */
static unsigned char itoa64[] =
    "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

static char *magic = "$1$";

static char *
to64(unsigned long v, int n)
{
	static char buf[5];
	char *s = buf;

	if (n > 4)
		return (NULL);

	memset(buf, '\0', sizeof(buf));
	while (--n >= 0) {
		*s++ = itoa64[v&0x3f];
		v >>= 6;
	}

	return (buf);
}

int
is_md5_salt(const char *salt)
{
	return (strncmp(salt, magic, strlen(magic)) == 0);
}

char *
md5_crypt(const char *pw, const char *salt)
{
	static char passwd[120], salt_copy[9];
	static const char *sp, *ep;
	unsigned char final[16];
	unsigned int final_len;
	int sl, pl, i, j;
	EVP_MD_CTX *ctx, *ctx1;
	unsigned long l;

	/* Refine the Salt first */
	sp = salt;

	/* If it starts with the magic string, then skip that */
	if(strncmp(sp, magic, strlen(magic)) == 0)
		sp += strlen(magic);

	/* It stops at the first '$', max 8 chars */
	for (ep = sp; *ep != '$'; ep++) {
		if (*ep == '\0' || ep >= (sp + 8))
			break;
	}

	/* get the length of the true salt */
	sl = ep - sp;

	/* Stash the salt */
	memcpy(salt_copy, sp, sl);
	salt_copy[sl] = '\0';

	ctx = EVP_MD_CTX_new();
	if (ctx == NULL) {
		fatal("md5_crypt: out of memory - ctx");
		return NULL; /*unreachable code*/
	}
	ctx1 = EVP_MD_CTX_new();
	if (ctx1 == NULL) {
		fatal("md5_crypt: out of memory - ctx1");
		return NULL; /*unreachable code*/
	}

	EVP_DigestInit_ex(ctx, EVP_md5(), NULL);

	/* The password first, since that is what is most unknown */
	EVP_DigestUpdate(ctx, pw, strlen(pw));

	/* Then our magic string */
	EVP_DigestUpdate(ctx, magic, strlen(magic));

	/* Then the raw salt */
	EVP_DigestUpdate(ctx, sp, sl);

	/* Then just as many characters of the MD5(pw, salt, pw) */
	EVP_DigestInit_ex(ctx1, EVP_md5(), NULL);
	EVP_DigestUpdate(ctx1, pw, strlen(pw));
	EVP_DigestUpdate(ctx1, sp, sl);
	EVP_DigestUpdate(ctx1, pw, strlen(pw));
	final_len = sizeof(final);
	EVP_DigestFinal(ctx1, final, &final_len);

	for(pl = strlen(pw); pl > 0; pl -= 16)
		EVP_DigestUpdate(ctx, final, pl > 16 ? 16 : pl);

	/* Don't leave anything around in vm they could use. */
	memset(final, '\0', sizeof final);

	/* Then something really weird... */
	for (j = 0, i = strlen(pw); i != 0; i >>= 1)
		if (i & 1)
			EVP_DigestUpdate(ctx, final + j, 1);
		else
			EVP_DigestUpdate(ctx, pw + j, 1);

	/* Now make the output string */
	snprintf(passwd, sizeof(passwd), "%s%s$", magic, salt_copy);

	final_len = sizeof(final);
	EVP_DigestFinal(ctx, final, &final_len);

	/*
	 * and now, just to make sure things don't run too fast
	 * On a 60 Mhz Pentium this takes 34 msec, so you would
	 * need 30 seconds to build a 1000 entry dictionary...
	 */
	for(i = 0; i < 1000; i++) {
		EVP_DigestInit_ex(ctx1, EVP_md5(), NULL);
		if (i & 1)
			EVP_DigestUpdate(ctx1, pw, strlen(pw));
		else
			EVP_DigestUpdate(ctx1, final, 16);

		if (i % 3)
			EVP_DigestUpdate(ctx1, sp, sl);

		if (i % 7)
			EVP_DigestUpdate(ctx1, pw, strlen(pw));

		if (i & 1)
			EVP_DigestUpdate(ctx1, final, 16);
		else
			EVP_DigestUpdate(ctx1, pw, strlen(pw));

		final_len = sizeof(final);
		EVP_DigestFinal(ctx1, final, &final_len);
	}

	l = (final[ 0]<<16) | (final[ 6]<<8) | final[12];
	strlcat(passwd, to64(l, 4), sizeof(passwd));
	l = (final[ 1]<<16) | (final[ 7]<<8) | final[13];
	strlcat(passwd, to64(l, 4), sizeof(passwd));
	l = (final[ 2]<<16) | (final[ 8]<<8) | final[14];
	strlcat(passwd, to64(l, 4), sizeof(passwd));
	l = (final[ 3]<<16) | (final[ 9]<<8) | final[15];
	strlcat(passwd, to64(l, 4), sizeof(passwd));
	l = (final[ 4]<<16) | (final[10]<<8) | final[ 5];
	strlcat(passwd, to64(l, 4), sizeof(passwd));
	l =                    final[11]                ;
	strlcat(passwd, to64(l, 2), sizeof(passwd));

	/* Don't leave anything around in vm they could use. */
	memset(final, 0, sizeof(final));
	memset(salt_copy, 0, sizeof(salt_copy));
	EVP_MD_CTX_free(ctx);
	EVP_MD_CTX_free(ctx1);
	(void)to64(0, 4);

	return (passwd);
}

#endif /* defined(HAVE_MD5_PASSWORDS) && !defined(HAVE_MD5_CRYPT) */
