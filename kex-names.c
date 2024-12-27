/* $OpenBSD: kex-names.c,v 1.4 2024/09/09 02:39:57 djm Exp $ */
/*
 * Copyright (c) 2000, 2001 Markus Friedl.  All rights reserved.
 * Copyright (c) 2014-2024 Roumen Petrov.  All rights reserved.
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

#include <stdlib.h>
#include <string.h>

#include "kex.h"
#include "log.h"
#include "digest.h"
#include "match.h"

#include "ssherr.h"

/* supported key exchange implementations */
#ifdef WITH_OPENSSL
extern const struct kex_impl kex_dh_grp1_sha1_impl;
extern const struct kex_impl kex_dh_grp14_sha1_impl;
extern const struct kex_impl kex_dh_grp14_sha256_impl;
extern const struct kex_impl kex_dh_grp16_sha512_impl;
extern const struct kex_impl kex_dh_grp18_sha512_impl;
extern const struct kex_impl kex_dh_gex_sha1_impl;
extern const struct kex_impl kex_dh_gex_sha256_impl;
# ifdef OPENSSL_HAS_ECC
extern const struct kex_impl kex_ecdh_p256_sha256_impl;
extern const struct kex_impl kex_ecdh_p384_sha384_impl;
#  ifdef OPENSSL_HAS_NISTP521
extern const struct kex_impl kex_ecdh_p521_sha512_impl;
#  endif /* OPENSSL_HAS_NISTP521 */
# endif /* OPENSSL_HAS_ECC */
#endif /* WITH_OPENSSL */
#if defined(HAVE_EVP_SHA256) || !defined(WITH_OPENSSL)
extern const struct kex_impl kex_c25519_sha256_impl;
extern const struct kex_impl kex_c25519_sha256_impl_ext;
#endif /* HAVE_EVP_SHA256 || !WITH_OPENSSL */
#ifdef USE_ECDH_X448
extern const struct kex_impl kex_c448_sha512_impl;
#endif
#ifdef ENABLE_KEX_SNTRUP761X25519
extern const struct kex_impl kex_kem_sntrup761x25519_sha512_impl;
extern const struct kex_impl kex_kem_sntrup761x25519_sha512_impl_ext;
#endif
#ifdef ENABLE_KEX_MLKEM768X25519
extern const struct kex_impl kex_kem_mlkem768x25519_sha256_impl;
#endif

static const struct kex_impl* const kex_impl_list[] = {
#ifdef WITH_OPENSSL
	&kex_dh_grp1_sha1_impl,
	&kex_dh_grp14_sha1_impl,
	&kex_dh_grp14_sha256_impl,
	&kex_dh_grp16_sha512_impl,
	&kex_dh_grp18_sha512_impl,
	&kex_dh_gex_sha1_impl,
	&kex_dh_gex_sha256_impl,
# ifdef OPENSSL_HAS_ECC
	&kex_ecdh_p256_sha256_impl,
	&kex_ecdh_p384_sha384_impl,
#  ifdef OPENSSL_HAS_NISTP521
	&kex_ecdh_p521_sha512_impl,
#  endif /* OPENSSL_HAS_NISTP521 */
# endif /* OPENSSL_HAS_ECC */
#endif /* WITH_OPENSSL */
#if defined(HAVE_EVP_SHA256) || !defined(WITH_OPENSSL)
	&kex_c25519_sha256_impl,
	&kex_c25519_sha256_impl_ext,
#endif /* HAVE_EVP_SHA256 || !WITH_OPENSSL */
#ifdef USE_ECDH_X448
	&kex_c448_sha512_impl,
#endif
#ifdef ENABLE_KEX_SNTRUP761X25519
	&kex_kem_sntrup761x25519_sha512_impl,
	&kex_kem_sntrup761x25519_sha512_impl_ext,
#endif
#ifdef ENABLE_KEX_MLKEM768X25519
	&kex_kem_mlkem768x25519_sha256_impl,
#endif
	NULL
};

const struct kex_impl*
kex_find_impl(const char *name)
{
	const struct kex_impl* const *p;

	for (p = kex_impl_list; *p != NULL; p++) {
		if (!(*p)->enabled()) continue;
		if (strcmp((*p)->name, name) == 0)
			return *p;
	}
	return NULL;
}

char *
kex_alg_list(char sep)
{
	char *ret = NULL, *tmp;
	size_t nlen, rlen = 0;
	const struct kex_impl* const *p;

	for (p = kex_impl_list; *p != NULL; p++) {
		if (!(*p)->enabled()) continue;
		if (ret != NULL)
			ret[rlen++] = sep;
		nlen = strlen((*p)->name);
		if ((tmp = realloc(ret, rlen + nlen + 2)) == NULL) {
			free(ret);
			return NULL;
		}
		ret = tmp;
		memcpy(ret + rlen, (*p)->name, nlen + 1);
		rlen += nlen;
	}
	return ret;
}

/* Validate KEX method name list */
int
kex_names_valid(const char *names)
{
	char *s, *cp, *p;

	if (names == NULL || strcmp(names, "") == 0)
		return 0;
	if ((s = cp = strdup(names)) == NULL)
		return 0;
	for ((p = strsep(&cp, ",")); p && *p != '\0';
	    (p = strsep(&cp, ","))) {
		if (kex_find_impl(p) == NULL) {
			error("Unsupported KEX algorithm \"%.100s\"", p);
			free(s);
			return 0;
		}
	}
	debug3("kex names ok: [%s]", names);
	free(s);
	return 1;
}

/* returns non-zero if proposal contains any algorithm from algs */
int
kex_has_any_alg(const char *proposal, const char *algs)
{
	char *cp = match_list(proposal, algs, NULL);
	if (cp == NULL) return 0;
	free(cp);
	return 1;
}

/*
 * Concatenate algorithm names, avoiding duplicates in the process.
 * Caller must free returned string.
 */
char *
kex_names_cat(const char *a, const char *b)
{
	char *ret = NULL, *tmp = NULL, *cp, *p;
	size_t len;

	if (a == NULL || *a == '\0')
		return strdup(b);
	if (b == NULL || *b == '\0')
		return strdup(a);
	if (strlen(b) > 1024*1024)
		return NULL;
	len = strlen(a) + strlen(b) + 2;
	if ((tmp = cp = strdup(b)) == NULL ||
	    (ret = calloc(1, len)) == NULL) {
		free(tmp);
		return NULL;
	}
	strlcpy(ret, a, len);
	for ((p = strsep(&cp, ",")); p && *p != '\0'; (p = strsep(&cp, ","))) {
		if (kex_has_any_alg(ret, p))
			continue; /* Algorithm already present */
		if (strlcat(ret, ",", len) >= len ||
		    strlcat(ret, p, len) >= len) {
			free(tmp);
			free(ret);
			return NULL; /* Shouldn't happen */
		}
	}
	free(tmp);
	return ret;
}

/*
 * Assemble a list of algorithms from a default list and a string from a
 * configuration file. The user-provided string may begin with '+' to
 * indicate that it should be appended to the default, '-' that the
 * specified names should be removed, or '^' that they should be placed
 * at the head.
 */
int
kex_assemble_names(char **listp, const char *def, const char *all)
{
	char *cp, *tmp, *patterns;
	char *list = NULL, *ret = NULL, *matching = NULL, *opatterns = NULL;
	int r = SSH_ERR_INTERNAL_ERROR;

	if (listp == NULL || def == NULL || all == NULL)
		return SSH_ERR_INVALID_ARGUMENT;

	if (*listp == NULL || **listp == '\0') {
		if ((*listp = strdup(def)) == NULL)
			return SSH_ERR_ALLOC_FAIL;
		return 0;
	}

	list = *listp;
	*listp = NULL;
	if (*list == '+') {
		/* Append names to default list */
		if ((tmp = kex_names_cat(def, list + 1)) == NULL) {
			r = SSH_ERR_ALLOC_FAIL;
			goto fail;
		}
		free(list);
		list = tmp;
	} else if (*list == '-') {
		/* Remove names from default list */
		if ((*listp = match_filter_denylist(def, list + 1)) == NULL) {
			r = SSH_ERR_ALLOC_FAIL;
			goto fail;
		}
		free(list);
		/* filtering has already been done */
		return 0;
	} else if (*list == '^') {
		/* Place names at head of default list */
		if ((tmp = kex_names_cat(list + 1, def)) == NULL) {
			r = SSH_ERR_ALLOC_FAIL;
			goto fail;
		}
		free(list);
		list = tmp;
	} else {
		/* Explicit list, overrides default - just use "list" as is */
	}

	/*
	 * The supplied names may be a pattern-list. For the -list case,
	 * the patterns are applied above. For the +list and explicit list
	 * cases we need to do it now.
	 */
	ret = NULL;
	if ((patterns = opatterns = strdup(list)) == NULL) {
		r = SSH_ERR_ALLOC_FAIL;
		goto fail;
	}
	/* Apply positive (i.e. non-negated) patterns from the list */
	while ((cp = strsep(&patterns, ",")) != NULL) {
		if (*cp == '!') {
			/* negated matches are not supported here */
			r = SSH_ERR_INVALID_ARGUMENT;
			goto fail;
		}
		free(matching);
		if ((matching = match_filter_allowlist(all, cp)) == NULL) {
			r = SSH_ERR_ALLOC_FAIL;
			goto fail;
		}
		if ((tmp = kex_names_cat(ret, matching)) == NULL) {
			r = SSH_ERR_ALLOC_FAIL;
			goto fail;
		}
		free(ret);
		ret = tmp;
	}
	if (ret == NULL || *ret == '\0') {
		/* An empty name-list is an error */
		/* XXX better error code? */
		r = SSH_ERR_INVALID_ARGUMENT;
		goto fail;
	}

	/* success */
	*listp = ret;
	ret = NULL;
	r = 0;

 fail:
	free(matching);
	free(opatterns);
	free(list);
	free(ret);
	return r;
}
