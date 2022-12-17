/*
 * Copyright (c) 2005-2022 Roumen Petrov.  All rights reserved.
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

#include "ssh-xkalg.h"
#include <string.h>
#include <openssl/sha.h>
#include <openssl/evp.h>

#include "sshxkey.h"
#include "sshbuf.h"
#include "log.h"
#include "match.h"
#include "myproposal.h"
#include "xmalloc.h"


/* SSH X509 public key algorithms*/
static int x509keyalgs_initialized = 0;
static SSHX509KeyAlgs x509keyalgs[20];


static void
initialize_xkalg(void) {
	SSHX509KeyAlgs *p = x509keyalgs;
	int k;

	if (x509keyalgs_initialized) return;

#ifdef TRACE_XKALG
logit("TRACE_XKALG initialize_xkalg:");
#endif
	k = sizeof(x509keyalgs) / sizeof(x509keyalgs[0]);
	for (; k > 0; k--, p++) {
		p->name = NULL;
		p->dgst = NULL;
		p->signame = NULL;
		p->basetype = KEY_UNSPEC;
		p->subtype = -1;
		p->chain = 0;
	}
	x509keyalgs_initialized = 1;
}


static void
add_default_xkalg(void) {
#ifdef TRACE_XKALG
logit("TRACE_XKALG add_default_xkalg:");
#endif

	/* EC public key algorithm: */
	/* - RFC6187: ssh opaque signature */
# ifdef OPENSSL_HAS_NISTP256
	if (ssh_add_x509key_alg("x509v3-ecdsa-sha2-nistp256,ssh-sha256,ecdsa-sha2-nistp256") < 0)
		fatal_f("oops");
# endif
# ifdef OPENSSL_HAS_NISTP384
	if (ssh_add_x509key_alg("x509v3-ecdsa-sha2-nistp384,ssh-sha384,ecdsa-sha2-nistp384") < 0)
		fatal_f("oops");
# endif
# ifdef OPENSSL_HAS_NISTP521
	if (ssh_add_x509key_alg("x509v3-ecdsa-sha2-nistp521,ssh-sha512,ecdsa-sha2-nistp521") < 0)
		fatal_f("oops");
# endif

	/* RSA public key algorithm: */
	/* - RFC6187 */
#ifdef HAVE_EVP_SHA256
	if (ssh_add_x509key_alg("x509v3-rsa2048-sha256,rsa2048-sha256,rsa2048-sha256") < 0)
		fatal_f("oops");
#endif
	if (ssh_add_x509key_alg("x509v3-ssh-rsa,rsa-sha1,ssh-rsa") < 0)
		fatal_f("oops");
	/* - draft-ietf-secsh-transport-NN.txt where NN <= 12
	 * does not define explicitly signature format.
	 * - starting from version 7.1 first is rsa-sha1
	 */
	if (ssh_add_x509key_alg("x509v3-sign-rsa,rsa-sha1") < 0)
		fatal_f("oops");
#ifdef OPENSSL_FIPS
	if(!FIPS_mode())
#endif
	if (ssh_add_x509key_alg("x509v3-sign-rsa,rsa-md5") < 0)
		fatal_f("oops");

	/* DSA public key algorithm: */
	/* - RFC6187 */
	if (ssh_add_x509key_alg("x509v3-ssh-dss,dss-raw,ssh-dss") < 0)
		fatal_f("oops");
	/* compatible with draft-ietf-secsh-transport-NN.txt
	 * where NN <= 12
	 */
	if (ssh_add_x509key_alg("x509v3-sign-dss,dss-asn1") < 0)
		fatal_f("oops");
	/* - some secsh implementations incompatible with
	 * draft-ietf-secsh-transport-NN.txt where NN <= 12
	 */
	if (ssh_add_x509key_alg("x509v3-sign-dss,dss-raw") < 0)
		fatal_f("oops");

#ifdef OPENSSL_HAS_ED25519
	/* NOTE: OPENSSL_HAS_ED25519 implies HAVE_EVP_DIGESTSIGN */
	if (ssh_add_x509key_alg("x509v3-ssh-ed25519,none,ssh-ed25519") < 0)
		fatal_f("oops");
#endif
}


void
fill_default_xkalg(void) {
	SSHX509KeyAlgs *p = x509keyalgs;

#ifdef TRACE_XKALG
logit("TRACE_XKALG fill_default_xkalg:");
#endif
	initialize_xkalg();
	if (p[0].name == NULL) add_default_xkalg();
}


static int
ssh_x509key_alg_digest(SSHX509KeyAlgs* p, const char *dgstname) {
	int id;

	if (dgstname == NULL) {
		fatal_f("dgstname is NULL");
		return(-1); /*unreachable code*/
	}

	if (strcasecmp("rsa-sha1", dgstname) == 0) {
		id = SSH_MD_RSA_SHA1; goto done; }
	if (strcasecmp("rsa-md5" , dgstname) == 0) {
		id = SSH_MD_RSA_MD5; goto done; }
#ifdef HAVE_EVP_SHA256
	if (strcasecmp("rsa2048-sha256", dgstname) == 0) {
		id = SSH_MD_RSA_SHA256; goto done; }
#endif

#ifdef OPENSSL_HAS_NISTP256
	if (strcasecmp("ssh-sha256"  , dgstname) == 0) {
		id = SSH_MD_EC_SHA256_SSH; goto done; }
	if (strcasecmp("sha256"  , dgstname) == 0) {
		id = SSH_MD_EC_SHA256; goto done; }
#endif
#ifdef OPENSSL_HAS_NISTP384
	if (strcasecmp("ssh-sha384"  , dgstname) == 0) {
		id = SSH_MD_EC_SHA384_SSH; goto done;
	}
	if (strcasecmp("sha384"  , dgstname) == 0) {
		id = SSH_MD_EC_SHA384; goto done; }
#endif
#ifdef OPENSSL_HAS_NISTP521
	if (strcasecmp("ssh-sha512"  , dgstname) == 0) {
		id = SSH_MD_EC_SHA512_SSH; goto done;
	}
	if (strcasecmp("sha512"  , dgstname) == 0) {
		id = SSH_MD_EC_SHA512; goto done; }
#endif

	if (strcasecmp("dss-asn1", dgstname) == 0) {
		id = SSH_MD_DSA_SHA1; goto done; }
	if (strcasecmp("dss-raw" , dgstname) == 0) {
		id = SSH_MD_DSA_RAW; goto done; }

#ifdef HAVE_EVP_DIGESTSIGN
	if (strcasecmp("none", dgstname) == 0) {
		id = SSH_MD_NONE; goto done; }
#endif

	return -1;

done:
	p->dgst = ssh_evp_md_find(id);

	return 0;
}


int
ssh_add_x509key_alg(const char *data) {
	char *name, *mdname, *signame;
	SSHX509KeyAlgs* p;
	int nid = -1;

	if (data == NULL) {
		error_f("data is NULL");
		return(-1);
	}

	name = xstrdup(data); /*fatal on error*/

	mdname = strchr(name, ',');
	if (mdname == NULL) {
		error_f("cannot parse digest");
		goto err;
	}
	*mdname++ = '\0';

	signame = strchr(mdname, ',');
	if (signame != NULL) *signame++ = '\0';

	initialize_xkalg();
	p = x509keyalgs;
	{
		int k = sizeof(x509keyalgs) / sizeof(x509keyalgs[0]);

		for (; k > 0; k--, p++) {
			if (p->name == NULL) break;
		}
		if (k <= 0) {
			error_f("insufficient slots");
			goto err;
		}
	}

	if (strncmp(name, "x509v3-ecdsa-sha2-", 18) == 0) {
		const char *ec_name = name + 18;

		nid = sshkey_curve_name_to_nid(ec_name);
		if (nid < 0) {
			fatal_f("unsupported curve %s", ec_name);
		}

		p->basetype = KEY_ECDSA;
		p->chain = 1;
	} else
#ifdef HAVE_EVP_SHA256
	if (strcmp(name, "x509v3-rsa2048-sha256") == 0) {
		p->basetype = KEY_RSA;
		p->chain = 1;
	} else
#endif
	if (strncmp(name, "x509v3-ssh-rsa", 14) == 0) {
		p->basetype = KEY_RSA;
		p->chain = 1;
	} else
	if (strncmp(name, "x509v3-sign-rsa", 15) == 0) {
		p->basetype = KEY_RSA;
		p->chain = 0;
	} else
	if (strncmp(name, "x509v3-ssh-dss", 14) == 0) {
		p->basetype = KEY_DSA;
		p->chain = 1;
	} else
	if (strncmp(name, "x509v3-sign-dss", 15) == 0) {
		p->basetype = KEY_DSA;
		p->chain = 0;
	} else
#ifdef OPENSSL_HAS_ED25519
	if (strncmp(name, "x509v3-ssh-ed25519", 18) == 0) {
		p->basetype = KEY_ED25519;
		p->chain = 1;
	} else
#endif
	{
		error_f("unsupported public key algorithm '%s'", name);
		goto err;
	}

	if (ssh_x509key_alg_digest(p, mdname) < 0) {
		error_f("unsupported digest %.50s", mdname);
		goto err;
	}

#ifdef OPENSSL_FIPS
	if (FIPS_mode()) {
		if ((EVP_MD_flags(p->dgst->md()) & EVP_MD_FLAG_FIPS) == 0) {
			error_f("%s in not enabled in FIPS mode ", mdname);
			goto err;
		}
	}
#endif
	p->name = name;
	p->signame = signame;
	p->subtype = nid;

	return (1);

err:
	free((void*)name);
	return (-1);
}


int/*bool*/
ssh_is_x509signame(const char *signame) {
	SSHX509KeyAlgs *xkalg;
	int k;

	if (signame == NULL) {
		fatal_f("signame is NULL");
		return(0); /*unreachable code*/
	}

	initialize_xkalg();
	xkalg = x509keyalgs;
	k = sizeof(x509keyalgs) / sizeof(x509keyalgs[0]);

	for (; k > 0; k--, xkalg++) {
		if (xkalg->name == NULL) return(0);
		if (strcmp(signame, X509PUBALG_SIGNAME(xkalg)) == 0) return(1);
	}
	return(0);
}


int
ssh_xkalg_nameind(const char *name, const SSHX509KeyAlgs **q, int loc) {
	int k, n;
	const SSHX509KeyAlgs *p;

	if (name == NULL) return (-1);

	initialize_xkalg();
	k = (loc < 0) ? 0 : (loc + 1);
	n = sizeof(x509keyalgs) / sizeof(x509keyalgs[0]);
	if (k < n) p = &x509keyalgs[k];

	for (; k < n; k++, p++) {
		if (p->name == NULL) return(-1);
		if (strcmp(p->name, name) == 0) {
			if (q) *q = p;
			return(k);
		}
	}
	return(-1);
}


static int
ssh_xkalg_typeind(int type, int subtype, const SSHX509KeyAlgs **q, int loc) {
	int k, n;
	const SSHX509KeyAlgs *p;

	initialize_xkalg();
	k = (loc < 0) ? 0 : (loc + 1);
	n = sizeof(x509keyalgs) / sizeof(x509keyalgs[0]);
	if (k < n) p = &x509keyalgs[k];

	type = sshkey_type_plain(type);
	for (; k < n; k++, p++) {
		if (p->name == NULL) break;
		if (type != p->basetype) continue;

		if ((subtype > 0) && (subtype != p->subtype))
			continue;

		if (q) *q = p;
		return(k);
	}
	return(-1);
}


int
ssh_xkalg_keyind(const struct sshkey *key, const SSHX509KeyAlgs **q, int loc) {
	return ssh_xkalg_typeind(key->type, key->ecdsa_nid, q, loc);
}


int
ssh_xkalg_keyfrmind(const struct sshkey *key, int frm, const SSHX509KeyAlgs **q, int loc) {

	while ((loc = ssh_xkalg_typeind(key->type, key->ecdsa_nid, q, loc)) >= 0) {
		int found = 0;

		switch (frm) {
		case X509FORMAT_FIRSTMATCH: found = 1;
			break;
		case X509FORMAT_LEGACY    : found = !(*q)->chain;
			break;
		case X509FORMAT_RFC6187   : found = (*q)->chain;
			break;
		}
		if (found) break;
	}
	return(loc);
}


int
ssh_xkalg_ind(const SSHX509KeyAlgs **q, int loc) {
	int k, n;

	initialize_xkalg();
	k = (loc < 0) ? 0 : (loc + 1);
	n = sizeof(x509keyalgs) / sizeof(x509keyalgs[0]);

	if (k < n) {
		const SSHX509KeyAlgs *p;

		p = &x509keyalgs[k];
		if (p->name != NULL) {
			if (q) *q = p;
			return(k);
		}
	}
	return(-1);
}


static void
ssh_xkalg_list(int type, struct sshbuf *b, const char *sep) {
	const SSHX509KeyAlgs *xkalg;
	int loc;
	int seplen;

	if (b == NULL) {
		error_f("buffer is NULL");
		return;
	}

/*
IMPORTANT NOTE:
  For every unique "key name" we MUST define unique "key type"
otherwise cannot distinguish them !
As example structure Kex contain integer attribute "kex_type"
and kex use method "load_host_key" to find hostkey. When client
request hostkey algorithms (comma separated list with names)
server should be able to find first hostkey that match one of them.
Note to "load_host_key" is assigned method "get_hostkey_by_type"
defined in "sshd.c".
*/

	if (sep == NULL) sep = ",";
	seplen = strlen(sep);

	for (
	    loc = ssh_xkalg_typeind(type, -1, &xkalg, -1);
	    loc >= 0;
	    loc = ssh_xkalg_typeind(type, -1, &xkalg, loc)
	) {
		const char *p;
		int dupl, k, r;

		/* exclude duplicate names */
		p = xkalg->name;
		dupl = 0;
		for (
		    k = ssh_xkalg_typeind(type, -1, &xkalg, -1);
		    (k >= 0) && (k < loc);
		    k = ssh_xkalg_typeind(type, -1, &xkalg, k)
		) {
			if (strcmp(p, xkalg->name) == 0) {
				dupl = 1;
				break;
			}
		}
		if (dupl) continue;

		if (sshbuf_len(b) > 0) {
			if ((r = sshbuf_put(b, sep, seplen)) != 0)
				fatal_fr(r, "buffer error");
		}
		if ((r = sshbuf_put(b, p, strlen(p))) != 0)
			fatal_fr(r, "buffer error");
	}
}


void
ssh_xkalg_listall(struct sshbuf *b, const char *sep) {
	ssh_xkalg_list(KEY_ECDSA, b, sep);
	ssh_xkalg_list(KEY_RSA, b, sep);
	ssh_xkalg_list(KEY_DSA, b, sep);
#ifdef OPENSSL_HAS_ED25519
	ssh_xkalg_list(KEY_ED25519, b, sep);
#endif
}


char*
default_hostkey_algorithms(void) {
	struct sshbuf *b;
	char *p;
	int r;

	b = sshbuf_new();
	if (b == NULL)
		fatal_f("sshbuf_new failed");

	ssh_xkalg_listall(b, ",");


{	char *allalgs = sshkey_alg_list(0, 0, 1, ',');
	/* NOTE
	 * - Define KEX_DEFAULT_PK_ALG list only key-based
	 *   algorithms (in order of precedence).
	 * - Since PKIX-SSH 12.4 KEX_DEFAULT_PK_ALG list even
	 *   unsupported algorithms!
	 * - Since PKIX-SSH 8.5 ssh-dss is not listed by default.
	 */
	/* filter unsupported by build */
	p = match_filter_allowlist(KEX_DEFAULT_PK_ALG",ssh-dss", allalgs);
	free(allalgs);
}

	if ((r = sshbuf_put(b, ",", 1)) != 0 ||
	    (r = sshbuf_put(b, p, strlen(p))) != 0)
		fatal_fr(r, "buffer error");

	p = xstrdup(sshbuf_ptr(b));

	sshbuf_free(b);

	return p;
}


char*
ssh_get_allnames(char sep, int sigflag, const char* pattern) {
	const char **list = NULL;;
	int loc;
	size_t k, n = 0, len = 0;

	if (pattern == NULL) pattern= "*";

{	const SSHX509KeyAlgs *xkalg;
	for (
	    loc = ssh_xkalg_ind(&xkalg, -1);
	    loc >= 0;
	    loc = ssh_xkalg_ind(&xkalg, loc)
	) {
		const char *p;

		if (match_pattern_list(xkalg->name, pattern, 0) != 1)
			continue;

		p = sigflag ? X509PUBALG_SIGNAME(xkalg) : xkalg->name;
		for (k = 0; k < n; k++) {
			if (strcmp(p, list[k]) == 0) {
				p = NULL;
				break;
			}
		}
		if (p == NULL) continue;

		k = n++;
		list = realloc(list, n * sizeof(char*));
		if (list == NULL)
			fatal_f("realloc fail for xkalg");
		list[k] = p;
		len += 1 + strlen(p);
	}
}
{	const char *name;
	/*
	 * According RFC8308 protocol extension "server-sig-algs",
	 * despite of it name, list public key algorithms that the
	 * server is able to process.
	 * OpenBSD version is still broken and does not list algorithms
	 * that use custom certificates. Broken behaviour will be keep
	 * until is fixed in OpenBSD version. Note that brokenness is
	 * keep as well in check for allowed keys - see sshconnect2.c
	 * function try_identity().
	 */
	for (
	    loc = sshkey_algind(&name, SSHKEY_ALG_PLAINKEY, -1);
	    loc >= 0;
	    loc = sshkey_algind(&name, SSHKEY_ALG_PLAINKEY, loc)
	) {
		const char *p;

		if (match_pattern_list(name, pattern, 0) != 1)
			continue;

		p = name;
		for (k = 0; k < n; k++) {
			if (strcmp(p, list[k]) == 0) {
				p = NULL;
				break;
			}
		}
		if (p == NULL) continue;

		k = n++;
		list = realloc(list, n * sizeof(char*));
		if (list == NULL)
			fatal_f("realloc fail for alg");
		list[k] = p;
		len += 1 + strlen(p);
	}
}
{	char *s = NULL, *p;

	if (n > 0) {
		s = p = malloc(len);
		if (s == NULL)
			fatal_f("out of memory");
	}
	for (k = 0; k < n; k++) {
		size_t l = strlen(list[k]);
		memmove(p, list[k], l);
		p += l;
		*p++ = sep;
	}
	if (n > 0)
		*(--p) = '\0';

	free(list);
	return s;
}
}
