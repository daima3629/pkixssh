/* $OpenBSD: sshd-auth.c,v 1.2 2024/12/03 22:30:03 jsg Exp $ */
/*
 * SSH2 implementation:
 * Privilege Separation:
 *
 * Copyright (c) 2000, 2001, 2002 Markus Friedl.  All rights reserved.
 * Copyright (c) 2002 Niels Provos.  All rights reserved.
 * Copyright (c) 2002-2024 Roumen Petrov.  All rights reserved.
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


static void
append_hostkey_type(struct sshbuf *b, const char *s)
{
	int r;

	if (match_pattern_list(s, options.hostkeyalgorithms, 0) != 1) {
		debug3_f("%s key not permitted by HostkeyAlgorithms", s);
		return;
	}
	if ((r = sshbuf_putf(b, "%s%s", sshbuf_len(b) > 0 ? "," : "", s)) != 0)
		fatal_fr(r, "sshbuf_putf");
}

static void
add_hostkey_algoritms(int k, struct sshbuf *b) {
	const char **algs;

	algs = sensitive_data.host_algorithms[k];
	if (algs == NULL) {
		debug("no suitable algorithms for host key %d", k);
		return;
	}

	for (; *algs != NULL; algs++) {
		const char *pkalg = *algs;

		/* Check that the key is accepted in HostkeyAlgorithms */
		if (match_pattern_list(pkalg,
		    options.hostkeyalgorithms, 0) != 1
		) {
			debug3_f("%s not permitted by "
				"HostkeyAlgorithms for key %d",
				pkalg, k);
			continue;
		}

		if (sshbuf_len(b) > 0) {
			if (sshbuf_put(b, ",", 1) != 0)
				goto err;
		}
		if (sshbuf_put(b, pkalg, strlen(pkalg)) != 0)
			goto err;
	}

	return;
err:
	fatal("cannot prepare hotkey algorithm list");
}

static char *
list_hostkey_types(void)
{
	struct sshbuf *b;
	struct sshkey *key;
	char *ret;
	u_int i;

	if ((b = sshbuf_new()) == NULL)
		fatal_f("sshbuf_new failed");
	for (i = 0; i < options.num_host_key_files; i++) {
		key = sensitive_data.host_keys[i];
		if (key == NULL)
			key = sensitive_data.host_pubkeys[i];
		if (key == NULL)
			continue;

		add_hostkey_algoritms(i, b);

		/* If the private key has a cert peer, then list that too */
		key = sensitive_data.host_certificates[i];
		if (key == NULL)
			continue;
		switch (key->type) {
		case KEY_RSA_CERT:
			/* for RSA we also support SHA2 signatures */
			append_hostkey_type(b,
			    "rsa-sha2-256-cert-v01@openssh.com");
			append_hostkey_type(b,
			    "rsa-sha2-512-cert-v01@openssh.com");
			/* FALLTHROUGH */
	#ifdef WITH_DSA
		case KEY_DSA_CERT:
	#endif
		case KEY_ECDSA_CERT:
		case KEY_ED25519_CERT:
	#ifdef WITH_XMSS
		case KEY_XMSS_CERT:
	#endif
			append_hostkey_type(b, sshkey_ssh_name(key));
			break;
		}
	}
	if ((ret = sshbuf_dup_string(b)) == NULL)
		fatal_f("sshbuf_dup_string failed");
	sshbuf_free(b);
	debug_f("%s", ret);
	return ret;
}
