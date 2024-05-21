/*
 * Copyright (c) 2012,2023 Damien Miller <djm@mindrot.org>
 * Copyright (c) 2024 Roumen Petrov.  All rights reserved.
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

#include <string.h>

#include "hostfile.h" /*required by "auth.h"*/
#include "misc.h" /*required by "auth.h"*/
#include "auth.h"
#include "log.h" /*required by "servconf.h" as well*/
#include "servconf.h"
#include "xmalloc.h"

extern ServerOptions options;

/*
 * Configuration of enabled authentication methods. Separate to the rest of
 * auth2-*.c because we want to query it during server configuration validity
 * checking in the sshd listener process without pulling all the auth code in
 * too.
 */

/* "none" is allowed only one time and it cleared by userauth_none() later */
int none_enabled = 1;
struct authmethod_cfg methodcfg_none = {
	"none",
	&none_enabled
};
struct authmethod_cfg methodcfg_pubkey = {
	"publickey",
	&options.pubkey_authentication
};
#ifdef GSSAPI
struct authmethod_cfg methodcfg_gssapi = {
	"gssapi-with-mic",
	&options.gss_authentication
};
#endif
struct authmethod_cfg methodcfg_passwd = {
	"password",
	&options.password_authentication
};
struct authmethod_cfg methodcfg_kbdint = {
	"keyboard-interactive",
	&options.kbd_interactive_authentication
};
struct authmethod_cfg methodcfg_hostbased = {
	"hostbased",
	&options.hostbased_authentication
};

static struct authmethod_cfg *authmethod_cfgs[] = {
	&methodcfg_none,
	&methodcfg_pubkey,
#ifdef GSSAPI
	&methodcfg_gssapi,
#endif
	&methodcfg_passwd,
	&methodcfg_kbdint,
	&methodcfg_hostbased,
	NULL
};

/*
 * Check a comma-separated list of methods for validity. Is need_enable is
 * non-zero, then also require that the methods are enabled.
 * Returns 0 on success or -1 if the methods list is invalid.
 */
int
auth2_methods_valid(const char *_methods, int need_enable)
{
	char *methods, *omethods, *method, *p;
	u_int i, found;
	int ret = -1;

	if (*_methods == '\0') {
		error("empty authentication method list");
		return -1;
	}
	omethods = methods = xstrdup(_methods);
	while ((method = strsep(&methods, ",")) != NULL) {
		for (found = i = 0; !found && authmethod_cfgs[i] != NULL; i++) {
			struct authmethod_cfg *cfg = authmethod_cfgs[i];

			if ((p = strchr(method, ':')) != NULL)
				*p = '\0';
			if (strcmp(method, cfg->name) != 0)
				continue;
			if (need_enable) {
				if (cfg->enabled == NULL ||
				    *(cfg->enabled) == 0) {
					error("Disabled method \"%s\" in "
					    "AuthenticationMethods list \"%s\"",
					    method, _methods);
					goto out;
				}
			}
			found = 1;
			break;
		}
		if (!found) {
			error("Unknown authentication method \"%s\" in list",
			    method);
			goto out;
		}
	}
	ret = 0;
 out:
	free(omethods);
	return ret;
}
