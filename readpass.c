/* $OpenBSD: readpass.c,v 1.68 2020/11/10 07:46:20 claudio Exp $ */
/*
 * Copyright (c) 2001 Markus Friedl.  All rights reserved.
 * Copyright (c) 2019-2020 Roumen Petrov.  All rights reserved.
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
#include <sys/wait.h>

#include <errno.h>
#include <fcntl.h>
#ifdef HAVE_PATHS_H
# include <paths.h>
#endif
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "xmalloc.h"
#include "misc.h"
#include "pathnames.h"
#include "log.h"
#include "ssh.h"

static char *
ssh_askpass(const char *askpass, const char *msg, const char *env_hint)
{
	pid_t pid, ret;
	size_t len;
	char *pass;
	int p[2], status;
	char buf[1024];
	void (*osigchld)(int);

	if (fflush(stdout) != 0)
		error_f("fflush: %s", strerror(errno));
	if (askpass == NULL)
		fatal("internal error: askpass undefined");
	if (pipe(p) == -1) {
		error_f("pipe: %s", strerror(errno));
		return NULL;
	}
	osigchld = ssh_signal(SIGCHLD, SIG_DFL);
	if ((pid = fork()) == -1) {
		error_f("fork: %s", strerror(errno));
		ssh_signal(SIGCHLD, osigchld);
		return NULL;
	}
	if (pid == 0) {
		close(p[0]);
		if (dup2(p[1], STDOUT_FILENO) == -1)
			fatal_f("dup2: %s", strerror(errno));
		if (env_hint != NULL)
			setenv("SSH_ASKPASS_PROMPT", env_hint, 1);
		execlp(askpass, askpass, msg, (char *)NULL);
		fatal_f("exec(%s): %s", askpass, strerror(errno));
	}
	close(p[1]);

	len = 0;
	do {
		ssize_t r = read(p[0], buf + len, sizeof(buf) - 1 - len);

		if (r == -1 && errno == EINTR)
			continue;
		if (r <= 0)
			break;
		len += r;
	} while (sizeof(buf) - 1 - len > 0);
	buf[len] = '\0';

	close(p[0]);
	while ((ret = waitpid(pid, &status, 0)) == -1)
		if (errno != EINTR)
			break;
	ssh_signal(SIGCHLD, osigchld);
	if (ret == -1 || !WIFEXITED(status) || WEXITSTATUS(status) != 0) {
		explicit_bzero(buf, sizeof(buf));
		return NULL;
	}

	buf[strcspn(buf, "\r\n")] = '\0';
	pass = xstrdup(buf);
	explicit_bzero(buf, sizeof(buf));
	return pass;
}

/* private/internal read_passphrase flags */
#define RP_ASK_PERMISSION	0x8000 /* pass hint to askpass for confirm UI */

/*
 * Reads a passphrase from /dev/tty with echo turned off/on.  Returns the
 * passphrase (allocated with xmalloc).  Exits if EOF is encountered. If
 * RP_ALLOW_STDIN is set, the passphrase will be read from stdin if no
 * tty is available
 */
char *
read_passphrase(const char *prompt, int flags)
{
	char *ret;
	int rppflags, use_askpass = 0, allow_askpass;
	const char *s;

#ifdef __ANDROID__
	allow_askpass = 1;
#else
	s = getenv("DISPLAY");
	allow_askpass = (s != NULL) && (*s != '\0');
#endif
	s = getenv(SSH_ASKPASS_REQUIRE_ENV);
	if (s != NULL) {
		if (strcasecmp(s, "force") == 0) {
			use_askpass = 1;
			allow_askpass = 1;
		} else if (strcasecmp(s, "prefer") == 0)
			use_askpass = allow_askpass;
		else if (strcasecmp(s, "never") == 0)
			allow_askpass = 0;
	}

	rppflags = (flags & RP_ECHO) ? RPP_ECHO_ON : RPP_ECHO_OFF;
	if (use_askpass)
		debug_f("requested to askpass");
	else if (flags & RP_USE_ASKPASS)
		use_askpass = 1;
	else if (flags & RP_ALLOW_STDIN) {
		if (!isatty(STDIN_FILENO)) {
			debug("read_passphrase: stdin is not a tty");
			use_askpass = 1;
		}
	} else {
		int ttyfd;
		rppflags |= RPP_REQUIRE_TTY;
		ttyfd = open(_PATH_TTY, O_RDWR);
		if (ttyfd != -1) {
			/*
			 * If we're on a tty, ensure that show the prompt at
			 * the beginning of the line. This will hopefully
			 * clobber any password characters the user has
			 * optimistically typed before echo is disabled.
			 */
			(void)write(ttyfd, "\r", 1);
			close(ttyfd);
		} else {
			debug("read_passphrase: can't open %s: %s", _PATH_TTY,
			    strerror(errno));
			use_askpass = 1;
		}
	}

#if 0	/* pointless in context of environment managed askpass */
	if ((flags & RP_USE_ASKPASS) && !allow_askpass)
		return (flags & RP_ALLOW_EOF) ? NULL : xstrdup("");
#endif

	if (use_askpass && allow_askpass) {
		const char *askpass = getenv(SSH_ASKPASS_ENV);
		const char *askpass_hint = NULL;

		if (askpass == NULL || *askpass == '\0')
			askpass = _PATH_SSH_ASKPASS;
		if ((flags & RP_ASK_PERMISSION) != 0)
			askpass_hint = "confirm";
		if ((ret = ssh_askpass(askpass, prompt, askpass_hint)) == NULL)
			if (!(flags & RP_ALLOW_EOF))
				return xstrdup("");
		return ret;
	}

{	char buf[1024];
	if (readpassphrase(prompt, buf, sizeof buf, rppflags) == NULL) {
		if (flags & RP_ALLOW_EOF)
			return NULL;
		return xstrdup("");
	}

	ret = xstrdup(buf);
	explicit_bzero(buf, sizeof(buf));
}
	return ret;
}

int
ask_permission(const char *fmt, ...)
{
	va_list args;
	char *p, prompt[1024];
	int allowed = 0;

	va_start(args, fmt);
	vsnprintf(prompt, sizeof(prompt), fmt, args);
	va_end(args);

	p = read_passphrase(prompt,
	    RP_USE_ASKPASS|RP_ALLOW_EOF|RP_ASK_PERMISSION);
	if (p != NULL) {
		/*
		 * Accept empty responses and responses consisting
		 * of the word "yes" as affirmative.
		 */
		if (*p == '\0' || *p == '\n' ||
		    strcasecmp(p, "yes") == 0)
			allowed = 1;
		free(p);
	}

	return (allowed);
}
