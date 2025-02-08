#ifdef __ANDROID__
/*
 * Copyright (c) 2016-2025 Roumen Petrov.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in the
 *       documentation and/or other materials provided with the distribution.
 *     * Neither the name of the <organization> nor the
 *       names of its contributors may be used to endorse or promote products
 *       derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL <COPYRIGHT HOLDER> BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "includes.h"
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "pathnames.h"
extern char *__progname;

#ifndef USE_LIBAPPWRAP
/* paths to application specific directories: */
extern char *get2_app_etcdir(const char *cmd);
extern char *get2_app_bindir(const char *cmd);
extern char *get2_app_libexecdir(const char *cmd);

static inline char*
get_app_etcdir(void) {
	return get2_app_etcdir(__progname);
}

static inline char*
get_app_bindir(void) {
	return get2_app_bindir(__progname);
}

static inline char*
get_app_libexecdir(void) {
	return get2_app_libexecdir(__progname);
}
#endif /*ndef USE_LIBAPPWRAP*/

/* Obsolete package rule:
 * Note it is expected binaries to be installed in $(prefix)/xbin.
 * In $(prefix)/bin is installed wrapper script that set custom configuration
 * like library patch and etc. and then execute real binary.
 *
 * API 29 requirement: untrusted application could execute binary
 * located only in write protected path (SELinux rule). Only
 * application library directory is write protected, so executable
 * could be installed only into this directory.
 * Also it must be renamed to libcmd-{name}.so for various reasons.
 */

char*
ssh_get_progname(char *argv0) {
	char *p, *q;

	UNUSED(argv0);

	q = strdup(__progname);
	p = strrchr(q, '/');
	if (p != NULL) /*just in case*/
		*p++ = '\0';
	else
		p = q;

	/* strip prefix */
	if (strncmp(p, "libcmd-", 7) == 0)
		p += 7;

	p = strdup(p);
	if (p == NULL) {
		perror("strdup");
		exit(1);
	}
	free(q);

{	/* strip suffix */
	size_t len = strlen(p);
	if (len > 3) {
		q = p + len - 3;
		if (strcmp(q, ".so") == 0)
			*q = '\0';
	}
}

	return p;
}


/* bionic stub replacement
 *
 * The  function ttyname() returns a pointer to a pathname on success.
 * On error, NULL is returned, and errno is set appropriately.
 */
char*
android_ttyname(int fd) {
	static char buf[PATH_MAX];

	return (android_ttyname_r(fd, buf, sizeof(buf)) == 0)
		? buf
		: NULL;
}


/* bionic stub replacement
 *
 * The function ttyname_r() returns 0 on success, and an error number
 * upon error.
 */
int
android_ttyname_r(int fd, char *buf, size_t buflen) {
	ssize_t k;

	if (buf == NULL) {
		errno = EINVAL;
		return errno;
	}
	if (buflen < 6) { /* "/dev/" + NUL */
		errno = ERANGE;
		return errno;
	}

	if (!isatty(fd)) {
		return errno;
	}

{
	char proc_fd[PATH_MAX];
	snprintf(proc_fd, sizeof(proc_fd), "/proc/self/fd/%d", fd);
	/*NOTE on error content of buf is undefined*/
	k = readlink(proc_fd, buf, buflen);
}

	if (k == -1)
		return errno;

	if ((size_t)k == buflen) {
		errno = ERANGE;
		return errno;
	}
	buf[k] = '\0';
	return 0;
}


/* Function endgrent is declared in platform header <grp.h>,
 * but not defined until API 26.
 * Unified header <pwd.h> does not declare it before API 26.
 */
void
endgrent(void) {
}

/* Function endpwent is declared in platform header <pwd.h>,
 * but not defined until API 26.
 * Unified header <pwd.h> does not declare it before API 26.
 */
void
endpwent(void) {
}


/* For untrusted applications new Android SELinux rules (API 29)
 * allows execution only from write protected directories.
 * Only application library directory is write protected.
 * In consequence executable must be packaged into it and with
 * name is a specific pattern.
 */
#ifndef USE_LIBAPPWRAP
/* On old versions for some reasons application could install
 * executable outside libdir.
 * So instead to relocate executable to "lib" directory let
 * relocate "bin" and "libexec".
 */
static int/*bool*/
relocate_etcdir(const char *pathname, char *pathbuf, size_t pathlen) {
	size_t len = strlen(SSHDIR);

	if (pathlen <= len) return 0;
	if (strncmp(pathname, SSHDIR, len) != 0) return 0;

{	const char *appdir = NULL;
	if (appdir == NULL) appdir = get_app_etcdir();
	if (appdir == NULL) return 0;

	len = snprintf(pathbuf, pathlen, "%s%s", appdir, pathname + len);
}

	return len <= pathlen;
}

static int/*bool*/
relocate_bindir(const char *pathname, char *pathbuf, size_t pathlen) {
	size_t len = strlen(SSHBINDIR);

	if (pathlen <= len) return 0;
	if (strncmp(pathname, SSHBINDIR, len) != 0) return 0;

{	static const char *appdir = NULL;
	if (appdir == NULL) appdir = get_app_bindir();
	if (appdir == NULL) return 0;

	/* in release build package manager extract only lib*.so
	 * binaries. To distinguish executables let package them
	 * in format "libcmd-{name}.so".
	 */
	len = snprintf(pathbuf, pathlen, "%s/libcmd-%s.so",
	    appdir, pathname + len + 1/*exclude separator*/);
}

	return len <= pathlen;
}

static int/*bool*/
relocate_libexecdir(const char *pathname, char *pathbuf, size_t pathlen) {
	size_t len = strlen(SSHLIBEXECDIR);

	if (pathlen <= len) return 0;
	if (strncmp(pathname, SSHLIBEXECDIR, len) != 0) return 0;

{	static const char *appdir = NULL;
	if (appdir == NULL) appdir = get_app_libexecdir();
	if (appdir == NULL) return 0;

	/* same as bindir */
	len = snprintf(pathbuf, pathlen, "%s/libcmd-%s.so",
	    appdir, pathname + len + 1/*exclude separator*/);
}

	return len <= pathlen;
}

static const char*
relocate_path(const char *pathname, char *pathbuf, size_t pathlen) {

	if (relocate_etcdir(pathname, pathbuf, pathlen) ||
	    relocate_bindir(pathname, pathbuf, pathlen) ||
	    relocate_libexecdir(pathname, pathbuf, pathlen)) {
		return pathbuf;
	}

	return pathname;
}
#endif /*ndef USE_LIBAPPWRAP*/


const char*
get_ssh_binary_path(void) {
	const char *pathname = SSHBINDIR "/ssh";
	static char pathbuf[PATH_MAX] = "\0";

	if (*pathbuf != '\0') return pathbuf;
#ifndef USE_LIBAPPWRAP
	if (relocate_bindir(pathname, pathbuf, sizeof(pathbuf)))
		return pathbuf;
#else
{	static const char ssh_utility[] = "libcmd-ssh.so";
	ssize_t len;
	char *s;

	len = readlink("/proc/self/exe", pathbuf, sizeof(pathbuf));
	if (len == -1) goto err;
	if (len == (ssize_t)sizeof(pathbuf)) goto err;
	pathbuf[len] = '\0';

	s = strrchr(pathbuf, '/');
	if (s == NULL) goto err;
	*++s = '\0';

	len = strlen(ssh_utility) + 1/*terminating NUL character*/;
	if (strlen(pathbuf) > (sizeof(pathbuf) - len)) goto err;

	memcpy(s, ssh_utility, len);
	return pathbuf;

err:
	*pathbuf = '\0';
}
#endif
	return pathname;
}


extern int appcmd_open(const char *path, int flags, mode_t mode);
extern int __real_open(const char *path, int flags, mode_t mode);

int
__wrap_open(const char *path, int flags, mode_t mode) {
#ifndef USE_LIBAPPWRAP
	char r_path[PATH_MAX];

	path = relocate_path(path, r_path, sizeof(r_path));
	return __real_open(path, flags, mode);
#else
	int ret;
	int oerrno;

	oerrno = errno;
	ret = appcmd_open(path, flags, mode);
	if ((ret == -1) && (errno == ENOSYS)) {
		errno = oerrno;
		ret = __real_open(path, flags, mode);
	}
	return ret;
#endif
}


extern FILE *appcmd_fopen(const char *path, const char *mode);
extern FILE* __real_fopen(const char *path, const char *mode);

FILE*
__wrap_fopen(const char *path, const char *mode) {
#ifndef USE_LIBAPPWRAP
	char r_path[PATH_MAX];

	path = relocate_path(path, r_path, sizeof(r_path));
	return  __real_fopen(path, mode);
#else
	FILE* ret;
	int oerrno;

	oerrno = errno;
	ret = appcmd_fopen(path, mode);
	if ((ret == NULL) && (errno == ENOSYS)) {
		errno = oerrno;
		ret = __real_fopen(path, mode);
	}
	return ret;
#endif
}


#ifndef USE_LIBAPPWRAP
extern int __real_rename(const char *oldpath, const char *newpath);

int
__wrap_rename(const char *oldpath, const char *newpath) {
	char r_oldpath[PATH_MAX], r_newpath[PATH_MAX];

	oldpath = relocate_path(oldpath, r_oldpath, sizeof(r_oldpath));
	newpath = relocate_path(newpath, r_newpath, sizeof(r_newpath));

	return __real_rename(oldpath, newpath);
}
#endif


#ifdef USE_LIBAPPWRAP
int/*bool*/
relocate_etcdir(const char *pathname, char *pathbuf, size_t pathlen) {
	size_t len = strlen(SSHDIR);

	if (pathlen <= len) return 0;
	if (strncmp(pathname, SSHDIR, len) != 0) return 0;

{	const char *appdir = NULL;
	if (appdir == NULL) appdir = getenv("SSH_SYSCONFDIR");
	if (appdir == NULL) return 0;

	len = snprintf(pathbuf, pathlen, "%s%s", appdir, pathname + len);
}

	return len <= pathlen;
}
#endif


/* Fake user for android */
#include "xmalloc.h"
#include <fcntl.h>
#include <openssl/des.h>
#undef getpwnam
#undef getpwuid
/* Remove inappropriate definition from android unified headers! */
#undef pw_gecos

/* Note _PATH_PASSWD is defined in platform headers but not in unified.
 * Force use of local declaration for consistency.
 */
#undef _PATH_PASSWD
#define _PATH_PASSWD	 "/etc/passwd"


static struct passwd *fake_passwd = NULL;
static char *ssh_home = NULL;
static char *ssh_shell = NULL;


static void
parse_fake_passwd(void) {
	char *pw_name;
	char *pw_passwd;
	char *pw_uid;
	char *pw_gid;
	char *pw_gecos;
	char *pw_dir;
	char *pw_shell = NULL;

	int   fd = -1;

{	const char *path = _PATH_PREFIX _PATH_PASSWD;

	fd = open(path, O_RDONLY);
	if (fd == -1)
		return;
}

{	/* parse password line */
	char buf[1024], *s;

	if (read(fd, buf, sizeof(buf)) <= 0) {
		close(fd);
		return;
	}

	if ((s = strchr(buf, '\r')) != NULL) *s = '\0';
	if ((s = strchr(buf, '\n')) != NULL) *s = '\0';
	if ((s = strchr(buf, '\t')) != NULL) *s = '\0';
	if ((s = strchr(buf, ' ' )) != NULL) *s = '\0';

	s = buf;

	pw_name = s;
	if (*pw_name == '\0') goto parse_err;
	s = strchr(s, ':'); if (s == NULL) goto parse_err;
	*s = '\0';

	pw_passwd = ++s;
	if (*pw_passwd == '\0') goto parse_err;
	s = strchr(s, ':'); if (s == NULL) goto parse_err;
	*s = '\0';

	pw_uid = ++s;
	s = strchr(s, ':'); if (s == NULL) goto parse_err;
	*s = '\0';

	pw_gid = ++s;
	s = strchr(s, ':'); if (s == NULL) goto parse_err;
	*s = '\0';

	pw_gecos = ++s;
	s = strchr(s, ':'); if (s == NULL) goto parse_err;
	*s = '\0';

	pw_dir = ++s;
	if (*pw_dir == '\0') goto parse_err;
	s = strchr(s, ':'); if (s == NULL) goto parse_err;
	*s = '\0';

	pw_shell = ++s;

parse_err:
	close(fd);
}

	if (pw_shell == NULL) return;

{	/* preset password data */
	char *s;

	s = strdup(pw_name);
	if (s != NULL)
		fake_passwd->pw_name = s;

	s = strdup(pw_passwd);
	if (s != NULL)
		fake_passwd->pw_passwd = s;

	(void) pw_uid;
	(void) pw_gid;
#ifdef __LP64__
	fake_passwd->pw_gecos = strdup(pw_gecos);
#else
	(void) pw_gecos;
#endif

	if (strcmp(pw_dir, "$HOME") == 0)
		pw_dir = getenv("HOME");
	if ((pw_dir != NULL) && (*pw_dir != '\0'))
		ssh_home = strdup(pw_dir);
	if (ssh_home != NULL)
		fake_passwd->pw_dir = ssh_home;

	if (strcmp(pw_shell, "$SHELL") == 0)
		pw_shell = getenv("SHELL");
	if ((pw_shell != NULL) && (*pw_shell != '\0'))
		ssh_shell = strdup(pw_shell);
	if (ssh_shell != NULL)
		fake_passwd->pw_shell = ssh_shell;
}
}


static void
init_fake_passwd(void) {

	if (fake_passwd != NULL) return;

{
	struct passwd* pw;
	size_t n;

	pw = getpwuid(getuid());
	if (pw == NULL) return;

	n = sizeof(*fake_passwd);
	fake_passwd = calloc(1, n);
	if (fake_passwd == NULL) return;

	memcpy(fake_passwd, pw, n);
}

	parse_fake_passwd();
}


static struct passwd*
preset_passwd(struct passwd *pw) {
	if (pw == NULL) return NULL;

#ifdef __LP64__
	/* usually not initialized but code expect string value */
	if (pw->pw_gecos == NULL)
		pw->pw_gecos = fake_passwd->pw_gecos;
#endif

	if (ssh_home != NULL)
		pw->pw_dir = ssh_home;

	if (ssh_shell != NULL)
		pw->pw_shell = ssh_shell;

	return pw;
}


/* bionic replacement */
struct passwd*
android_getpwnam(const char* name) {
	struct passwd* pw;

	init_fake_passwd();

	if ((fake_passwd != NULL) && (strcmp(name, fake_passwd->pw_name) == 0))
		return fake_passwd;

	pw = getpwnam(name);

	return preset_passwd(pw);
}


/* bionic replacement */
struct passwd*
android_getpwuid(uid_t uid) {
	struct passwd* pw;

	init_fake_passwd();

	if ((fake_passwd != NULL) && (uid == fake_passwd->pw_uid))
		return fake_passwd;

	pw = getpwuid(uid);

	return preset_passwd(pw);
}


#else

static void *empty_translation_unit = &empty_translation_unit;

#endif /*def __ANDROID__*/
