
/*
 * Copyright (c) 1999-2004 Damien Miller <djm@mindrot.org>
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
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include "includes.h"

#include <sys/types.h>
#ifdef HAVE_SYS_SELECT_H
# include <sys/select.h>
#endif
#ifdef HAVE_SYS_TIME_H
# include <sys/time.h>
#endif

#include <fcntl.h>
#include <string.h>
#include <signal.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <unistd.h>

#ifndef HAVE___PROGNAME
char *__progname;
#endif

#ifdef __ANDROID__
/* see port-android.c */
#else
/*
 * NB. duplicate __progname in case it is an alias for argv[0]
 * Otherwise it may get clobbered by setproctitle()
 */
char *ssh_get_progname(char *argv0)
{
	char *p, *q;
#ifdef HAVE___PROGNAME
	extern char *__progname;

	UNUSED(argv0);
	p = __progname;
#else
	if (argv0 == NULL)
		return ("unknown");	/* XXX */
	p = strrchr(argv0, '/');
	if (p == NULL)
		p = argv0;
	else
		p++;
#endif
	if ((q = strdup(p)) == NULL) {
		perror("strdup");
		exit(1);
	}

	return q;
}
#endif /*ndef __ANDROID__*/

#ifndef HAVE_SETLOGIN
int setlogin(const char *name)
{
	UNUSED(name);
	return (0);
}
#endif /* !HAVE_SETLOGIN */

#ifndef HAVE_INNETGR
int innetgr(const char *netgroup, const char *host,
	    const char *user, const char *domain)
{
	UNUSED(netgroup);
	UNUSED(host);
	UNUSED(user);
	UNUSED(domain);
	return (0);
}
#endif /* HAVE_INNETGR */

#if !defined(HAVE_SETEUID) && defined(HAVE_SETREUID)
int seteuid(uid_t euid)
{
	return (setreuid(-1, euid));
}
#endif /* !defined(HAVE_SETEUID) && defined(HAVE_SETREUID) */

#if !defined(HAVE_SETEGID) && defined(HAVE_SETRESGID)
int setegid(uid_t egid)
{
	return(setresgid(-1, egid, -1));
}
#endif /* !defined(HAVE_SETEGID) && defined(HAVE_SETRESGID) */

#if !defined(HAVE_STRERROR) && defined(HAVE_SYS_ERRLIST) && defined(HAVE_SYS_NERR)
const char *strerror(int e)
{
	extern int sys_nerr;
	extern char *sys_errlist[];

	if ((e >= 0) && (e < sys_nerr))
		return (sys_errlist[e]);

	return ("unlisted error");
}
#endif

#ifndef HAVE_UTIMES
int utimes(const char *filename, const struct timeval *tvp)
{
	struct utimbuf ub;

	ub.actime = tvp[0].tv_sec;
	ub.modtime = tvp[1].tv_sec;

	return (utime(filename, &ub));
}
#endif

#ifndef HAVE_UTIMENSAT
/*
 * A limited implementation of utimensat() that only implements the
 * functionality used by secsh, currently only AT_FDCWD and
 * AT_SYMLINK_NOFOLLOW.
 */
int
utimensat(int fd, const char *pathname, const struct timespec times[2],
    int flags)
{
	struct timeval tv[2];

	if (fd != AT_FDCWD) {
		errno = ENOSYS;
		return -1;
	}

	tv[0].tv_sec = times[0].tv_sec;
	tv[0].tv_usec = times[0].tv_nsec / 1000;
	tv[1].tv_sec = times[1].tv_sec;
	tv[1].tv_usec = times[1].tv_nsec / 1000;

# ifdef HAVE_FUTIMES
{	int ret, oflags = O_WRONLY;

#  ifdef O_NOFOLLOW
	if (flags & AT_SYMLINK_NOFOLLOW)
		oflags |= O_NOFOLLOW;
#  endif /* O_NOFOLLOW */
	if ((fd = open(pathname, oflags)) == -1)
		return -1;
	ret = futimes(fd, tv);
	close(fd);
	return ret;
}
# else
	UNUSED(flags);
	return utimes(pathname, tv);
# endif
}
#endif

#ifndef HAVE_FCHOWNAT
/*
 * A limited implementation of fchownat() that only implements the
 * functionality used by secsh, currently only AT_FDCWD and
 * AT_SYMLINK_NOFOLLOW.
 */
int
fchownat(int fd, const char *pathname, uid_t owner, gid_t group, int flags)
{
	if (fd != AT_FDCWD) {
		errno = ENOSYS;
		return -1;
	}
# ifdef HAVE_FCHOWN
{	int ret, oflags = O_WRONLY;

#  ifdef O_NOFOLLOW
	if (flags & AT_SYMLINK_NOFOLLOW)
		oflags |= O_NOFOLLOW;
#  endif /* O_NOFOLLOW */
	if ((fd = open(pathname, oflags)) == -1)
		return -1;
	ret = fchown(fd, owner, group);
	close(fd);
	return ret;
}
# else
	UNUSED(flags);
	return chown(pathname, owner, group);
# endif
}
#endif

#ifndef HAVE_FCHMODAT
/*
 * A limited implementation of fchmodat() that only implements the
 * functionality used by secsh, currently only AT_FDCWD and
 * AT_SYMLINK_NOFOLLOW.
 */
int
fchmodat(int fd, const char *pathname, mode_t mode, int flags)
{
	if (fd != AT_FDCWD) {
		errno = ENOSYS;
		return -1;
	}
# ifdef HAVE_FCHMOD
{	int ret, oflags = O_WRONLY;

#  ifdef O_NOFOLLOW
	if (flags & AT_SYMLINK_NOFOLLOW)
		oflags |= O_NOFOLLOW;
#  endif /* O_NOFOLLOW */
	if ((fd = open(pathname, oflags)) == -1)
		return -1;
	ret = fchmod(fd, mode);
	close(fd);
	return ret;
}
# else
	UNUSED(flags);
	return chmod(pathname, mode);
# endif
}
#endif

#ifndef HAVE_TRUNCATE
int truncate(const char *path, off_t length)
{
	int fd, ret, saverrno;

	fd = open(path, O_WRONLY);
	if (fd == -1)
		return (-1);

	ret = ftruncate(fd, length);
	saverrno = errno;
	close(fd);
	if (ret == -1)
		errno = saverrno;

	return(ret);
}
#endif /* HAVE_TRUNCATE */

#if !defined(HAVE_NANOSLEEP) && !defined(HAVE_NSLEEP)
int nanosleep(const struct timespec *req, struct timespec *rem)
{
	int rc, saverrno;
	extern int errno;
	struct timeval tstart, tstop, tremain, time2wait;

	TIMESPEC_TO_TIMEVAL(&time2wait, req)
	(void) gettimeofday(&tstart, NULL);
	rc = select(0, NULL, NULL, NULL, &time2wait);
	if (rc == -1) {
		saverrno = errno;
		(void) gettimeofday (&tstop, NULL);
		errno = saverrno;
		tremain.tv_sec = time2wait.tv_sec -
			(tstop.tv_sec - tstart.tv_sec);
		tremain.tv_usec = time2wait.tv_usec -
			(tstop.tv_usec - tstart.tv_usec);
		tremain.tv_sec += tremain.tv_usec / 1000000L;
		tremain.tv_usec %= 1000000L;
	} else {
		tremain.tv_sec = 0;
		tremain.tv_usec = 0;
	}
	if (rem != NULL)
		TIMEVAL_TO_TIMESPEC(&tremain, rem)

	return(rc);
}
#endif

#if !defined(HAVE_USLEEP)
int usleep(unsigned int useconds)
{
	struct timespec ts;

	ts.tv_sec = useconds / 1000000;
	ts.tv_nsec = (useconds % 1000000) * 1000;
	return nanosleep(&ts, NULL);
}
#endif

#ifndef HAVE_TCGETPGRP
pid_t
tcgetpgrp(int fd)
{
	int ctty_pgrp;

	if (ioctl(fd, TIOCGPGRP, &ctty_pgrp) == -1)
		return(-1);
	else
		return(ctty_pgrp);
}
#endif /* HAVE_TCGETPGRP */

#ifndef HAVE_TCSENDBREAK
int
tcsendbreak(int fd, int duration)
{
# if defined(TIOCSBRK) && defined(TIOCCBRK)
	struct timeval sleepytime;

	sleepytime.tv_sec = 0;
	sleepytime.tv_usec = 400000;
	if (ioctl(fd, TIOCSBRK, 0) == -1)
		return (-1);
	(void)select(0, 0, 0, 0, &sleepytime);
	if (ioctl(fd, TIOCCBRK, 0) == -1)
		return (-1);
	return (0);
# else
	return -1;
# endif
}
#endif /* HAVE_TCSENDBREAK */

#ifndef HAVE_STRDUP
char *
strdup(const char *str)
{
	size_t len;
	char *cp;

	len = strlen(str) + 1;
	cp = malloc(len);
	if (cp != NULL)
		return(memcpy(cp, str, len));
	return NULL;
}
#endif

#ifndef HAVE_ISBLANK
int
isblank(int c)
{
	return (c == ' ' || c == '\t');
}
#endif

#ifndef HAVE_GETPGID
pid_t
getpgid(pid_t pid)
{
#if defined(HAVE_GETPGRP) && !GETPGRP_VOID
	return getpgrp(pid);
#elif defined(HAVE_GETPGRP)
	if (pid == 0)
		return getpgrp();
#endif

	errno = ESRCH;
	return -1;
}
#endif

#ifndef HAVE_PLEDGE
int
pledge(const char *promises, const char *paths[])
{
	UNUSED(promises);
	UNUSED(paths);
	return 0;
}
#endif

#ifndef HAVE_RAISE
int
raise(int sig)
{
	kill(getpid(), sig);
}
#endif

#ifndef HAVE_GETSID
pid_t
getsid(pid_t pid)
{
	errno = ENOSYS;
	return -1;
}
#endif

#ifndef HAVE_KILLPG
int
killpg(pid_t pgrp, int sig)
{
	return kill(pgrp, sig);
}
#endif

#ifdef FFLUSH_NULL_BUG
#undef fflush
int _ssh_compat_fflush(FILE *f)
{
	int r1, r2;

	if (f == NULL) {
		r1 = fflush(stdout);
		r2 = fflush(stderr);
		if (r1 == -1 || r2 == -1)
			return -1;
		return 0;
	}
	return fflush(f);
}
#endif

#ifndef HAVE_LOCALTIME_R
struct tm *
localtime_r(const time_t *timep, struct tm *result)
{
	struct tm *tm = localtime(timep);
	return memcpy(result, tm, sizeof(*tm));
}
#endif
