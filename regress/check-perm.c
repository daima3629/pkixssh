/*
 * Placed in the public domain
 */

/* $OpenBSD: modpipe.c,v 1.6 2013/11/21 03:16:47 djm Exp $ */

#include "includes.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <stdlib.h>
#include <errno.h>
#include <pwd.h>
#ifdef HAVE_LIBGEN_H
#include <libgen.h>
#endif

/* misc.c */
int safe_path(const char *, struct stat *, const char *, uid_t, char *, size_t);

static void
fatal(const char *fmt, ...)
{
	va_list args;

	va_start(args, fmt);
	vfprintf(stderr, fmt, args);
	fputc('\n', stderr);
	va_end(args);
	exit(1);
}
/* Based on session.c. NB. keep tests in sync */
static void
safely_chroot(const char *path, uid_t uid)
{
	const char *cp;
	char component[PATH_MAX];
	struct stat st;

	if (*path != '/')
		fatal("chroot path does not begin at root");
	if (strlen(path) >= sizeof(component))
		fatal("chroot path too long");

	/*
	 * Descend the path, checking that each component is a
	 * root-owned directory with strict permissions.
	 */
	for (cp = path; cp != NULL;) {
		if ((cp = strchr(cp, '/')) == NULL)
			strlcpy(component, path, sizeof(component));
		else {
			cp++;
			memcpy(component, path, cp - path);
			component[cp - path] = '\0';
		}

		/* debug3("%s: checking '%s'", __func__, component); */

		if (stat(component, &st) == -1)
			fatal("%s: stat(\"%s\"): %s", __func__,
			    component, strerror(errno));
		if (st.st_uid != 0 || (st.st_mode & 022) != 0)
			fatal("bad ownership or modes for chroot "
			    "directory %s\"%s\"",
			    cp == NULL ? "" : "component ", component);
		if (!S_ISDIR(st.st_mode))
			fatal("chroot path %s\"%s\" is not a directory",
			    cp == NULL ? "" : "component ", component);

	}

	if (chdir(path) == -1)
		fatal("Unable to chdir to chroot path \"%s\": "
		    "%s", path, strerror(errno));
}

/* from platform.c */
int
platform_sys_dir_uid(uid_t uid)
{
	if (uid == 0)
		return 1;
#ifdef PLATFORM_SYS_DIR_UID
	if (uid == PLATFORM_SYS_DIR_UID)
		return 1;
#endif
	return 0;
}

static void
usage(void)
{
	fprintf(stderr, "check-perm -m [chroot | keys-command] [path]\n");
	exit(1);
}

int
main(int argc, char **argv)
{
	const char *path = ".";
	char errmsg[256];
	int ch, mode = -1;
	extern char *optarg;
	extern int optind;
	struct stat st;

	while ((ch = getopt(argc, argv, "hm:")) != -1) {
		switch (ch) {
		case 'm':
			if (strcasecmp(optarg, "chroot") == 0)
				mode = 1;
			else if (strcasecmp(optarg, "keys-command") == 0)
				mode = 2;
			else {
				fprintf(stderr, "Invalid -m option\n"),
				usage();
			}
			break;
		default:
			usage();
		}
	}
	argc -= optind;
	argv += optind;

	if (argc > 1)
		usage();
	else if (argc == 1)
		path = argv[0];

	if (mode == 1)
		safely_chroot(path, getuid());
	else if (mode == 2) {
		if (stat(path, &st) == -1)
			fatal("Could not stat %s: %s", path, strerror(errno));
		if (safe_path(path, &st, NULL, 0,
		    errmsg, sizeof(errmsg)) != 0)
			fatal("Unsafe %s: %s", path, errmsg);
	} else {
		fprintf(stderr, "Invalid mode\n");
		usage();
	}
	return 0;
}
