/*
 * Copyright (c) 2008,2014 Darren Tucker <dtucker@zip.com.au>
 * Copyright (c) 2015-2018 Roumen Petrov.  All rights reserved.
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF MIND, USE, DATA OR PROFITS, WHETHER
 * IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING
 * OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include "includes.h"

#if !defined(HAVE_STATVFS) || !defined(HAVE_FSTATVFS)

#ifdef HAVE_SYS_STATFS_H
# include <sys/statfs.h>
#endif
#ifdef HAVE_SYS_MOUNT_H
# include <sys/mount.h>
#endif
#include <string.h>	/*for memset*/
#include <errno.h>

#ifndef MNAMELEN
/* OpenSSH finaly defines MNAMELEN in commit:
 * "bsd-statvfs: include sys/vfs.h, check for f_flags"
 *   (Sun, 25 Feb 2018 11:22:57 +1100)
 * but for unknow reason with so small size!
 * Let keep size as defined in PKIX-SSH 8.5 since
 *   (Wed, 12 Aug 2015 00:18:04 +0300)
# define MNAMELEN 32
 */
# define MNAMELEN 90
#endif

#ifdef USE_STRUCT_STATFS
static void
copy_statfs_to_statvfs(struct statvfs *to, struct statfs *from)
{
	to->f_bsize = from->f_bsize;
	to->f_frsize = from->f_bsize;	/* no exact equivalent */
	to->f_blocks = from->f_blocks;
	to->f_bfree = from->f_bfree;
	to->f_bavail = from->f_bavail;
	to->f_files = from->f_files;
	to->f_ffree = from->f_ffree;
	to->f_favail = from->f_ffree;	/* no exact equivalent */
	to->f_fsid = 0;			/* XXX fix me */
#ifdef HAVE_STRUCT_STATFS_F_FLAGS
	to->f_flag = from->f_flags;
#else
	to->f_flag = 0;
#endif
	to->f_namemax = MNAMELEN;
}
#endif /*def USE_STRUCT_STATFS*/

# ifndef HAVE_STATVFS
int statvfs(const char *path, struct statvfs *buf)
{
#  ifdef USE_STRUCT_STATFS
	struct statfs fs;

	memset(&fs, 0, sizeof(fs));
	if (statfs(path, &fs) == -1)
		return -1;
	copy_statfs_to_statvfs(buf, &fs);
	return 0;
#  else
	errno = ENOSYS;
	return -1;
#  endif
}
# endif

# ifndef HAVE_FSTATVFS
int fstatvfs(int fd, struct statvfs *buf)
{
#  ifdef USE_STRUCT_STATFS
	struct statfs fs;

	memset(&fs, 0, sizeof(fs));
	if (fstatfs(fd, &fs) == -1)
		return -1;
	copy_statfs_to_statvfs(buf, &fs);
	return 0;
#  else
	errno = ENOSYS;
	return -1;
#  endif
}
# endif

#endif
