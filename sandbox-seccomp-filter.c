/*
 * Copyright (c) 2012 Will Drewry <wad@dataspill.org>
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

/*
 * Uncomment the SANDBOX_SECCOMP_FILTER_DEBUG macro below to help diagnose
 * filter breakage during development. *Do not* use this in production,
 * as it relies on making library calls that are unsafe in signal context.
 *
 * Instead, live systems the auditctl(8) may be used to monitor failures.
 * E.g.
 *   auditctl -a task,always -F uid=<privsep uid>
 */
/* #define SANDBOX_SECCOMP_FILTER_DEBUG 1 */

/* XXX it should be possible to do logging via the log socket safely */

#if 0
/* NOTE: on older kernels - error: redefinition of 'union sigval' */
#ifdef SANDBOX_SECCOMP_FILTER_DEBUG
/* Use the kernel headers in case of an older toolchain. */
# include <asm/siginfo.h>
# define __have_siginfo_t 1
# define __have_sigval_t 1
# define __have_sigevent_t 1
#endif /* SANDBOX_SECCOMP_FILTER_DEBUG */
#endif

#include "includes.h"

#ifdef SANDBOX_SECCOMP_FILTER

#include <sys/types.h>
#include <sys/resource.h>
#include <sys/prctl.h>
#include <sys/mman.h>
#include <sys/syscall.h>

#include <linux/net.h>
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <elf.h>

#include <asm/unistd.h>
#ifdef __s390__
#include <asm/zcrypt.h>
#endif

#include <errno.h>
#include <signal.h>
#include <stdarg.h>
#include <stddef.h>  /* for offsetof */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "log.h"
#include "ssh-sandbox.h"
#include "xmalloc.h"

/* Linux seccomp_filter sandbox */
#define SECCOMP_FILTER_FAIL SECCOMP_RET_KILL

/* Use a signal handler to emit violations when debugging */
#ifdef SANDBOX_SECCOMP_FILTER_DEBUG
# undef SECCOMP_FILTER_FAIL
# define SECCOMP_FILTER_FAIL SECCOMP_RET_TRAP
#endif /* SANDBOX_SECCOMP_FILTER_DEBUG */

#if __BYTE_ORDER == __LITTLE_ENDIAN
# define ARG_LO_OFFSET  0
# define ARG_HI_OFFSET  sizeof(uint32_t)
#elif __BYTE_ORDER == __BIG_ENDIAN
# define ARG_LO_OFFSET  sizeof(uint32_t)
# define ARG_HI_OFFSET  0
#else
#error "Unknown endianness"
#endif

/* Simple helpers to avoid manual errors (but larger BPF programs). */
#define SC_DENY(_nr, _errno) \
	BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, (_nr), 0, 1), \
	BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_ERRNO|(_errno))
#define SC_ALLOW(_nr) \
	BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, (_nr), 0, 1), \
	BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_ALLOW)
#define SC_ALLOW_ARG(_nr, _arg_nr, _arg_val) \
	BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, (_nr), 0, 6), \
	/* load and test syscall argument, low word */ \
	BPF_STMT(BPF_LD+BPF_W+BPF_ABS, \
	    offsetof(struct seccomp_data, args[(_arg_nr)]) + ARG_LO_OFFSET), \
	BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, \
	    ((_arg_val) & 0xFFFFFFFF), 0, 3), \
	/* load and test syscall argument, high word */ \
	BPF_STMT(BPF_LD+BPF_W+BPF_ABS, \
	    offsetof(struct seccomp_data, args[(_arg_nr)]) + ARG_HI_OFFSET), \
	BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, \
	    (((uint32_t)((uint64_t)(_arg_val) >> 32)) & 0xFFFFFFFF), 0, 1), \
	BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_ALLOW), \
	/* reload syscall number; all rules expect it in accumulator */ \
	BPF_STMT(BPF_LD+BPF_W+BPF_ABS, \
		offsetof(struct seccomp_data, nr))
/* Allow if syscall argument contains only values in mask */
#define SC_ALLOW_ARG_MASK(_nr, _arg_nr, _arg_mask) \
	BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, (_nr), 0, 8), \
	/* load, mask and test syscall argument, low word */ \
	BPF_STMT(BPF_LD+BPF_W+BPF_ABS, \
	    offsetof(struct seccomp_data, args[(_arg_nr)]) + ARG_LO_OFFSET), \
	BPF_STMT(BPF_ALU+BPF_AND+BPF_K, ~((_arg_mask) & 0xFFFFFFFF)), \
	BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, 0, 0, 4), \
	/* load, mask and test syscall argument, high word */ \
	BPF_STMT(BPF_LD+BPF_W+BPF_ABS, \
	    offsetof(struct seccomp_data, args[(_arg_nr)]) + ARG_HI_OFFSET), \
	BPF_STMT(BPF_ALU+BPF_AND+BPF_K, \
	    ~(((uint32_t)((uint64_t)(_arg_mask) >> 32)) & 0xFFFFFFFF)), \
	BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, 0, 0, 1), \
	BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_ALLOW), \
	/* reload syscall number; all rules expect it in accumulator */ \
	BPF_STMT(BPF_LD+BPF_W+BPF_ABS, \
		offsetof(struct seccomp_data, nr))

/* Syscall filtering set for preauth. */
static const struct sock_filter preauth_insns[] = {
	/* Ensure the syscall arch convention is as expected. */
	BPF_STMT(BPF_LD+BPF_W+BPF_ABS,
		offsetof(struct seccomp_data, arch)),
	BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, SECCOMP_AUDIT_ARCH, 1, 0),
	BPF_STMT(BPF_RET+BPF_K, SECCOMP_FILTER_FAIL),
	/* Load the syscall number for checking. */
	BPF_STMT(BPF_LD+BPF_W+BPF_ABS,
		offsetof(struct seccomp_data, nr)),

	/* Syscalls to non-fatally deny */
#ifdef __NR_lstat
	SC_DENY(__NR_lstat, EACCES),
#endif
#ifdef __NR_lstat64
	SC_DENY(__NR_lstat64, EACCES),
#endif
#ifdef __NR_fstat
	SC_DENY(__NR_fstat, EACCES),
#endif
#ifdef __NR_fstat64
	SC_DENY(__NR_fstat64, EACCES),
#endif
#ifdef __NR_fstatat64
	SC_DENY(__NR_fstatat64, EACCES),
#endif
#ifdef __NR_open
	SC_DENY(__NR_open, EACCES),
#endif
#ifdef __NR_openat
	SC_DENY(__NR_openat, EACCES),
#endif
#ifdef __NR_newfstatat
	SC_DENY(__NR_newfstatat, EACCES),
#endif
#ifdef __NR_stat
	SC_DENY(__NR_stat, EACCES),
#endif
#ifdef __NR_stat64
	SC_DENY(__NR_stat64, EACCES),
#endif
#ifdef __NR_shmget
	SC_DENY(__NR_shmget, EACCES),
#endif
#ifdef __NR_shmat
	SC_DENY(__NR_shmat, EACCES),
#endif
#ifdef __NR_shmdt
	SC_DENY(__NR_shmdt, EACCES),
#endif
#ifdef __NR_ipc
	SC_DENY(__NR_ipc, EACCES),
#endif
#ifdef __NR_statx
	SC_DENY(__NR_statx, EACCES),
#endif

	/* Syscalls to permit */
#ifdef __NR_brk
	SC_ALLOW(__NR_brk),
#endif
#ifdef __NR_clock_gettime
	SC_ALLOW(__NR_clock_gettime),
#endif
#ifdef __NR_clock_gettime64
	SC_ALLOW(__NR_clock_gettime64),
#endif
#ifdef __NR_close
	SC_ALLOW(__NR_close),
#endif
#ifdef __NR_exit
	SC_ALLOW(__NR_exit),
#endif
#ifdef __NR_exit_group
	SC_ALLOW(__NR_exit_group),
#endif
#ifdef __NR_futex
	SC_ALLOW(__NR_futex),
#endif
#ifdef __NR_futex_time64
	SC_ALLOW(__NR_futex_time64),
#endif
#ifdef __NR_geteuid
	SC_ALLOW(__NR_geteuid),
#endif
#ifdef __NR_geteuid32
	SC_ALLOW(__NR_geteuid32),
#endif
#ifdef __NR_getpgid
	SC_ALLOW(__NR_getpgid),
#endif
#ifdef __NR_getpid
	SC_ALLOW(__NR_getpid),
#endif
#ifdef __NR_gettid
	SC_ALLOW(__NR_gettid),
#endif
#ifdef __NR_getrandom
	SC_ALLOW(__NR_getrandom),
#endif
#ifdef __NR_gettid
	SC_ALLOW(__NR_gettid),
#endif
#ifdef __NR_gettimeofday
	SC_ALLOW(__NR_gettimeofday),
#endif
#ifdef __NR_getuid
	SC_ALLOW(__NR_getuid),
#endif
#ifdef __NR_getuid32
	SC_ALLOW(__NR_getuid32),
#endif
#ifdef __NR_madvise
	SC_ALLOW_ARG(__NR_madvise, 2, MADV_NORMAL),
# ifdef MADV_FREE
	SC_ALLOW_ARG(__NR_madvise, 2, MADV_FREE),
# endif
# ifdef MADV_DONTNEED
	SC_ALLOW_ARG(__NR_madvise, 2, MADV_DONTNEED),
# endif
# ifdef MADV_DONTFORK
	SC_ALLOW_ARG(__NR_madvise, 2, MADV_DONTFORK),
# endif
# ifdef MADV_DONTDUMP
	SC_ALLOW_ARG(__NR_madvise, 2, MADV_DONTDUMP),
# endif
# ifdef MADV_WIPEONFORK
	SC_ALLOW_ARG(__NR_madvise, 2, MADV_WIPEONFORK),
# endif
	SC_DENY(__NR_madvise, EINVAL),
#endif
#ifdef __NR_mmap
	SC_ALLOW_ARG_MASK(__NR_mmap, 2, PROT_READ|PROT_WRITE|PROT_NONE),
#endif
#ifdef __NR_mmap2
	SC_ALLOW_ARG_MASK(__NR_mmap2, 2, PROT_READ|PROT_WRITE|PROT_NONE),
#endif
#ifdef __NR_mprotect
	SC_ALLOW_ARG_MASK(__NR_mprotect, 2, PROT_READ|PROT_WRITE|PROT_NONE),
#endif
#ifdef __NR_mremap
	SC_ALLOW(__NR_mremap),
#endif
#ifdef __NR_munmap
	SC_ALLOW(__NR_munmap),
#endif
#ifdef __NR_nanosleep
	SC_ALLOW(__NR_nanosleep),
#endif
#ifdef __NR_clock_nanosleep
	SC_ALLOW(__NR_clock_nanosleep),
#endif
#ifdef __NR_clock_nanosleep_time64
	SC_ALLOW(__NR_clock_nanosleep_time64),
#endif
#ifdef __NR__newselect
	SC_ALLOW(__NR__newselect),
#endif
#ifdef __NR_ppoll
	SC_ALLOW(__NR_ppoll),
#endif
#ifdef __NR_ppoll_time64
	SC_ALLOW(__NR_ppoll_time64),
#endif
#ifdef __NR_poll
	SC_ALLOW(__NR_poll),
#endif
#ifdef __NR_pselect6
	SC_ALLOW(__NR_pselect6),
#endif
#ifdef __NR_pselect6_time64
	SC_ALLOW(__NR_pselect6_time64),
#endif
#ifdef __NR_read
	SC_ALLOW(__NR_read),
#endif
#ifdef __NR_rt_sigaction
	SC_ALLOW(__NR_rt_sigaction),
#endif
#ifdef __NR_rt_sigprocmask
	SC_ALLOW(__NR_rt_sigprocmask),
#endif
#ifdef __NR_select
	SC_ALLOW(__NR_select),
#endif
#ifdef __NR_shutdown
	SC_ALLOW(__NR_shutdown),
#endif
#ifdef __NR_sigprocmask
	SC_ALLOW(__NR_sigprocmask),
#endif
#ifdef __NR_time
	SC_ALLOW(__NR_time),
#endif
#ifdef __NR_write
	SC_ALLOW(__NR_write),
#endif
#ifdef __NR_writev
	SC_ALLOW(__NR_writev),
#endif
#ifdef __NR_socketcall
	SC_ALLOW_ARG(__NR_socketcall, 0, SYS_SHUTDOWN),
	SC_DENY(__NR_socketcall, EACCES),
#endif
#ifdef __NR_socket
	SC_DENY(__NR_socket, EACCES),
#endif
#if defined(__NR_ioctl) && defined(__s390__)
	/* Allow ioctls for ICA crypto card on s390 */
	SC_ALLOW_ARG(__NR_ioctl, 1, Z90STAT_STATUS_MASK),
	SC_ALLOW_ARG(__NR_ioctl, 1, ICARSAMODEXPO),
	SC_ALLOW_ARG(__NR_ioctl, 1, ICARSACRT),
	SC_ALLOW_ARG(__NR_ioctl, 1, ZSECSENDCPRB),
	/* Allow ioctls for EP11 crypto card on s390 */
	SC_ALLOW_ARG(__NR_ioctl, 1, ZSENDEP11CPRB),
#endif
#if defined(__x86_64__) && defined(__ILP32__) && defined(__X32_SYSCALL_BIT)
	/*
	 * On Linux x32, the clock_gettime VDSO falls back to the
	 * x86-64 syscall under some circumstances, e.g.
	 * https://bugs.debian.org/849923
	 */
	SC_ALLOW(__NR_clock_gettime & ~__X32_SYSCALL_BIT),
#endif

	/* Default deny */
	BPF_STMT(BPF_RET+BPF_K, SECCOMP_FILTER_FAIL),
};

static const struct sock_fprog preauth_program = {
	.len = (unsigned short)(sizeof(preauth_insns)/sizeof(preauth_insns[0])),
	.filter = (struct sock_filter *)preauth_insns,
};

struct ssh_sandbox {
	pid_t child_pid;
};

struct ssh_sandbox *
ssh_sandbox_init(struct monitor *monitor)
{
	struct ssh_sandbox *box;

	UNUSED(monitor);
	/*
	 * Strictly, we don't need to maintain any state here but we need
	 * to return non-NULL to satisfy the API.
	 */
	debug3_f("preparing seccomp filter sandbox");
	box = xcalloc(1, sizeof(*box));
	box->child_pid = 0;

	return box;
}

#ifdef SANDBOX_SECCOMP_FILTER_DEBUG
extern struct monitor *pmonitor;
void mm_log_handler(LogLevel level, const char *msg, void *ctx);

static void
ssh_sandbox_violation(int signum, siginfo_t *info, void *void_context)
{
	char msg[256];

	UNUSED(signum); UNUSED(void_context);
	snprintf(msg, sizeof(msg),
	    "%s: unexpected system call (arch:0x%x,syscall:%d @ %p)",
	    __func__, info->si_arch, info->si_syscall, info->si_call_addr);
	mm_log_handler(SYSLOG_LEVEL_FATAL, msg, pmonitor);
	_exit(1);
}

static void
ssh_sandbox_child_debugging(void)
{
	struct sigaction act;
	sigset_t mask;

	debug3_f("installing SIGSYS handler");
	memset(&act, 0, sizeof(act));
	sigemptyset(&mask);
	sigaddset(&mask, SIGSYS);

	act.sa_sigaction = &ssh_sandbox_violation;
	act.sa_flags = SA_SIGINFO;
	if (sigaction(SIGSYS, &act, NULL) == -1)
		fatal_f("sigaction(SIGSYS): %s", strerror(errno));
	if (sigprocmask(SIG_UNBLOCK, &mask, NULL) == -1)
		fatal_f("sigprocmask(SIGSYS): %s", strerror(errno));
}
#endif /* SANDBOX_SECCOMP_FILTER_DEBUG */

void
ssh_sandbox_child(struct ssh_sandbox *box)
{
	struct rlimit rl_zero;
	int nnp_failed = 0;

	UNUSED(box);
	/* Set rlimits for completeness if possible. */
	rl_zero.rlim_cur = rl_zero.rlim_max = 0;
#ifndef SANDBOX_SKIP_RLIMIT_FSIZE
	if (setrlimit(RLIMIT_FSIZE, &rl_zero) == -1)
		fatal_f("setrlimit(RLIMIT_FSIZE, { 0, 0 }): %s",
			strerror(errno));
#endif
#ifndef SANDBOX_SKIP_RLIMIT_NOFILE
/*
 * NOTE: The Open Group Base Specifications requires poll to return error
 * EINVAL if argument nfds argument is greater than limit {OPEN_MAX}.
 * Switch to poll requires to set limits to one on systems that conform
 * with POSIX specification. Also note that cryptographic library
 * may require file description to obtain random data.
 */
{	struct rlimit rl_nofile;
	/* Cannot use zero because of poll(2) requirement */
	rl_nofile.rlim_cur = rl_nofile.rlim_max = 1;
	if (setrlimit(RLIMIT_NOFILE, &rl_nofile) == -1)
		fatal_f("setrlimit(RLIMIT_NOFILE, { 1, 1 }): %s",
			strerror(errno));
}
#endif
	if (setrlimit(RLIMIT_NPROC, &rl_zero) == -1)
		fatal_f("setrlimit(RLIMIT_NPROC, { 0, 0 }): %s",
			strerror(errno));

#ifdef SANDBOX_SECCOMP_FILTER_DEBUG
	ssh_sandbox_child_debugging();
#endif /* SANDBOX_SECCOMP_FILTER_DEBUG */

	debug3_f("setting PR_SET_NO_NEW_PRIVS");
	if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == -1) {
		debug_f("prctl(PR_SET_NO_NEW_PRIVS): %s", strerror(errno));
		nnp_failed = 1;
	}
	debug3_f("attaching seccomp filter program");
	if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &preauth_program) == -1)
		debug_f("prctl(PR_SET_SECCOMP): %s", strerror(errno));
	else if (nnp_failed)
		fatal_f("SECCOMP_MODE_FILTER activated but "
		    "PR_SET_NO_NEW_PRIVS failed");
}

void
ssh_sandbox_parent_finish(struct ssh_sandbox *box)
{
	free(box);
	debug3_f("finished");
}

void
ssh_sandbox_parent_preauth(struct ssh_sandbox *box, pid_t child_pid)
{
	box->child_pid = child_pid;
}

#endif /* SANDBOX_SECCOMP_FILTER */
