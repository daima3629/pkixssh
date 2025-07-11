# Android configuration settings
#
# Copyright (c) 2018-2024 Roumen Petrov
#
# serial 20241111

AC_DEFUN([SSH_ANDROID_PRECONF], [
case "$host" in
*-*-linux-android*)
  dnl PKIX-SSH up to version 11.6 support as minimum API level 9 and
  dnl build only with platform headers.
  dnl Version after 11.6 support as minimum API level 16 and build
  dnl either with platform or unified headers.

  dnl API before 21 define "getpagesize" is inline function, i.e.
  dnl not-detectable by function checks.
  ac_cv_func_getpagesize=yes

  dnl Function "openpty" is defined in API 23, but declared only in
  dnl unified headers => for consistency across versions always use
  dnl local port, based on /dev/ptmx
  ac_cv_search_openpty=no
  ac_cv_func_openpty=use_port
  ac_cv_file__dev_ptmx=yes

  dnl API 21 adds <sys/statvfs.h> to platform headers but it is always
  dnl available as unified header is.
  dnl Before API 21 functions "statvfs" and "fstatvfs" are defined in
  dnl Bionic "C" library only on some platforms!
  dnl => use local port for consistency across versions
  ac_cv_header_sys_statvfs_h=ignore
  ac_cv_func_statvfs=use_port
  ac_cv_func_fstatvfs=use_port

  dnl Platform headers always declare syscall wrapper function "getsid".
  dnl In unified it is declared for API 17. Also before API 17 it is
  dnl defined in "C" library only on some platforms!
  dnl => always use local inline replacement (see misc.c)
  ac_cv_func_getsid=yes

  dnl Function "mbtowc" is defined in API 21 but always declared
  dnl => use local port for consistency
  ac_cv_func_mbtowc=use_port

  dnl Function "getline" is defined in API 18 but in platform headers
  dnl is not declared until API 21.
  dnl Note in unified headers function is declared accordingly.
  dnl => use local port for consistency
  ac_cv_func_getline=use_port

  dnl LARGE FILES
  dnl https://android.googlesource.com/platform/bionic/+/master/docs/32-bit-abi.md
  dnl
  dnl Autoconf 2.72 largefile test defines _FILE_OFFSET_BITS to 64.
  dnl If pre Autoconf 2.72 build is with unified headers test
  dnl defines _FILE_OFFSET_BITS.
  dnl As result on 32-bit platforms is activated __USE_FILE_OFFSET64.
  dnl => temporary suppress for now
  dnl
  dnl NOTE: autoconf 2.72 removes cache variable ac_cv_sys_file_offset_bits!
  dnl Also variable ac_have_largefile cannot be used as is documented.
  dnl autoconf 2.72:
  ac_cv_sys_largefile_opts='none needed'
  dnl pre autoconf 2.72:
  ac_cv_sys_file_offset_bits=no

  dnl see port-android.c for details
  ac_cv_func_endgrent=yes

  dnl Function "getifaddrs" is defined in API 24 and declared
  dnl in unified headers accordingly.
  dnl => do not use "bind interface" for consistency
  ac_cv_func_getifaddrs=ignore

  dnl Function "futimes" is defined in API 26, but declared only in
  dnl unified headers.
  dnl => use utimes as work-around for consistency
  ac_cv_func_futimes=ignore

  dnl Function "nl_langinfo" is declared in API 26 only in unified
  dnl headers. It is defined in "C" library only on some platforms
  dnl depending from NDK version!
  dnl => do not use "nl_langinfo" for consistency
  ac_cv_func_nl_langinfo=ignore

  dnl Function "mblen" is defined in API 26 only on some platforms
  dnl depending from NDK version!
  dnl It is declared in unified headers, but declaration exist in
  dnl headers for previous API
  dnl => do not use "mblen" for consistency
  ac_cv_func_mblen=ignore

  dnl Function "getrandom" is declared in API 28(unified headers).
  dnl Before API 28 it is defined in "C" static-library on some
  dnl platforms depending from NDK version!
  dnl => do not use "getrandom" for consistency
  ac_cv_func_getrandom=ignore

  dnl Function "getentropy" is declared in API 28(unified headers).
  dnl Before API 28 it is defined in "C" static-library on some
  dnl platforms depending from NDK version!
  dnl => do not use "getentropy" for consistency
  ac_cv_func_getentropy=ignore

  dnl Function "glob" is declared in API 28(unified headers).
  dnl Before API 28 it is defined in "C" static-library on some
  dnl platforms depending from NDK version!
  dnl => do not use "glob" for consistency
  ac_cv_func_glob=ignore

  dnl Function "reallocarray" is declared in API 29(unified headers).
  dnl Before API 29 it is defined in "C" static-library on some
  dnl platforms depending from NDK version!
  dnl => do not use "reallocarray" for consistency
  ac_cv_func_reallocarray=ignore

  dnl Function "close_range" is declared in API 34(unified headers).
  dnl Before API 34 it is defined in "C" static-library on some
  dnl platforms depending from NDK version!
  dnl => do not use "close_range" for consistency
  ac_cv_func_close_range=ignore

  dnl Function "ppoll" is declared in API 21(unified headers).
  dnl NOTE: Use system.

  dnl Header utmpx.h is addeed in NDK r27 with no-op implementation.
  dnl => ignore to disable utmpx automatically
  ac_cv_header_utmpx_h=ignore
  ;;
esac
])
