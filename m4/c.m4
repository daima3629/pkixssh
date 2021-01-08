# options to check compiler
#
# Author: Roumen Petrov
# Revision: 7 Jan 2021
#

AC_DEFUN([SSH_AC_PROG_CC],
[
  AC_REQUIRE([AC_PROG_CC])
  # check for macro defined in 2.69b
  m4_ifdef([AC_CONFIG_MACRO_DIRS],
    [
# Note autoconf 2.69b obsoletes AC_PROG_CC_C99 macro and c99 tests
# are performed in standard macro.
    ],
    [
    AC_REQUIRE([AC_PROG_CC_C99])
    ]
  )
])
