# options to check compiler
#
# Author: Roumen Petrov
# Revision: 2022-01-30
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
# Note macro AC_PROG_CC_C99 is added in autoconf 2.60.
    m4_ifdef([AC_PROG_CC_C99], [AC_REQUIRE([AC_PROG_CC_C99])])
    ]
  )
])
