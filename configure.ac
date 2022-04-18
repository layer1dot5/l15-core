AC_PREREQ([2.69])
AC_INIT([L15 Core], [0.0], [l2xl@protonmail.com])
AC_CONFIG_SRCDIR([src/core/chain_api.cpp])
AC_CONFIG_AUX_DIR([build-aux])
AC_CONFIG_MACRO_DIR([build-aux/m4])

LT_INIT([static])

AM_INIT_AUTOMAKE([1.16 foreign subdir-objects])

# Checks for programs.
AC_PROG_CXX
AC_PROG_MKDIR_P

AX_CXX_COMPILE_STDCXX([17], [noext], [mandatory])

# Checks for libraries.
AX_BOOST_BASE([1.70],, [AC_MSG_ERROR([Boost 1.70 or higher is needed, but it was not found in your system])])
AX_BOOST_FILESYSTEM(,[AC_MSG_ERROR([libboost_filesystem is required, but it was not found in your system])])
AX_PTHREAD(,[AC_MSG_ERROR([libpthread is required, but it was not found in your system])])

# Checks for typedefs, structures, and compiler characteristics.
AC_TYPE_INT32_T
AC_TYPE_INT64_T
AC_TYPE_UINT32_T
AC_TYPE_UINT64_T
AC_TYPE_UINT8_T

# Checks for library functions.
AC_CHECK_FUNCS([dup2 memset pow select socket sqrt strtoul strtoull])

dnl Enable debug
AC_ARG_ENABLE([debug],
    [AS_HELP_STRING([--enable-debug],
                    [use compiler flags and macros suited for debugging (default is no)])],
    [enable_debug=$enableval],
    [enable_debug=no])

if test "x$enable_debug" = xyes; then
  dnl Disable all optimizations
  AX_CHECK_COMPILE_FLAG([-O0], [[DEBUG_CXXFLAGS="$DEBUG_CXXFLAGS -O0"]],,[[$CXXFLAG_WERROR]])

  dnl Prefer -g3, fall back to -g if that is unavailable.
  AX_CHECK_COMPILE_FLAG(
    [-g3],
    [[DEBUG_CXXFLAGS="$DEBUG_CXXFLAGS -g3"]],
    [AX_CHECK_COMPILE_FLAG([-g],[[DEBUG_CXXFLAGS="$DEBUG_CXXFLAGS -g"]],,[[$CXXFLAG_WERROR]])],
    [[$CXXFLAG_WERROR]])

  AX_CHECK_PREPROC_FLAG([-DDEBUG],[[DEBUG_CPPFLAGS="$DEBUG_CPPFLAGS -DDEBUG"]],,[[$CXXFLAG_WERROR]])
  AX_CHECK_PREPROC_FLAG([-DDEBUG_LOCKORDER],[[DEBUG_CPPFLAGS="$DEBUG_CPPFLAGS -DDEBUG_LOCKORDER"]],,[[$CXXFLAG_WERROR]])
  AX_CHECK_PREPROC_FLAG([-DABORT_ON_FAILED_ASSUME],[[DEBUG_CPPFLAGS="$DEBUG_CPPFLAGS -DABORT_ON_FAILED_ASSUME"]],,[[$CXXFLAG_WERROR]])
  AX_CHECK_COMPILE_FLAG([-ftrapv],[DEBUG_CXXFLAGS="$DEBUG_CXXFLAGS -ftrapv"],,[[$CXXFLAG_WERROR]])
fi

AC_CONFIG_FILES([Makefile
                 src/Makefile
                 src/core/Makefile
                 src/tools/Makefile
                 test/Makefile])


dnl boost's m4 checks do something really nasty: they export these vars. As a
dnl result, they leak into subdir's configure and crazy things may happen.
dnl Until this is fixed upstream and we've synced, we'll just un-export them.

CPPFLAGS_TEMP="$CPPFLAGS"
unset CPPFLAGS
CPPFLAGS="$CPPFLAGS_TEMP"

LDFLAGS_TEMP="$LDFLAGS"
unset LDFLAGS
LDFLAGS="$LDFLAGS_TEMP"

LIBS_TEMP="$LIBS"
unset LIBS
LIBS="$LIBS_TEMP"

PKGCONFIG_PATH_TEMP="$PKG_CONFIG_PATH"
unset PKG_CONFIG_PATH
PKG_CONFIG_PATH="$PKGCONFIG_PATH_TEMP"

PKGCONFIG_LIBDIR_TEMP="$PKG_CONFIG_LIBDIR"
unset PKG_CONFIG_LIBDIR
PKG_CONFIG_LIBDIR="$PKGCONFIG_LIBDIR_TEMP"

ac_configure_args="${ac_configure_args} --enable-static --disable-shared --enable-c++17 --with-gui=no --with-incompatible-bdb --disable-tests --disable-bench --with-tests=no"
AC_CONFIG_SUBDIRS([node])

AC_OUTPUT

