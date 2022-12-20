AC_PREREQ([2.69])

AC_INIT([L15 Core], [m4_esyscmd_s([./version.sh])], [l2xl@protonmail.com])
AC_CONFIG_SRCDIR([src/core/chain_api.cpp])
AC_CONFIG_AUX_DIR([build-aux])
AC_CONFIG_MACRO_DIR([build-aux/m4])

LT_INIT([static])

AM_INIT_AUTOMAKE([1.16 foreign subdir-objects])

dnl Compiler checks (here before libtool).
if test "x${CXXFLAGS}" != "x"; then
  CXXFLAGS_overridden=yes
else
  CXXFLAGS_overridden=
fi

if test "x${CPPFLAGS}" != "x"; then
  CPPFLAGS_overridden=yes
else
  CPPFLAGS_overridden=
fi

if test "x${LDFLAGS}" != "x"; then
  LDFLAGS_overridden=yes
else
  LDFLAGS_overridden=
fi

# Checks for programs.
AC_PROG_CC
AC_PROG_CXX
AC_PROG_CPP
AC_PROG_MKDIR_P

AX_CXX_COMPILE_STDCXX([20], [noext], [mandatory])

dnl Enable debug
AC_ARG_ENABLE([debug],
    [AS_HELP_STRING([--enable-debug],
                    [use compiler flags and macros suited for debugging (default is no)])],
    [enable_debug=$enableval],
    [enable_debug=no])

if test "$enable_debug" = "yes"; then
  dnl If debugging is enabled, and the user hasn't overridden CXXFLAGS, clear
  dnl them, to prevent autoconfs "-g -O2" being added. Otherwise we'd end up
  dnl with "-O0 -g3 -g -O2".
  if test "$CXXFLAGS_overridden" != "yes"; then
  CXXFLAGS=""
  fi

  dnl Disable all optimizations
  AX_CHECK_COMPILE_FLAG([-O0], [DEBUG_CXXFLAGS="$DEBUG_CXXFLAGS -O0"], [], [$CXXFLAG_WERROR])

  dnl Prefer -g3, fall back to -g if that is unavailable.
  AX_CHECK_COMPILE_FLAG(
    [-g3],
    [DEBUG_CXXFLAGS="$DEBUG_CXXFLAGS -g3"],
    [AX_CHECK_COMPILE_FLAG([-g], [DEBUG_CXXFLAGS="$DEBUG_CXXFLAGS -g"], [], [$CXXFLAG_WERROR])],
    [$CXXFLAG_WERROR])

  AX_CHECK_PREPROC_FLAG([-DDEBUG], [DEBUG_CPPFLAGS="$DEBUG_CPPFLAGS -DDEBUG"], [], [$CXXFLAG_WERROR])
  AX_CHECK_COMPILE_FLAG([-ftrapv], [DEBUG_CXXFLAGS="$DEBUG_CXXFLAGS -ftrapv"], [], [$CXXFLAG_WERROR])
fi

# Checks for libraries.
AX_BOOST_BASE([1.70],, [AC_MSG_ERROR([Boost 1.70 or higher is needed, but it was not found in your system])])
AX_BOOST_FILESYSTEM(,[AC_MSG_ERROR([libboost_filesystem is required, but it was not found in your system])])
AX_PTHREAD(,[AC_MSG_ERROR([libpthread is required, but it was not found in your system])])

CC="$PTHREAD_CC"
CXX="$PTHREAD_CXX"
LIBS="$PTHREAD_LIBS $LIBS"
CPPFLAGS="$DEBUG_CPPFLAGS $CPPFLAGS"
CFLAGS="$PTHREAD_CFLAGS $CFLAGS"
CXXFLAGS="$DEBUG_CXXFLAGS $PTHREAD_CFLAGS $CXXFLAGS"

AX_TBB
AX_ZMQ(,,[AC_MSG_ERROR([libzmq is required, but it was not found in your system])])


# Checks for typedefs, structures, and compiler characteristics.
AC_TYPE_INT32_T
AC_TYPE_INT64_T
AC_TYPE_UINT32_T
AC_TYPE_UINT64_T
AC_TYPE_UINT8_T

# Checks for library functions.
AC_CHECK_FUNCS([dup2 memset pow sqrt strtoul strtoull])

AC_CONFIG_FILES([Makefile
                 src/Makefile
                 src/common/Makefile
                 src/tools/Makefile
                 src/core/Makefile
                 src/service/Makefile
                 src/app/Makefile
                 test/Makefile
                 test/core/Makefile
                 test/p2p/Makefile
                 test/service/Makefile
                 contrib/Makefile])


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

dnl AC_CONFIG_SUBDIRS does not support custom arguments per subproject
dnl so that is the reason to use more flexible AX_SUBDIRS_CONFIGURE.
dnl Unfortunately AX_SUBDIRS_CONFIGURE does not allow 'autoreconf' be called recursively for all subprojects (just does it for 'configure' script only)
dnl so we call 'autoreconf' for the every subproject manually with 'autogen.sh', placed at the source tree root.

AX_SUBDIRS_CONFIGURE(
    [node],
    [[--enable-static], [--disable-shared], [--enable-c++20], [--disable-multiprocess], [--with-gui=no], [--with-incompatible-bdb], [--with-tests=no]],
    [[--disable-tests], [--disable-bench], [--with-zmq]],
    [],
    [])


AX_SUBDIRS_CONFIGURE(
    [contrib/secp256k1],
    [[--enable-static], [--disable-shared], [--enable-experimental], [--enable-module-musig], [--enable-module-schnorrsig], [--enable-module-frost], [--enable-module-recovery]],
    [[--disable-tests], [--disable-benchmark], [--enable-examples]],
    [],
    [[--disable-bench]])

AC_OUTPUT

echo
echo "  ==============================================================================================================="
echo "  L15 config result:"
echo "  build version   = $VERSION"
echo
echo "  debug enabled   = $enable_debug"
echo "  werror          = $enable_werror"
echo
echo "  target os       = $host_os"
echo "  build os        = $build_os"
echo
echo "  CPPFLAGS        = $CPPFLAGS $ZMQ_CPPFLAGS"
echo "  CXX             = $CXX"
echo "  CXXFLAGS        = $CXXFLAGS"
echo "  LDFLAGS         = $LDFLAGS $ZMQ_LDFLAGS"
echo "  LIBS            = $LIBS $ZMQ_LIBS"
echo "  ARFLAGS         = $ARFLAGS"
echo "  ==============================================================================================================="
echo
