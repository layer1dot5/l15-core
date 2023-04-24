AC_PREREQ([2.69])

AC_INIT([L15 Core], [m4_esyscmd_s([./version.sh])], [l2xl@protonmail.com])
AC_CONFIG_SRCDIR([src/core/channel_keys.cpp])
AC_CONFIG_AUX_DIR([build-aux])
AC_CONFIG_MACRO_DIR([build-aux/m4])

LT_INIT([pic-only])

AM_INIT_AUTOMAKE([1.16 foreign subdir-objects])

dnl Compiler checks (here before libtool).
if test "x${CXXFLAGS}" != "x"; then
  CXXFLAGS_overridden=yes
else
  CXXFLAGS_overridden=
fi

if test "x${CFLAGS}" != "x"; then
  CFLAGS_overridden=yes
else
  CFLAGS_overridden=
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

compiler_name=`basename "$CC"`
if test "x$compiler_name" = "xemcc"; then
    WITH_EMSCRIPTEN=yes
else
    WITH_EMSCRIPTEN=no
fi

# Checks for programs.
AC_PROG_CC
AC_PROG_CXX
AC_PROG_CPP
AC_PROG_MKDIR_P

AX_CXX_COMPILE_STDCXX([20], [noext], [mandatory])

default_build_tools=yes
default_build_services=yes
default_build_apis=yes
default_build_inscribeit=no
default_plugin_api=no

dnl Enable Python integrations
AC_ARG_ENABLE([python-module],
              [AS_HELP_STRING([--enable-python-module],[Enable API binding module for python (disabled by default)])],
              [
                if test $enableval != no; then
                    default_plugin_api=yes
                fi
              ],
              [enable_python_module=no])

AC_ARG_ENABLE([wasm-module],
              [AS_HELP_STRING([--enable-wasm-module], [Enable plugin API binding for WebAssembly (disabled by default)])],
              [
                if test $enableval != no; then
                    default_plugin_api=yes
                fi
              ],
              [enable_wasm_module=no])

if test "$enable_python_module" = "yes" "$enable_wasm_module" = "yes"; then
    AC_MSG_ERROR([WebAssembly and Python modules cannot be build simultaneously])
fi

AC_ARG_ENABLE([plugin-api],
              [AS_HELP_STRING([--enable-plugin-api], [Enable plugin API build (disabled by default)])],
              [
                if test $enableval != no; then
                    default_build_tools=no
                    default_build_services=no
                    default_build_apis=no
                    default_build_inscribeit=yes
                fi
              ],
              [
                if test $default_plugin_api != no; then
                    default_build_tools=no
                    default_build_services=no
                    default_build_apis=no
                    default_build_inscribeit=yes
                    AC_MSG_NOTICE([default_build_inscribeit: $default_build_inscribeit])
                fi
                enable_plugin_api=$default_plugin_api
              ])

AC_ARG_ENABLE([build-apis],
              [AS_HELP_STRING([--enable-build-apis], [Enable APIs build (enabled by default)])],
              [
                if test $enableval = no; then
                    default_build_services=no
                    default_build_tools=no
                fi
              ],
              [enable_build_apis=$default_build_apis])

AC_ARG_ENABLE([build-services],
              [AS_HELP_STRING([--enable-build-services], [Enable services build (enabled by default)])],
              [
                if test $enableval = no; then
                    default_build_tools=no
                fi
              ],
              [enable_build_services=$default_build_services])

AC_ARG_ENABLE([build-tools],
              [AS_HELP_STRING([--enable-build-tools], [Enable tools build (enabled by default)])],
              [],
              [enable_build_tools=$default_build_tools])


AC_ARG_ENABLE([build-inscribeit],
              [AS_HELP_STRING([--enable-build-inscribeit], [Enable inscribeit API build (disabled by default)])],
              [],
              [
                enable_build_inscribeit=$default_build_inscribeit
              ])


if test "$enable_plugin_api" = "yes"; then
    if test "$enable_build_apis" = "yes"; then
        AC_MSG_ERROR([Cannot enable plugin API with general APIs])
    fi
fi

if test "$enable_build_services" != "yes"; then
    if test "$enable_build_tools" = "yes"; then
        AC_MSG_ERROR([Cannot build tools without services])
    fi
fi

if test "$enable_build_apis" != "yes"; then
    if test "$enable_build_services" = "yes"; then
        AC_MSG_ERROR([Cannot build services without general APIs])
    fi
fi

AM_CONDITIONAL([BUILD_APIS], [test "$enable_build_apis" = "yes"])
AM_CONDITIONAL([BUILD_SERVICES], [test "$enable_build_services" = "yes"])
AM_CONDITIONAL([BUILD_TOOLS], [test "$enable_build_tools" = "yes"])
AM_CONDITIONAL([BUILD_INSCRIBEIT], [test "$enable_build_inscribeit" = "yes"])
AM_CONDITIONAL([BUILD_PLUGIN_API], [test "$enable_plugin_api" = "yes"])
AM_CONDITIONAL([BUILD_PYTHON_MODULE], [test "$enable_python_module" = "yes"])
AM_CONDITIONAL([BUILD_WASM_MODULE], [test "$enable_wasm_module" = "yes"])

if test "$enable_python_module" = "yes"; then
    AM_PATH_PYTHON([3])
    AC_MSG_NOTICE([python is $PYTHON])

    AX_PKG_SWIG([], [], [ AC_MSG_ERROR([SWIG is required to build.]) ])
    AX_PYTHON_DEVEL
    AX_SWIG_PYTHON
fi

dnl Enable debug
AC_ARG_ENABLE([debug],
    [AS_HELP_STRING([--enable-debug],
                    [use compiler flags and macros suited for debugging (disabled by default)])],
    [],
    [enable_debug=no])

dnl If debugging is enabled, and the user hasn't overridden CXXFLAGS, clear
dnl them, to prevent autoconfs "-g -O2" being added. Otherwise we'd end up
dnl with "-O0 -g3 -g -O2".
if test "$CXXFLAGS_overridden" != "yes"; then
      CXXFLAGS=""
fi
if test "$CFLAGS_overridden" != "yes"; then
      CFLAGS=""
fi
if test "$LDLAGS_overridden" != "yes"; then
      LDLAGS=""
fi


if test "$enable_debug" = "yes"; then

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

if test "$enable_wasm_module" = "yes"; then
  CPPFLAGS="$DEBUG_CPPFLAGS $CPPFLAGS"
  CXXFLAGS="$DEBUG_CXXFLAGS $CXXFLAGS -fexceptions"
  LDFLAGS="$LDFLAGS -fexceptions -sEXPORT_EXCEPTION_HANDLING_HELPERS -sLLD_REPORT_UNDEFINED  -sEXPORTED_FUNCTIONS=['_malloc'] -sEXPORT_NAME='L15' -sMODULARIZE=1 -sNO_FILESYSTEM=1"

  if test "$enable_debug" != "yes"; then
      CFLAGS=" -O3 $CFLAGS"
      CXXFLAGS=" -O3 $CXXFLAGS"
      LDFLAGS=" -O3 $LDFLAGS"
  fi

else
  AX_PTHREAD(,[AC_MSG_ERROR([libpthread is required, but it was not found in your system])])

  CC="$PTHREAD_CC"
  CXX="$PTHREAD_CXX"
  LIBS="$PTHREAD_LIBS $LIBS"
  CPPFLAGS="$DEBUG_CPPFLAGS $CPPFLAGS"
  CFLAGS="$PTHREAD_CFLAGS $CFLAGS"
  CXXFLAGS="$DEBUG_CXXFLAGS $PTHREAD_CFLAGS $CXXFLAGS"

  AX_TBB
fi

if test "$enable_plugin_api" != "yes"; then
  AX_ZMQ(,,[AC_MSG_ERROR([libzmq is required, but it was not found in your system])])
fi

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
                 src/core/Makefile
                 test/Makefile
                 test/p2p/Makefile
                 contrib/Makefile])

if test "$enable_build_tools" = "yes"; then
    AC_CONFIG_FILES([src/tools/Makefile])
fi

if test "$enable_build_services" = "yes"; then
    AC_CONFIG_FILES([src/service/Makefile test/service/Makefile])
fi

if test "$enable_build_apis" = "yes"; then
    AC_CONFIG_FILES([src/api/Makefile test/core/Makefile])
fi

if test "$enable_build_inscribeit" = "yes"; then
    AC_CONFIG_FILES([src/inscribeit/Makefile])
    if test "$enable_build_tools" = "yes"; then
        AC_CONFIG_FILES([test/inscribeit/Makefile])
    fi
fi

if test "$enable_python_module" = "yes"; then
    AC_CONFIG_FILES([src/python_binding/Makefile])
fi

if test "$enable_wasm_module" = "yes"; then
    AC_CONFIG_FILES([src/wasm_binding/Makefile])
fi

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

if test "$enable_plugin_api" = "yes"; then
AX_SUBDIRS_CONFIGURE(
    [node],
    [[--disable-shared], [--enable-c++20],
     [--with-libs], [--without-sqlite], [--without-bdb], [--without-miniupnpc], [--without-natpmp],
     [--without-qrencode], [--without-libmultiprocess], [--without-mpgen],
     [--without-zmq], [--without-utils], [--without-daemon], [--without-gui],
     [--without-experimental-kernel-lib],
     [--disable-wallet], [--disable-usdt], [--disable-upnp-default], [--disable-natpmp-default],
     [--disable-tests], [--disable-gui-tests], [--disable-bench], [--disable-extended-functional-tests],
     [--disable-fuzz], [--disable-fuzz-binary], [--disable-asm], [--disable-multiprocess], [--disable-external-signer],
     [--disable-experimental-util-chainstate], [--disable-hardening]],
    [[--disable-tests], [--disable-bench], [--with-pic]],
    [[--disable-examples]],
    [])

AX_SUBDIRS_CONFIGURE(
    [contrib/secp256k1],
    [[--enable-static], [--disable-shared], [--enable-experimental], [--enable-module-schnorrsig]],
    [[--disable-tests], [--disable-benchmark], [--disable-examples], [--with-pic]],
    [],
    [[--disable-bench]])


else

AX_SUBDIRS_CONFIGURE(
    [node],
    [[--enable-static], [--disable-shared], [--enable-c++20], [--disable-hardening], [--disable-multiprocess], [--with-gui=no], [--with-incompatible-bdb], [--with-tests=no]],
    [[--disable-tests], [--disable-bench], [--with-zmq], [--with-pic]],
    [],
    [])

AX_SUBDIRS_CONFIGURE(
    [contrib/secp256k1],
    [[--enable-static], [--disable-shared], [--enable-experimental], [--enable-module-musig], [--enable-module-schnorrsig], [--enable-module-frost], [--enable-module-recovery]],
    [[--disable-tests], [--disable-benchmark], [--enable-examples], [--with-pic]],
    [],
    [[--disable-bench]])

fi

AC_OUTPUT

echo
echo "  ==============================================================================================================="
echo "  L15 config result:"
echo "  build version    = $VERSION"
echo
echo "  debug enabled    = $enable_debug"
echo
echo "  build tools      = $enable_build_tools"
echo "  build services   = $enable_build_services"
echo "  build apis       = $enable_build_apis"
echo "  build inscribeit = $enable_build_inscribeit"
echo "  plugin api       = $enable_plugin_api"
echo "  python module    = $enable_python_module"
echo "  wasm module      = $enable_wasm_module"
echo
echo "  target os        = $host_os"
echo "  build os         = $build_os"
echo
echo "  CPPFLAGS         = $CPPFLAGS $ZMQ_CPPFLAGS"
echo "  CXX              = $CXX"
echo "  CXXFLAGS         = $CXXFLAGS"
echo "  LDFLAGS          = $LDFLAGS $ZMQ_LDFLAGS"
echo "  LIBS             = $LIBS $ZMQ_LIBS"
echo "  ARFLAGS          = $ARFLAGS"
echo "  ==============================================================================================================="
echo
