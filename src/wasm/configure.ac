AC_PREREQ([2.69])

m4_define([VERSION_MAJOR], [0])
m4_define([VERSION_MINOR], [0])
m4_define([VERSION_BUILD], [m4_default_nblank_quoted(m4_esyscmd_s([echo $COMMIT_SHORT_SHA]), [dev])])

AC_INIT([L15 Wasm plugin], m4_join([.], [VERSION_MAJOR], [VERSION_MINOR], [VERSION_BUILD]), [l2xl@protonmail.com])
AM_INIT_AUTOMAKE([-Wall -Werror foreign])
AC_PROG_CXX

AC_CHECK_TOOL([EMCXX], [em++])
if test "x$EMCXX" = "x"; then
    AC_MSG_ERROR([Emscripten compiler not found. Please install Emscripten.])
fi

AC_CONFIG_FILES([Makefile])
AC_OUTPUT

echo
echo "  ==============================================================================================================="
echo "  L15 wasm plugin config result:"
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
