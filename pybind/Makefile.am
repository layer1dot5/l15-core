AM_CPPFLAGS = \
 -I$(top_srcdir)/node/src \
 -I$(top_srcdir)/node/src/univalue/include \
 -I$(top_srcdir)/node/src/consensus \
 -I$(top_srcdir)/node/src/script \
 -I$(top_srcdir)/node/src/support \
 -I$(top_srcdir)/contrib/secp256k1/include \
 -I$(top_srcdir)/src/common \
 -I$(top_srcdir)/src/p2p \
 -I$(top_srcdir)/src/core \
 -I$(top_srcdir)/contrib/cex\
 $(PYBIND_CPPFLAGS)

SWIG_SOURCES_CPP = \
 $(top_srcdir)/node/src/support/cleanse.cpp

SWIG_FLAGS = -stdstl
SWIG_SOURCES = l15-core-pybind.i
SWIG_PYTHON_MODULE = libl15-core-pybind-wrap.cxx
CLEANFILES = $(SWIG_PYTHON_MODULE) libl15-core-pybind.py

BUILT_SOURCES = $(SWIG_PYTHON_MODULE)
EXTRA_DIST = $(SWIG_SOURCES)

$(SWIG_PYTHON_MODULE): $(SWIG_SOURCES)
	$(SWIG) -c++ -python -o $@ $<

# $(python3 -m pybind11 --includes)

AM_LDFLAGS = -L$(top_builddir)/node/src \
             -L$(top_builddir)/node/src/crypto

pkglib_LTLIBRARIES = _libl15-core-pybind.la
#lib_LTLIBRARIES = libl15-core-pybind.so
#noinst_LTLIBRARIES = libl15-core-pybind.la

_libl15_core_pybind_la_SOURCES = $(SWIG_PYTHON_MODULE) $(SWIG_SOURCES_CPP)
#_libl15_core_pybind_la_SOURCES = $(SWIG_PYTHON_MODULE) l15-core-pybind.hpp l15-core-pybind.cpp
_libl15_core_pybind_la_CXXFLAGS = $(PYTHON_INCLUDES) $(PYTHON_CPPFLAGS) -fPIC
_libl15_core_pybind_la_LDFLAGS = -shared -module -avoid-version -no-undefined $(PYTHON_LDFLAGS) -fPIC
#libl15_core_pybind_la_LDFLAGS = -module -avoid-version -no-undefined

_libl15_core_pybind_la_LIBADD = \
$(top_builddir)/node/src/libbitcoin_common.a \
$(top_builddir)/node/src/libbitcoin_util.a \
$(top_builddir)/node/src/libbitcoin_consensus.a \
$(top_builddir)/node/src/crypto/libbitcoin_crypto_base.la \
$(top_builddir)/node/src/crypto/libbitcoin_crypto_avx2.la \
$(top_builddir)/node/src/crypto/libbitcoin_crypto_x86_shani.la \
$(top_builddir)/node/src/crypto/libbitcoin_crypto_sse41.la \
$(top_builddir)/contrib/secp256k1/libsecp256k1.la \
$(top_builddir)/node/src/libunivalue.la \
$(PYTHON_LIBS) \
$(BOOST_FILESYSTEM_LIB)

#$(top_builddir)/src/core/libl15-core.la \
#$(top_builddir)/src/tools/libl15-tools.la \
#$(top_builddir)/src/common/libl15-common.la \
#

#_libl15_core_pybind_la_LIBADD = \
#$(PYTHON_LIBS) \
#$(BOOST_FILESYSTEM_LIB)

#all-local: l15Core.py

install-completed-library:
	cp $(srcdir)/__init__.py $(top_builddir)/pybind/
	cp $(top_builddir)/pybind/.libs/_libl15-core-pybind.so $(top_builddir)/pybind/_libl15_core_pybind.so
