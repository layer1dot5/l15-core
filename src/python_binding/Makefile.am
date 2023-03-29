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
 -I$(top_srcdir)/contrib/cex \
 -I$(top_srcdir)/src/inscribeit \
 $(PYBIND_CPPFLAGS)

# $(top_srcdir)/node/src/support/cleanse.cpp \
# $(top_srcdir)/node/src/bech32.cpp \
# $(top_srcdir)/node/src/primitives/transaction.cpp

SWIG_SOURCES_CPP = \
 l15-core-pybind.cpp

SWIG_FLAGS = -stdstl
SWIG_SOURCES = l15-core-pybind.i
SWIG_PYTHON_MODULE = libl15-core-pybind-wrap.cxx
CLEANFILES = $(SWIG_PYTHON_MODULE) libl15-core-pybind.py

BUILT_SOURCES = $(SWIG_PYTHON_MODULE)
EXTRA_DIST = $(SWIG_SOURCES)

$(SWIG_PYTHON_MODULE): $(SWIG_SOURCES)
	$(SWIG) -c++ -python -o $@ $<

AM_LDFLAGS = -L$(top_builddir)/node/src \
             -L$(top_builddir)/node/src/crypto

pkglib_LTLIBRARIES = _libl15-core-pybind.la

_libl15_core_pybind_la_SOURCES = $(SWIG_PYTHON_MODULE) $(SWIG_SOURCES_CPP)
_libl15_core_pybind_la_CXXFLAGS = $(PYTHON_INCLUDES) $(PYTHON_CPPFLAGS)
_libl15_core_pybind_la_LDFLAGS = -shared -module -avoid-version $(PYTHON_LDFLAGS)

_libl15_core_pybind_la_LIBADD = \
    $(top_builddir)/src/core/libl15-core.la  \
    $(top_builddir)/src/common/libl15-common.la \
    $(top_builddir)/node/src/libbitcoinconsensus.la \
    $(top_builddir)/contrib/secp256k1/libsecp256k1.la \
    $(top_builddir)/node/src/libunivalue.la \
    $(top_builddir)/src/inscribeit/libl15-inscribeit.la \
    $(PYTHON_LIBS) \
    $(BOOST_FILESYSTEM_LIB)

install-completed-library:
	cp $(srcdir)/__init__.py $(top_builddir)/src/python_binding/
	cp $(top_builddir)/src/python_binding/.libs/_libl15-core-pybind.so $(top_builddir)/src/python_binding/_libl15_core_pybind.so

