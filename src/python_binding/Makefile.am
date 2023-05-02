AM_CPPFLAGS = \
 -I$(top_srcdir)/node/src \
 -I$(top_srcdir)/node/src/univalue/include \
 -I$(top_srcdir)/node/src/consensus \
 -I$(top_srcdir)/node/src/primitives \
 -I$(top_srcdir)/node/src/script \
 -I$(top_srcdir)/node/src/support \
 -I$(top_srcdir)/contrib/secp256k1/include \
 -I$(top_srcdir)/src/common \
 -I$(top_srcdir)/src/core \
 -I$(top_srcdir)/contrib/cex \
 -I$(top_srcdir)/src/inscribeit \
 -I$(top_srcdir)/src/python_binding \
$(PYTHON_CPPFLAGS) $(PYTHON_INCLUDES)

SWIG_FLAGS = -stdstl
SWIG_SOURCES = l15-core-pybind.i
SWIG_PYTHON_MODULE = libl15-core-pybind-wrap.cxx
CLEANFILES = $(SWIG_PYTHON_MODULE) libl15-core-pybind.py

BUILT_SOURCES = $(SWIG_PYTHON_MODULE)
EXTRA_DIST = $(SWIG_SOURCES)

$(SWIG_PYTHON_MODULE): $(SWIG_SOURCES) $(top_srcdir)/src/inscribeit/contract_error.hpp $(top_srcdir)/src/common/common_error.hpp $(top_srcdir)/src/core/transaction.hpp
	$(SWIG) -I$(top_srcdir)/src/common  -I$(top_srcdir)/src/core -I$(top_srcdir)/src/inscribeit -I$(top_srcdir)/node/src -I$(top_srcdir)/node/src/primitives -I$(top_srcdir)/node/src/script -I$(top_srcdir)/node/src/consensus -c++ -python -o $@ $<


lib_LTLIBRARIES = _libl15_core_pybind.la

_libl15_core_pybind_la_SOURCES = $(SWIG_PYTHON_MODULE) $(SWIG_SOURCES_CPP)
_libl15_core_pybind_la_LDFLAGS = -shared -module -avoid-version $(PYTHON_LDFLAGS) -Wl,--no-undefined

_libl15_core_pybind_la_LIBADD = \
    $(top_builddir)/src/core/libl15-core.la \
    $(top_builddir)/src/common/libl15-common.la \
    $(top_builddir)/node/src/secp256k1/libsecp256k1.la \
    $(top_builddir)/node/src/libbitcoinconsensus.la \
    $(top_builddir)/node/src/libunivalue.la \
    $(top_builddir)/src/inscribeit/libl15-inscribeit.la \
    $(PYTHON_LIBS)

install-completed-library:
	cp $(srcdir)/__init__.py $(top_builddir)/src/python_binding/
	cp $(top_builddir)/src/python_binding/.libs/_libl15_core_pybind.so $(top_builddir)/src/python_binding/_libl15_core_pybind.so

