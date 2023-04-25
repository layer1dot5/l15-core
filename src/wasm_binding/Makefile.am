
AM_CPPFLAGS = -DWASM_MODULE \
 -I$(top_srcdir)/src/common \
 -I$(top_srcdir)/src/core \
 -I$(top_srcdir)/src/inscribeit \
 -I$(top_srcdir)/contrib/secp256k1/include \
 -I$(top_srcdir)/contrib/cli11 \
 -I$(top_srcdir)/contrib/cex \
 -I$(top_srcdir)/node/src \
 -I$(top_srcdir)/node/src/univalue/include \
 -I$(top_srcdir)/node/src/consensus \
 -I$(top_srcdir)/node/src/script \
 -I$(top_srcdir)/node/src/support


AM_LDFLAGS=-L$(top_builddir)/node/src -L$(top_builddir)/node/src/crypto --post-js inscribeit.js


L15_LIBS = \
$(top_builddir)/src/core/libl15-core.la  \
$(top_builddir)/src/common/libl15-common.la \
$(top_builddir)/node/src/libbitcoinconsensus.la \
$(top_builddir)/contrib/secp256k1/libsecp256k1.la \
$(top_builddir)/node/src/libunivalue.la \
$(top_builddir)/src/inscribeit/libl15-inscribeit.la

BUILT_SOURCES = inscribeit.cpp inscribeit.js
EXTRA_DIST = inscribeit.idl

CLEANFILES = $(BUILT_SOURCES) l15.wasm

inscribeit.js: inscribeit.idl

inscribeit.cpp: inscribeit.idl
	webidl_binder $< inscribeit

l15.cpp: inscribeit.cpp

bin_PROGRAMS = l15.js

l15_js_SOURCES = l15.cpp
l15_js_LDADD = $(L15_LIBS)
