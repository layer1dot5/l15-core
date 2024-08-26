ACLOCAL_AMFLAGS = -I build-aux/m4

VERSION_MODULE = version.cpp
BUILT_SOURCES = $(VERSION_MODULE)

SUBDIRS =

if BUILD_SECP256K1
SUBDIRS += $(SECP256K1_PATH)
endif

SUBDIRS += $(NODE_PATH) src

AM_CPPFLAGS = \
 -I$(top_srcdir)/src/common \
 -I$(top_srcdir)/src/core \
 -I$(top_srcdir)/$(SECP256K1_PATH)/include \
 -I$(top_srcdir)/contrib/cli11 \
 -I$(top_srcdir)/contrib/cex \
 -I$(top_srcdir)/$(NODE_PATH)/src \
 -I$(top_srcdir)/$(NODE_PATH)/src/univalue/include \
 -I$(top_srcdir)/$(NODE_PATH)/src/consensus \
 -I$(top_srcdir)/$(NODE_PATH)/src/script \
 -I$(top_srcdir)/$(NODE_PATH)/src/support


AM_LDFLAGS=-L$(top_builddir)/$(NODE_PATH)/src -L$(top_builddir)/$(NODE_PATH)/src/crypto

L15_LIBS =

if BUILD_TOOLS

SUBDIRS += test

L15_LIBS += \
$(top_builddir)/src/tools/libl15-tools.la \
$(top_builddir)/src/api/libl15-api.la

endif

L15_LIBS += \
$(top_builddir)/src/core/libl15-core.la  \
$(top_builddir)/src/common/libl15-common.la \
$(top_builddir)/$(NODE_PATH)/src/libbitcoinconsensus.la \
$(top_builddir)/$(NODE_PATH)/src/libunivalue.la \
$(top_builddir)/$(SECP256K1_PATH)/libsecp256k1.la

#$(top_builddir)/node/src/crypto/libbitcoin_crypto_base.la

if BUILD_TOOLS

AM_CPPFLAGS += \
 -I$(top_srcdir)/src/api \
 -I$(top_srcdir)/src/tools

L15_LIBS += \
$(BOOST_FILESYSTEM_LIB)

bin_PROGRAMS = l15-cli

l15_cli_SOURCES = src/cli.cpp
l15_cli_LDADD = $(L15_LIBS)

endif

lib_LTLIBRARIES = libl15.la

$(VERSION_MODULE): $(top_srcdir)/version.sh Makefile
	echo '#include "version.hpp"' >$@
	(echo 'const char* const l15::Version::core_version = "'; $< $(top_srcdir); echo '";') | tr -d '\n' >>$@; echo >>$@
	(echo 'const char* const l15::Version::node_version = "'; $< $(top_srcdir)/$(NODE_PATH); echo '";')| tr -d '\n' >>$@; echo >>$@
	(echo 'const char* const l15::Version::secp256k1_version = "'; $< $(top_srcdir)/$(SECP256K1_PATH); echo '";')| tr -d '\n' >>$@; echo >>$@


nodist_libl15_la_SOURCES = $(VERSION_MODULE)
libl15_la_LDFLAGS = -no-version -Wl,--whole-archive $(L15_LIBS)

CLEANFILES = $(VERSION_MODULE)
