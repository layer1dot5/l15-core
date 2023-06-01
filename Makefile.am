ACLOCAL_AMFLAGS = -I build-aux/m4

SUBDIRS = contrib $(NODE_PATH) src test

if BUILD_SECP256K1
SUBDIRS += $(SECP256K1_PATH)
endif

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
$(top_builddir)/$(NODE_PATH)/src/crypto/libbitcoin_crypto_avx2.la \
$(top_builddir)/$(NODE_PATH)/src/crypto/libbitcoin_crypto_x86_shani.la \
$(top_builddir)/$(NODE_PATH)/src/crypto/libbitcoin_crypto_sse41.la \
$(BOOST_FILESYSTEM_LIB)

bin_PROGRAMS = l15-cli

l15_cli_SOURCES = src/cli.cpp
l15_cli_LDADD = $(L15_LIBS)

endif
