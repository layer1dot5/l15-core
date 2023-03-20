ACLOCAL_AMFLAGS = -I build-aux/m4

SUBDIRS = contrib node src test

AM_CPPFLAGS = \
 -I$(top_srcdir)/src/common \
 -I$(top_srcdir)/src/core \
 -I$(top_srcdir)/src/api \
 -I$(top_srcdir)/src/tools \
 -I$(top_srcdir)/contrib/secp256k1/include \
 -I$(top_srcdir)/contrib/cli11 \
 -I$(top_srcdir)/contrib/cex \
 -I$(top_srcdir)/node/src \
 -I$(top_srcdir)/node/src/support


AM_LDFLAGS=-L$(top_builddir)/node/src

L15_LIBS = \
$(top_builddir)/src/api/libl15-api.la  \
$(top_builddir)/src/core/libl15-core.la  \
$(top_builddir)/src/tools/libl15-tools.la \
$(top_builddir)/src/common/libl15-common.la \
-lbitcoin_common -lbitcoin_util -lbitcoin_consensus \
$(top_builddir)/node/src/crypto/libbitcoin_crypto_base.la \
$(top_builddir)/node/src/crypto/libbitcoin_crypto_avx2.la \
$(top_builddir)/node/src/crypto/libbitcoin_crypto_x86_shani.la \
$(top_builddir)/node/src/crypto/libbitcoin_crypto_sse41.la \
$(top_builddir)/contrib/secp256k1/libsecp256k1.la \
$(top_builddir)/node/src/libunivalue.la \
$(BOOST_FILESYSTEM_LIB)


bin_PROGRAMS = l15-cli

l15_cli_SOURCES = src/cli.cpp
l15_cli_LDADD = $(L15_LIBS)

