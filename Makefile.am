SUBDIRS = node src test

AM_CPPFLAGS = -I$(top_srcdir)/src -I$(top_srcdir)/src/tools -I$(top_srcdir)/contrib/cli11
AM_LDFLAGS=-L$(top_builddir)/node/src -L$(top_builddir)/node/src/crypto

L15_LIBS = -lbitcoin_common -lbitcoin_util -lbitcoin_consensus \
-lbitcoin_crypto_base -lbitcoin_crypto_avx2 -lbitcoin_crypto_shani -lbitcoin_crypto_sse41 \
$(top_builddir)/node/src/secp256k1/libsecp256k1.la $(top_builddir)/node/src/univalue/libunivalue.la \
$(BOOST_FILESYSTEM_LIB) $(PTHREAD_LIBS)


bin_PROGRAMS = l15-cli

l15_cli_SOURCES = src/cli.cpp
l15_cli_LDADD =$(top_builddir)/src/tools/libl15-tools.la $(top_builddir)/src/core/libl15-core.la $(L15_LIBS)

