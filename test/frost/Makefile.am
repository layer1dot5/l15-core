
AM_CPPFLAGS = \
 -DZMQ_BUILD_DRAFT_API=1 $(ZMQ_CPPFLAGS) \
 -I$(top_srcdir)/test/testlib \
 -I$(top_srcdir)/contrib \
 -I$(top_srcdir)/contrib/cex \
 -I$(top_srcdir)/contrib/cli11 \
 -I$(top_srcdir)/contrib/secp256k1/include \
 -I$(top_srcdir)/node/src \
 -I$(top_srcdir)/node/src/univalue/include \
 -I$(top_srcdir)/node/src/consensus \
 -I$(top_srcdir)/src/common \
 -I$(top_srcdir)/src/p2p \
 -I$(top_srcdir)/src/tools \
 -I$(top_srcdir)/src/core \
 -I$(top_srcdir)/src/service \
 -I$(top_srcdir)/src/frost

AM_LDFLAGS=-L$(top_builddir)/node/src

L15_LIBS = \
$(top_builddir)/test/testlib/libl15-test.la \
$(top_builddir)/src/frost/libl15-frost.la \
$(top_builddir)/src/service/libl15-srv.la \
$(top_builddir)/src/core/libl15-core.la \
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

bin_PROGRAMS = test_frost_signer

test_frost_signer_CPPFLAGS = $(AM_CPPFLAGS) $(ZMQ_CPPFLAGS)
test_frost_signer_SOURCES = test_frost_signer.cpp
test_frost_signer_LDADD = $(ZMQ_LDFLAGS) $(L15_LIBS) $(ZMQ_LIBS)

