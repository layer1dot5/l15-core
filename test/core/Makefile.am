
AM_CPPFLAGS = \
 -I$(top_srcdir)/test \
 -I$(top_srcdir)/contrib \
 -I$(top_srcdir)/contrib/cex \
 -I$(top_srcdir)/contrib/cli11 \
 -I$(top_srcdir)/contrib/secp256k1/include \
 -I$(top_srcdir)/node/src \
 -I$(top_srcdir)/node/src/univalue/include \
 -I$(top_srcdir)/node/src/consensus \
 -I$(top_srcdir)/node/src/support \
 -I$(top_srcdir)/src/common \
 -I$(top_srcdir)/src/p2p \
 -I$(top_srcdir)/src/tools \
 -I$(top_srcdir)/src/api \
 -I$(top_srcdir)/src/core


AM_LDFLAGS=-L$(top_builddir)/node/src -L$(top_builddir)/node/src/crypto

L15_LIBS = \
$(top_builddir)/src/api/libl15-api.la \
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

bin_PROGRAMS = test_threshold_sign test_taptree test_taproot test_node
#test_ptlc


test_taptree_SOURCES = test_taptree.cpp
test_taptree_LDADD = $(L15_LIBS)


test_taproot_SOURCES = test_taproot.cpp
test_taproot_LDADD = $(L15_LIBS)


#test_ptlc_SOURCES = test_ptlc.cpp
#test_ptlc_LIBADD = $(L15_LIBS)


test_node_SOURCES = test_node.cpp
test_node_LDADD = $(L15_LIBS)

test_threshold_sign_SOURCES = test_threshold_sign.cpp
test_threshold_sign_LDADD = $(L15_LIBS) $(ZMQ_LDFLAGS) $(ZMQ_LIBS)

