
AM_CPPFLAGS = \
 -I$(top_srcdir)/test \
 -I$(top_srcdir)/contrib \
 -I$(top_srcdir)/contrib/cex \
 -I$(top_srcdir)/contrib/cli11 \
 -I$(top_srcdir)/$(SECP256K1_PATH)/include \
 -I$(top_srcdir)/$(NODE_PATH)/src \
 -I$(top_srcdir)/$(NODE_PATH)/src/univalue/include \
 -I$(top_srcdir)/$(NODE_PATH)/src/consensus \
 -I$(top_srcdir)/$(NODE_PATH)/src/support \
 -I$(top_srcdir)/src/common \
 -I$(top_srcdir)/src/p2p \
 -I$(top_srcdir)/src/tools \
 -I$(top_srcdir)/src/api \
 -I$(top_srcdir)/src/core


AM_LDFLAGS=-L$(top_builddir)/$(NODE_PATH)/src -L$(top_builddir)/$(NODE_PATH)/src/crypto

L15_LIBS = \
$(top_builddir)/src/api/libl15-api.la \
$(top_builddir)/src/core/libl15-core.la \
$(top_builddir)/src/tools/libl15-tools.la \
$(top_builddir)/src/common/libl15-common.la \
-lbitcoin_common -lbitcoin_util -lbitcoin_consensus \
$(top_builddir)/$(NODE_PATH)/src/crypto/libbitcoin_crypto_base.la \
$(top_builddir)/$(NODE_PATH)/src/crypto/libbitcoin_crypto_avx2.la \
$(top_builddir)/$(NODE_PATH)/src/crypto/libbitcoin_crypto_x86_shani.la \
$(top_builddir)/$(NODE_PATH)/src/crypto/libbitcoin_crypto_sse41.la \
$(top_builddir)/$(NODE_PATH)/src/libunivalue.la \
$(top_builddir)/$(SECP256K1_PATH)/libsecp256k1.la \
$(BOOST_FILESYSTEM_LIB)

bin_PROGRAMS =

if BUILD_FROST

  bin_PROGRAMS += test_p2p_frost
  test_p2p_frost_SOURCES = test_p2p_frost.cpp
  test_p2p_frost_LDADD = $(L15_LIBS)

endif

