AM_CPPFLAGS=-I$(top_srcdir)/node/src -I$(top_srcdir)/node/src/univalue/include -I$(top_srcdir)/src -I$(top_srcdir)/test
AM_LDFLAGS=-L$(top_builddir)/node/src -L$(top_builddir)/node/src/crypto

L15_LIBS = -lbitcoin_common -lbitcoin_util -lbitcoin_consensus \
-lbitcoin_crypto_base -lbitcoin_crypto_avx2 -lbitcoin_crypto_shani -lbitcoin_crypto_sse41 \
$(top_builddir)/node/src/secp256k1/libsecp256k1.la $(top_builddir)/node/src/univalue/libunivalue.la \
$(BOOST_PROGRAM_OPTIONS_LIB) $(BOOST_FILESYSTEM_LIB) $(PTHREAD_LIBS)



bin_PROGRAMS = test_ptlc

test_ptlc_SOURCES = test_ptlc.cpp
test_ptlc_LDADD =$(top_builddir)/src/core/libl15-core.la $(L15_LIBS)

#$(top_builddir)/src/tools/libl15-client.la 


