SUBDIRS =

if BUILD_APIS
SUBDIRS += core p2p
endif

if BUILD_SERVICES
SUBDIRS += service
endif

if BUILD_INSCRIBEIT
if !WASM_BIND
SUBDIRS += inscribeit
endif
endif

if BUILD_TOOLS

AM_CPPFLAGS = \
 -I$(top_srcdir)/test \
 -I$(top_srcdir)/contrib \
 -I$(top_srcdir)/contrib/cex \
 -I$(top_srcdir)/contrib/cli11 \
 -I$(top_srcdir)/contrib/secp256k1/include \
 -I$(top_srcdir)/node/src \
 -I$(top_srcdir)/node/src/univalue/include \
 -I$(top_srcdir)/node/src/consensus \
 -I$(top_srcdir)/node/src/script \
 -I$(top_srcdir)/node/src/support \
 -I$(top_srcdir)/src/common \
 -I$(top_srcdir)/src/p2p \
 -I$(top_srcdir)/src/tools \
 -I$(top_srcdir)/src/api \
 -I$(top_srcdir)/src/core \
 -I$(top_srcdir)/src/service


AM_LDFLAGS=$(ZMQ_LDFLAGS) -L$(top_builddir)/node/src -L$(top_builddir)/node/src/crypto

L15_LIBS = \
$(top_builddir)/src/service/libl15-srv.la \
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

bin_PROGRAMS = signer

signer_SOURCES = zmq_service.cpp signer.cpp
signer_LDADD = $(L15_LIBS) $(ZMQ_LIBS)

endif

