AM_CPPFLAGS = \
 -DZMQ_BUILD_DRAFT_API=1 $(ZMQ_CPPFLAGS) \
 -I$(top_srcdir)/node/src \
 -I$(top_srcdir)/contrib/secp256k1/include \
 -I$(top_srcdir)/contrib/cex \
 -I$(top_srcdir)/contrib/cli11 \
 -I$(top_srcdir)/src/common \
 -I$(top_srcdir)/src/core \
 -I$(top_srcdir)/src/service \
 -I$(top_srcdir)/src/p2p


noinst_LTLIBRARIES = libl15-test.la
libl15_test_la_SOURCES = zmq_service.cpp