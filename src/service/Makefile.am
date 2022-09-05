
AM_CPPFLAGS = $(ZMQ_CPPFLAGS) \
 -I$(top_srcdir)/node/src \
 -I$(top_srcdir)/node/src/univalue/include \
 -I$(top_srcdir)/node/src/consensus \
 -I$(top_srcdir)/node/src/script \
 -I$(top_srcdir)/node/src/support \
 -I$(top_srcdir)/contrib/secp256k1/include \
 -I$(top_srcdir)/src/common \
 -I$(top_srcdir)/src/core \
 -I$(top_srcdir)/contrib/cex


noinst_LTLIBRARIES = libl15-srv.la


libl15_srv_la_SOURCES = \
	onchain_service.cpp \
	onchain_protocol.cpp

