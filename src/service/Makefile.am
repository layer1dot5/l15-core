
AM_CPPFLAGS = $(ZMQ_CPPFLAGS) \
 -I$(top_srcdir)/$(NODE_PATH)/src \
 -I$(top_srcdir)/$(NODE_PATH)/src/univalue/include \
 -I$(top_srcdir)/$(NODE_PATH)/src/consensus \
 -I$(top_srcdir)/$(NODE_PATH)/src/script \
 -I$(top_srcdir)/$(NODE_PATH)/src/support \
 -I$(top_srcdir)/$(SECP256K1_PATH)/include \
 -I$(top_srcdir)/src/common \
 -I$(top_srcdir)/src/core \
 -I$(top_srcdir)/src/api \
 -I$(top_srcdir)/src/p2p \
 -I$(top_srcdir)/contrib/cex


noinst_LTLIBRARIES = libl15-srv.la


libl15_srv_la_SOURCES = \
	onchain_service.cpp \
	onchain_protocol.cpp \
	storage_service.cpp \
	generic_service.cpp \
	zmq_context.cpp

if BUILD_FROST
libl15_srv_la_SOURCES += signer_service.cpp
endif