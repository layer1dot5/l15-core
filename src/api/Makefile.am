
AM_CPPFLAGS = \
 -I$(top_srcdir)/$(NODE_PATH)/src \
 -I$(top_srcdir)/$(NODE_PATH)/src/univalue/include \
 -I$(top_srcdir)/$(NODE_PATH)/src/consensus \
 -I$(top_srcdir)/$(NODE_PATH)/src/primitives \
 -I$(top_srcdir)/$(NODE_PATH)/src/script \
 -I$(top_srcdir)/$(NODE_PATH)/src/support \
 -I$(top_srcdir)/$(SECP256K1_PATH)/include \
 -I$(top_srcdir)/src/common \
 -I$(top_srcdir)/src/p2p \
 -I$(top_srcdir)/src/core \
 -I$(top_srcdir)/contrib/cex


noinst_LTLIBRARIES = libl15-api.la
libl15_api_la_SOURCES = \
	chain_api.cpp \
	wallet_api.cpp \
	exechelper.cpp

if BUILD_FROST

  libl15_api_la_SOURCES += signer_api.cpp

endif