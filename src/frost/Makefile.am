AM_CPPFLAGS = \
 -I$(top_srcdir)/node/src \
 -I$(top_srcdir)/contrib/secp256k1/include \
 -I$(top_srcdir)/contrib/cex \
 -I$(top_srcdir)/contrib/cli11 \
 -I$(top_srcdir)/src/common \
 -I$(top_srcdir)/src/p2p \
 -I$(top_srcdir)/src/service \
 -I$(top_srcdir)/src/core


noinst_LTLIBRARIES = libl15-frost.la
libl15_frost_la_SOURCES = \
	frost_signer.cpp \
	frost_sm.cpp