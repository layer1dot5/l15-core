
AM_CPPFLAGS = $(DEBUG_CPPFLAGS)\
 -I$(top_srcdir)/node/src \
 -I$(top_srcdir)/node/src/univalue/include \
 -I$(top_srcdir)/node/src/consensus \
 -I$(top_srcdir)/node/src/script \
 -I$(top_srcdir)/node/src/support \
 -I$(top_srcdir)/contrib/secp256k1/include \
 -I$(top_srcdir)/src/core \
 -I$(top_srcdir)/contrib/cex

AM_CXXFLAGS = $(DEBUG_CXXFLAGS)

noinst_LTLIBRARIES = libl15-app.la
libl15_app_la_SOURCES = \
	signing_mgr.cpp
