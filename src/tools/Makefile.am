AM_CPPFLAGS = $(DEBUG_CPPFLAGS) \
 -I$(top_srcdir)/node/src \
 -I$(top_srcdir)/contrib/secp256k1/include \
 -I$(top_srcdir)/contrib/cex \
 -I$(top_srcdir)/contrib/cli11 \
 -I$(top_srcdir)/src/common \
 -I$(top_srcdir)/src/core \
 -I$(top_srcdir)/src/tools

AM_CXXFLAGS = $(DEBUG_CXXFLAGS)

noinst_LTLIBRARIES = libl15-tools.la
libl15_tools_la_SOURCES = \
	config.cpp nodehelper.cpp