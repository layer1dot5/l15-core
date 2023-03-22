AM_CPPFLAGS = \
 -I$(top_srcdir)/node/src \
 -I$(top_srcdir)/node/src/support \
 -I$(top_srcdir)/contrib/secp256k1/include \
 -I$(top_srcdir)/contrib/cex \
 -I$(top_srcdir)/contrib/cli11 \
 -I$(top_srcdir)/src/common \
 -I$(top_srcdir)/src/api \
 -I$(top_srcdir)/src/tools


noinst_LTLIBRARIES = libl15-tools.la
libl15_tools_la_SOURCES = \
	config.cpp nodehelper.cpp

libl15-tools.a: libl15-tools.la
	cp .libs/libl15-tools.a .

all-local: libl15-tools.a
