
VERSION_MODULE = version.cpp

.PHONY: $(VERSION_MODULE)

$(VERSION_MODULE): $(top_srcdir)/version.sh Makefile
	echo '#include "version.hpp"' >$@
	(echo 'const char* const l15::Version::core_version = "'; $< $(top_srcdir); echo '";') | tr -d '\n' >>$@; echo >>$@
	(echo 'const char* const l15::Version::node_version = "'; $< $(top_srcdir)/node; echo '";')| tr -d '\n' >>$@; echo >>$@
	(echo 'const char* const l15::Version::secp256k1_version = "'; $< $(top_srcdir)/contrib/secp256k1; echo '";')| tr -d '\n' >>$@; echo >>$@

AM_CPPFLAGS = \
 -I$(top_srcdir)/node/src \
 -I$(top_srcdir)/node/src/univalue/include \
 -I$(top_srcdir)/node/src/consensus \
 -I$(top_srcdir)/node/src/policy \
 -I$(top_srcdir)/node/src/script \
 -I$(top_srcdir)/node/src/support \
 -I$(top_srcdir)/contrib/secp256k1/include \
 -I$(top_srcdir)/src/common \
 -I$(top_srcdir)/contrib/cex


noinst_LTLIBRARIES = libl15-common.la
libl15_common_la_SOURCES = \
	common.cpp \
	utils.cpp

nodist_libl15_common_la_SOURCES = $(VERSION_MODULE)

CLEANFILES = $(VERSION_MODULE)