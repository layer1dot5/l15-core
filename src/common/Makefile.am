
VERSION_MODULE = version.cpp

.PHONY: $(VERSION_MODULE)

$(VERSION_MODULE): $(top_srcdir)/version.sh Makefile
	echo '#include "version.hpp"' >$@
	(echo 'const char* const l15::Version::core_version = "'; $< $(top_srcdir); echo '";') | tr -d '\n' >>$@; echo >>$@
	(echo 'const char* const l15::Version::node_version = "'; $< $(top_srcdir)/$(NODE_PATH); echo '";')| tr -d '\n' >>$@; echo >>$@
	(echo 'const char* const l15::Version::secp256k1_version = "'; $< $(top_srcdir)/$(SECP256K1_PATH); echo '";')| tr -d '\n' >>$@; echo >>$@

AM_CPPFLAGS = \
 -I$(top_srcdir)/$(NODE_PATH)/src \
 -I$(top_srcdir)/$(NODE_PATH)/src/univalue/include \
 -I$(top_srcdir)/$(NODE_PATH)/src/consensus \
 -I$(top_srcdir)/$(NODE_PATH)/src/policy \
 -I$(top_srcdir)/$(NODE_PATH)/src/script \
 -I$(top_srcdir)/$(NODE_PATH)/src/support \
 -I$(top_srcdir)/$(SECP256K1_PATH)/include \
 -I$(top_srcdir)/src/common \
 -I$(top_srcdir)/contrib/cex


noinst_LTLIBRARIES = libl15-common.la
libl15_common_la_SOURCES = \
	common.cpp \
	utils.cpp

nodist_libl15_common_la_SOURCES = $(VERSION_MODULE)

CLEANFILES = $(VERSION_MODULE)