
AM_CPPFLAGS = \
 -I$(top_srcdir)/contrib/nlohmann_json \
 -I$(top_srcdir)/test \
 -I$(top_srcdir)/contrib \
 -I$(top_srcdir)/contrib/cex \
 -I$(top_srcdir)/contrib/cli11 \
 -I$(top_srcdir)/$(SECP256K1_PATH)/include \
 -I$(top_srcdir)/$(NODE_PATH)/src \
 -I$(top_srcdir)/$(NODE_PATH)/src/crypto \
 -I$(top_srcdir)/$(NODE_PATH)/src/policy \
 -I$(top_srcdir)/$(NODE_PATH)/src/primitives \
 -I$(top_srcdir)/$(NODE_PATH)/src/consensus \
 -I$(top_srcdir)/$(NODE_PATH)/src/script \
 -I$(top_srcdir)/$(NODE_PATH)/src/support \
 -I$(top_srcdir)/src/common


L15_LIBS = \
$(top_builddir)/src/common/libl15-common.la \
$(top_builddir)/$(NODE_PATH)/src/libbitcoinconsensus.la \
$(top_builddir)/$(SECP256K1_PATH)/libsecp256k1.la \
$(BOOST_FILESYSTEM_LIB)

bin_PROGRAMS = test_utils


test_utils_SOURCES = test_utils.cpp
test_utils_LDADD = $(L15_LIBS)
