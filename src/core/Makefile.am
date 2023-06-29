
AM_CPPFLAGS = \
 -I$(top_srcdir)/node/src \
 -I$(top_srcdir)/node/src/univalue/include \
 -I$(top_srcdir)/node/src/consensus \
 -I$(top_srcdir)/node/src/primitives \
 -I$(top_srcdir)/node/src/script \
 -I$(top_srcdir)/node/src/support \
 -I$(top_srcdir)/node/src/crypto \
 -I$(top_srcdir)/contrib/secp256k1/include \
 -I$(top_srcdir)/src/common \
 -I$(top_srcdir)/contrib/cex


noinst_LTLIBRARIES = libl15-core.la
libl15_core_la_SOURCES = \
	script_merkle_tree.cpp \
	channel_keys.cpp \
	master_key.cpp \
	transaction.cpp

#	channel_contract.cpp
#	channel.cpp
