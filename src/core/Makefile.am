
AM_CPPFLAGS = \
 -I$(top_srcdir)/node/src \
 -I$(top_srcdir)/node/src/univalue/include \
 -I$(top_srcdir)/node/src/consensus \
 -I$(top_srcdir)/node/src/script \
 -I$(top_srcdir)/node/src/support \
 -I$(top_srcdir)/contrib/secp256k1/include \
 -I$(top_srcdir)/src \
 -I$(top_srcdir)/src/core \
 -I$(top_srcdir)/contrib/cex

noinst_LTLIBRARIES = libl15-core.la
libl15_core_la_SOURCES = \
	script_merkle_tree.cpp \
	channel_keys.cpp \
	channel_contract.cpp \
	channel.cpp \
	chain_api.cpp \
	wallet_api.cpp \
	utils.cpp \
	exechelper.cpp \
	signer_api.cpp
