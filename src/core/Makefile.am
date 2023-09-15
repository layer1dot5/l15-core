
AM_CPPFLAGS = \
 -I$(top_srcdir)/$(NODE_PATH)/src \
 -I$(top_srcdir)/$(NODE_PATH)/src/univalue/include \
 -I$(top_srcdir)/$(NODE_PATH)/src/consensus \
 -I$(top_srcdir)/$(NODE_PATH)/src/primitives \
 -I$(top_srcdir)/$(NODE_PATH)/src/script \
 -I$(top_srcdir)/$(NODE_PATH)/src/support \
 -I$(top_srcdir)/$(NODE_PATH)/src/crypto \
 -I$(top_srcdir)/$(SECP256K1_PATH)/include \
 -I$(top_srcdir)/src/common \
 -I$(top_srcdir)/contrib/cex


noinst_LTLIBRARIES = libl15-core.la
libl15_core_la_SOURCES = \
	script_merkle_tree.cpp \
	channel_keys.cpp \
	master_key.cpp \
	key_factory.cpp \
	transaction.cpp

#	channel_contract.cpp
#	channel.cpp
