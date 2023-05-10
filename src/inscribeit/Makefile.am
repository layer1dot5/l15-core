
AM_CPPFLAGS = \
 -I$(top_srcdir)/node/src \
 -I$(top_srcdir)/node/src/univalue/include \
 -I$(top_srcdir)/node/src/consensus \
 -I$(top_srcdir)/node/src/primitives \
 -I$(top_srcdir)/node/src/script \
 -I$(top_srcdir)/node/src/support \
 -I$(top_srcdir)/node/src/policy \
 -I$(top_srcdir)/contrib/secp256k1/include \
 -I$(top_srcdir)/src/common \
 -I$(top_srcdir)/src/core \
 -I$(top_srcdir)/contrib/cex


noinst_LTLIBRARIES = libl15-inscribeit.la
libl15_inscribeit_la_SOURCES = \
	inscription.cpp \
	contract_builder.cpp \
	create_inscription.cpp \
	swap_inscription.cpp

libl15_inscribeit_la_LDFLAGS = $(AM_LDFLAGS) -Wl,--gc-sections
libl15_inscribeit_la_CXXFLAGS = $(AM_CXXFLAGS) -ffunction-sections -fdata-sections
