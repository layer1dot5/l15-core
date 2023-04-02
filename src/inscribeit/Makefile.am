
AM_CPPFLAGS = \
 -I$(top_srcdir)/node/src \
 -I$(top_srcdir)/node/src/univalue/include \
 -I$(top_srcdir)/node/src/consensus \
 -I$(top_srcdir)/node/src/script \
 -I$(top_srcdir)/node/src/support \
 -I$(top_srcdir)/contrib/secp256k1/include \
 -I$(top_srcdir)/src/common \
 -I$(top_srcdir)/src/core \
 -I$(top_srcdir)/contrib/cex


noinst_LTLIBRARIES = libl15-inscribeit.la
libl15_inscribeit_la_SOURCES = \
	contract_builder.cpp \
	create_inscription.cpp \
	swap_inscription.cpp

libinscribeit_la_CPPFLAGS = $(AM_LDFLAGS) -Wl,--gc-sections
libinscribeit_la_CPPFLAGS = $(AM_CPPFLAGS) -fPIC
libinscribeit_la_CXXFLAGS = $(AM_CXXFLAGS) -fPIC -ffunction-sections -fdata-sections
