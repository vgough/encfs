
if BUILD_NLS
NLS_DIR = po
endif

SUBDIRS = encfs m4 $(NLS_DIR)


EXTRA_DIST = config.rpath mkinstalldirs  encfs.spec makedist.sh makedist2.sh \
	     intl/autosprintf.h intl/autosprintf.cpp intl/gettext.h

AUTOMAKE_OPTIONS = foreign 

MAINTAINERCLEANFILES = aclocal.m4 


ACLOCAL_AMFLAGS = -I m4 -I m4-local
