
include $(top_srcdir)/Makefile.common

ALL_INCLUDES = @RLOG_CFLAGS@ @OPENSSL_CFLAGS@
ALL_LDFLAGS = @RLOG_LIBS@ @OPENSSL_LIBS@ @FUSE_LIBS@

INCLUDES = $(all_includes) -I../intl

AM_CXXFLAGS = -DRLOG_COMPONENT="encfs" $(ALL_INCLUDES) 

if BUILD_NLS
# define a C macro LOCALEDIR indicating where catalogs will be installed
#localedir = $(datadir)/locale

AM_CXXFLAGS += -DLOCALEDIR=\"$(localedir)\"
ALL_LDFLAGS += @LIBINTL@
endif

lib_LTLIBRARIES = libencfs.la
bin_PROGRAMS = encfs encfsctl
dist_bin_SCRIPTS = encfssh
noinst_PROGRAMS = test

all-local: encfs-man.html

#encfs_LDADD   = libencfs.la -lfuse
#encfsctl_LDADD = libencfs.la -lfuse
#test_LDADD   = libencfs.la -lfuse
encfs_LDADD   = libencfs.la $(ALL_LDFLAGS)
encfsctl_LDADD = libencfs.la $(ALL_LDFLAGS)
test_LDADD   = libencfs.la $(ALL_LDFLAGS)

if BUILD_STATIC
encfs_LDFLAGS = -all-static
encfsctl_LDFLAGS = -all-static
test_LDFLAGS = -all-static
endif

# CURRENT : REVISION : AGE
#   +1  :  0  :  +1       => new interface that does not break old one
#   +1  :  0  :   0       => new interface that breaks old one
#       :     :   0       => no new interfaces, but breaks old apps
#       :  +1 :           => internal changes, nothing breaks
#
libencfs_la_LDFLAGS = -version-info 3:1:0
libencfs_la_LIBADD = -lrlog

EXTRASRC = ../intl/autosprintf.cpp
if BUILD_OPENSSL
if BUILD_SSLCIPHER
EXTRASRC += SSL_Cipher.cpp
endif
endif

libencfs_la_SOURCES = \
    readpassphrase.cpp \
    base64.cpp \
    ConfigReader.cpp \
    ConfigVar.cpp \
    Context.cpp \
    Cipher.cpp \
    CipherKey.cpp \
    FileIO.cpp \
    RawFileIO.cpp \
    BlockFileIO.cpp \
    CipherFileIO.cpp \
    MACFileIO.cpp \
    NameIO.cpp \
    StreamNameIO.cpp \
    BlockNameIO.cpp \
    NullNameIO.cpp \
    Interface.cpp \
    MemoryPool.cpp \
    NullCipher.cpp \
    DirNode.cpp \
    FileNode.cpp \
    FileUtils.cpp \
    ${EXTRASRC}


encfs_SOURCES = \
    encfs.cpp \
    openssl.cpp \
    main.cpp

test_SOURCES = \
    test.cpp

encfsctl_SOURCES = \
    encfsctl.cpp

noinst_HEADERS = \
    base64.h \
    BlockFileIO.h \
    BlockNameIO.h \
    CipherFileIO.h \
    Cipher.h \
    CipherKey.h \
    ConfigReader.h \
    ConfigVar.h \
    Context.h \
    DirNode.h \
    encfs.h \
    FileIO.h \
    FileNode.h \
    FileUtils.h \
    Interface.h \
    i18n.h \
    MACFileIO.h \
    MemoryPool.h \
    Mutex.h \
    NameIO.h \
    NullCipher.h \
    NullNameIO.h \
    openssl.h \
    Range.h \
    RawFileIO.h \
    readpassphrase.h \
    SSL_Cipher.h \
    StreamNameIO.h

man_MANS=encfs.1 encfsctl.1
EXTRA_DIST = encfs.pod encfsctl.pod encfs.1 encfsctl.1 encfs-man.html

if BUILD_MAN
SUFFIXES = .1 .pod
# since we have POD2MAN, we can specify how to rebuild encfs.1 if necessary
.pod.1:
	@POD2MAN@ --section=1 --release=@VERSION@ --center="Encrypted Filesystem" $< $@

CLEANFILES = encfs.1 encfsctl.1
endif

if BUILD_MANHTML
encfs-man.html: encfs.pod
	@POD2HTML@ encfs.pod > $@
endif

