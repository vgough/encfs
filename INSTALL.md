This document provides generic information for compiling EncFS.

If you are looking for specific instructions for your distribution,
take a look at the page  
**[Installing EncFS](https://github.com/vgough/encfs/wiki/Installing-Encfs)**
in the wiki.

Compiling EncFS
===============

EncFS uses the GNU autoconf / automake toolchain to create makefiles.
Also, the configure script is automatically generated using autoreconf.

Compiling EncFS is a three-step process:

    autoreconf -if
    ./configure
    make

Optional, but strongly recommended, is running the test suite
to verfify that the generated binaries work as expected
(runtime: 20 seconds)

    make test

The compilation process creates two executables, encfs and encfsctl in
the encfs directory.  You can install to in a system directory via

    make install

. If the default path (`/usr/local`) is not where you want things
installed, then use the `--prefix` option to `configure` to specify the
install prefix.

Encfs and encfsctl can also be installed by hand.  They need no special
permissions.  You may also want the man pages encfs.1 and encfsctl.1.

Dependencies
============

EncFS depends on a number of libraries:

    openssl fuse boost-serialization gettext libtool libintl

Compiling on Debian and Ubuntu
==============================

We use Travis CI to automatically build-test every commit:

[![Build Status](https://travis-ci.org/vgough/encfs.svg)](https://travis-ci.org/vgough/encfs)

The [Travis configuration file .travis.yml](.travis.yml) therefore
always contains up-to-date instructions to build EncFS on Ubuntu
(Travis uses Ubuntu build machines).
