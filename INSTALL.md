This document provides generic information for compiling EncFS.

If you are looking for specific instructions for your distribution,
take a look at the page
**[Installing EncFS](https://github.com/vgough/encfs/wiki/Installing-Encfs)**
in the wiki.

Compiling EncFS
===============

EncFS uses the CMake toolchain to create makefiles.

Steps to build EncFS:

    mkdir build
    cd build
    cmake ..
    make

Optional, but strongly recommended, is running the test suite
to verify that the generated binaries work as expected
(runtime: 20 seconds)

    make test

The compilation process creates two executables, encfs and encfsctl in
the encfs directory.  You can install to in a system directory via

    make install

. If the default path (`/usr/local`) is not where you want things
installed, then set the CMAKE_INSTALL_PREFIX option when running cmake.  Eg:

    cmake .. -DCMAKE_INSTALL_PREFIX=/opt/local

Encfs and encfsctl can also be installed by hand.  They need no special
permissions.  You may also want the man pages encfs.1 and encfsctl.1.

Dependencies
============

EncFS depends on a number of libraries:

    * fuse : the userspace filesystem layer
    * openssl : used for cryptographic primitives
    * tinyxml2 : for reading and writing XML configuration files
    * gettext : internationalization support
    * libintl : internationalization support

Compiling on Debian and Ubuntu
==============================

See the automated build static in README.md for current build status on Ubuntu systems.

The build configuration files (circle.yml) always contains up-to-date
instructions to build EncFS on Ubuntu distributions.
