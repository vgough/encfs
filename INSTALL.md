This document provides generic information for compiling EncFS.

If you are looking for specific instructions for your operating system or distribution,
take a look at the **[wiki](https://github.com/vgough/encfs/wiki)**.

Compiling EncFS
===============

EncFS uses the CMake toolchain to create makefiles.

Quickest way to build and test EncFS :

    ./build.sh

Or following are the detailed steps to build EncFS:

    mkdir build
    cd build
    cmake ..
    make

If CMake can't find FUSE or OpenSSL, you can use the following options:

    cmake .. -DFUSE_ROOT_DIR=/pathto/fuse -DOPENSSL_ROOT_DIR=/pathto/openssl

Optional, but strongly recommended, is running the unit and integration
tests to verify that the generated binaries work as expected.  Unit
tests will run almost instantly:

    make unittests
    make test

Integration tests will take ~20 seconds to run and will mount an
encrypted filesystem and run tests on it:  
*running integration tests from root (or with sudo) will run additional ones*

    make integration

The compilation process creates two executables, encfs and encfsctl in
the encfs directory.  You can install to in a system directory via:

    make install

If the default path (`/usr/local`) is not where you want things
installed, then set the CMAKE_INSTALL_PREFIX option when running cmake.  Eg:

    cmake .. -DCMAKE_INSTALL_PREFIX=/opt/local

Encfs and encfsctl can also be installed by hand.  They need no special
permissions.  You may also want the man pages encfs.1 and encfsctl.1.

Dependencies
============

EncFS depends on a number of libraries:

    * fuse                   : the userspace filesystem layer
    * openssl / libressl     : used for cryptographic primitives
    * tinyxml2 (embeded)     : for reading and writing XML configuration files
    * gettext                : internationalization support
    * libintl                : internationalization support
    * cmake                  : version 3.0.2 (Debian jessie version) or newer
    * GNU make / ninja-build : to run the build for cmake
