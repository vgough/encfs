This document provides generic information for compiling EncFS.

If you are looking for specific instructions for your distribution,
take a look at the page
**[Installing EncFS](https://github.com/vgough/encfs/wiki/Installing-Encfs)**
in the wiki.

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

    * fuse : the userspace filesystem layer
    * openssl or libressl : used for cryptographic primitives
    * tinyxml2 : for reading and writing XML configuration files
    * gettext : internationalization support
    * libintl : internationalization support
    * cmake : version 3.0.2 (Debian jessie version) or newer
    * GNU make or ninja-build : to run the build for cmake

Compiling on Debian and Ubuntu
==============================

See the automated build static in README.md for current build status on Ubuntu systems.

The build configuration files (circle.yml) always contains up-to-date
instructions to build EncFS on Ubuntu distributions.

On Debian Stable, additional installations from Backports branch might be
required (cmake 3.x for example, see https://backports.debian.org/ for instructions).
