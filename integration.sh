#!/bin/bash -eux

# Make sure we are in the directory this script is in.
cd "$(dirname "$0")"

if [ -d build ] ; then
    cd build
else
    mkdir build
    cd build
    cmake ..
fi
make -j$(nproc)
cd ..

#if [ ! -d ~/fuse-xfstests ] ; then
#    cd ~
#    git clone https://github.com/rfjakob/fuse-xfstests
#    cd fuse-xfstests
#    make
#    cd "$(dirname "$0")"
#fi

perl -I. -MTest::Harness -e '$Test::Harness::debug=1; $Test::Harness::verbose=1; runtests @ARGV;' integration/*.t.pl
