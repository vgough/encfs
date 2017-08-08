#!/bin/bash -eu

# Make sure we are in the directory this script is in.
cd "$(dirname "$0")"

if [[ ! -d build ]]
then
	mkdir build
	cd build
	cmake .. $*
	cd ..
fi

make -j2 -C build
make test -C build
make integration -C build

echo
echo 'Everything looks good, you can install via "make install -C build".'

