#!/bin/bash -eu

if [[ ! -d build ]]
then
	mkdir build
fi

cd build
cmake ..
make -j2
make test

cd ..

