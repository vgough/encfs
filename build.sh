#!/bin/bash

set -eu

if [ ! -d build ]
then
	mkdir build
	cd build
	cmake ..
else
	cd build
fi

make

