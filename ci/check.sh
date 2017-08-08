#!/bin/bash -eu

cmake --version

CFG=""
if [ "$TRAVIS_OS_NAME" = "osx" ]; then
  CFG="-DENABLE_NLS=OFF -DOPENSSL_ROOT_DIR=/usr/local/opt/openssl"
fi

if [[ ! -d build ]]
then
  mkdir build
fi

cd build
cmake .. ${CFG}
make -j2
make test

cd ..

