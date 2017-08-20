#!/bin/bash -eu

cmake --version

CFG=""
if uname -s | grep -q Linux; then
  if [ "$TRAVIS" == "true" ]; then
    CFG="-DLINT=ON"
  fi
fi
if uname -s | grep -q Darwin; then
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
make integration

cd ..

