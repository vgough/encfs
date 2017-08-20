#!/bin/bash -eu

: ${TRAVIS:=false}
: ${TRAVIS_SUDO:=true}

cmake --version

CFG=$*
if uname -s | grep -q Linux; then
  if [ "$TRAVIS" == "true" && CC="clang-4.0" ]; then
    CFG="-DLINT=ON $CFG"
  fi
fi

if uname -s | grep -q Darwin; then
  CFG="-DENABLE_NLS=OFF -DOPENSSL_ROOT_DIR=/usr/local/opt/openssl $CFG"
fi

if [[ ! -d build ]]
then
  mkdir build
fi

cd build
cmake .. ${CFG}
make -j2
make test
if [ "$TRAVIS_SUDO" == "true" ]; then
  make integration
fi

cd ..

