#!/bin/bash -eu

: ${CHECK:=false}
: ${INTEGRATION:=true}

cmake --version

CFG=$*
if [[ "$CHECK" == "true" ]]; then
  CFG="-DLINT=ON $CFG"
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
if [[ "$INTEGRATION" == "true" ]]; then
  make integration
fi

cd ..

echo
echo 'Everything looks good, you can install via "make install -C build".'
