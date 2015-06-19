set -x
set -e
mkdir build
cd build
../ci/cmake/bin/cmake -DCMAKE_INSTALL_PREFIX:PATH=/tmp/encfs -DCMAKE_BUILD_TYPE=Debug ..
