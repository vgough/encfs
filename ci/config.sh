set -x
set -e
mkdir build
cd build
cmake -DCMAKE_INSTALL_PREFIX:PATH=/tmp/encfs -DCMAKE_BUILD_TYPE=Debug -DMINIGLOG=ON ..
