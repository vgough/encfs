set -x
set -e
if [ ! -e ci/cmake/bin/cmake ]; then
  #wget http://www.cmake.org/files/v3.1/cmake-3.1.0-Linux-x86_64.tar.gz
  tar -xzf ci/cmake-3.0.2-Linux-x86_64.tar.gz
  mv cmake-3.0.2-Linux-x86_64 ci/cmake
fi
