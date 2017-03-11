set -x
set -e
if [ ! -e ci/cmake/bin/cmake ]; then
  wget http://www.cmake.org/files/v3.2/cmake-3.2.0-Linux-x86_64.tar.gz
  tar -xzf cmake-3.2.0-Linux-x86_64.tar.gz
  mv cmake-3.2.0-Linux-x86_64 ci/cmake
fi
