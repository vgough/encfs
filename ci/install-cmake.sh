set -x
set -e
if [ ! -e ci/cmake/bin/cmake ]; then
  # First x86_64 cmake compiled version
  wget http://www.cmake.org/files/v3.1/cmake-3.1.0-Linux-x86_64.tar.gz
  tar -xzf cmake-3.1.0-Linux-x86_64.tar.gz
  mv cmake-3.1.0-Linux-x86_64 ci/cmake
fi
