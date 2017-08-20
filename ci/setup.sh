#!/bin/bash -eu

: ${TRAVIS:=false}

if uname -s | grep -q Linux; then
  sudo modprobe fuse
  # Download cmake > 3.5 so that we can run clang-tidy
  # Circle will use an older one (2.8 in Trusty)
  if [ "$TRAVIS" == "true" ]; then
    wget https://cmake.org/files/v3.9/cmake-3.9.1-Linux-x86_64.tar.gz -O /tmp/cmake.tar.gz
    tar -C /tmp/ -xf /tmp/cmake.tar.gz
    sudo rm -f $(which cmake)
    sudo ln -s $(ls -1 /tmp/cmake*/bin/cmake) /bin/
  fi
fi

if uname -s | grep -q Darwin; then
  brew cask install osxfuse
fi

