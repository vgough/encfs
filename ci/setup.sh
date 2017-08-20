#!/bin/bash -eu

: ${INTEGRATION:=false}
: ${CHECK:=false}

if [[ "$INTEGRATION" == "true" ]]; then
  if uname -s | grep -q Linux; then
    sudo modprobe fuse
  elif uname -s | grep -q Darwin; then
    brew cask install osxfuse
  fi
fi

if [[ "$CHECK" == "true" ]]; then
  if uname -s | grep -q Linux; then
    wget https://cmake.org/files/v3.9/cmake-3.9.1-Linux-x86_64.tar.gz -O /tmp/cmake.tar.gz
    tar -C /tmp/ -xf /tmp/cmake.tar.gz
    sudo rm -f $(which cmake)
    sudo ln -s $(ls -1 /tmp/cmake*/bin/cmake) /bin/
  fi
fi


