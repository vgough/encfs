#!/bin/bash -eu

: ${INTEGRATION:=true}
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
    mkdir /tmp/bin
    ln -s $(ls -1 /tmp/cmake*/bin/cmake) /tmp/bin/
  fi
fi


