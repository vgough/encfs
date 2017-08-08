#!/bin/bash -eu

if [ "$TRAVIS_OS_NAME" == "linux" ]; then
  sudo modprobe fuse
fi

if [ "$TRAVIS_OS_NAME" == "osx" ]; then
  brew cask install osxfuse
fi

