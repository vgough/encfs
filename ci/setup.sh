#!/bin/bash -eu

: ${INTEGRATION:=true}

if [[ "$INTEGRATION" == "true" ]]; then
  if uname -s | grep -q Linux; then
    sudo modprobe fuse
  elif uname -s | grep -q FreeBSD; then
    kldload fuse
    # Remove non fully supported reverse tests for now
    rm integration/reverse.t.pl
  elif uname -s | grep -q Darwin; then
    brew cask install osxfuse
    brew reinstall openssl
  fi
fi
