#!/bin/bash -eu

: ${INTEGRATION:=true}

if [[ "$INTEGRATION" == "true" ]]; then
  if uname -s | grep -q Linux; then
    sudo modprobe fuse
  elif uname -s | grep -q FreeBSD; then
    kldload fuse
  elif uname -s | grep -q Darwin; then
    brew cask install osxfuse
    brew reinstall openssl
  fi
fi
