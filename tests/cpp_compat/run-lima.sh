#!/bin/bash
# Runs the C++ backward compatibility check (docs/testing/cpp-compatibility.md)
# with a Lima VM for the C++ side: builds the volumes there, copies them
# back, and checks them with this build.
#
#   LIMA_INSTANCE=default  the Lima instance to use (Ubuntu or Debian)
#   VOLUMES=<dir>          where the volumes land (default: a temp dir)
#   SKIP_CHECK=1           only build and copy the volumes
set -euo pipefail
cd "$(dirname "$0")/../.."
INSTANCE=${LIMA_INSTANCE:-default}
VOLUMES=${VOLUMES:-$(mktemp -d)/cppvols}

limactl start "$INSTANCE"
# Lima shares the home directory read-only, so files go in and out with
# `limactl copy`.
limactl shell "$INSTANCE" -- bash -c '
  command -v encfs >/dev/null || {
    sudo DEBIAN_FRONTEND=noninteractive apt-get update -qq
    sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -qq encfs fuse3
  }'
limactl copy tests/cpp_compat/make-volumes.sh "$INSTANCE:/tmp/make-volumes.sh"
limactl shell "$INSTANCE" -- bash -c '
  OUT=/tmp/encfs-compat/cppvols bash /tmp/make-volumes.sh &&
  tar czf /tmp/encfs-compat/cppvols.tgz -C /tmp/encfs-compat cppvols'
unpack=$(mktemp -d)
limactl copy "$INSTANCE:/tmp/encfs-compat/cppvols.tgz" "$unpack/cppvols.tgz"
tar xzf "$unpack/cppvols.tgz" -C "$unpack"
rm -rf "$VOLUMES"
mkdir -p "$(dirname "$VOLUMES")"
mv "$unpack/cppvols" "$VOLUMES"
rm -rf "$unpack"
limactl stop "$INSTANCE"
echo "volumes in $VOLUMES"

if [ -z "${SKIP_CHECK:-}" ]; then
  ENCFS_CPP_VOLUMES=$VOLUMES cargo test --test cpp_compat_test -- --ignored --nocapture
fi
