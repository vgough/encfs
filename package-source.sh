#!/bin/bash -eux

# Get git version, something like "v1.2.3"
GITVERSION=$(git describe --tags --dirty)
# Drop leading "v" to get just "1.2.3"
VERSION=${GITVERSION#v}
# Folder name inside the tarball should be "encfs-1.2.3"
PREFIX="encfs-$VERSION"

# Actually create archive
git archive --prefix "$PREFIX/" -o $PREFIX.tar.gz HEAD
