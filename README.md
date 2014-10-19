# EncFS - an Encrypted Filesystem

[![Build Status](https://travis-ci.org/vgough/encfs.svg)](https://travis-ci.org/vgough/encfs)

## About

EncFS provides an encrypted filesystem in user-space. It runs in userspace,
using the FUSE library for the filesystem interface. EncFS is open source
software, licensed under the LGPL.

EncFS is now over 10 years old (first release in 2003).  It was written because
older NFS-based encrypted filesystems such as CFS had not kept pace with Linux
development.  When FUSE became available, I wrote a CFS replacement for my own
use and released the first version to Open Source in 2003.

EncFS encrypts individual files, by translating all requests for the virtual
EncFS filesystem into the equivalent encrypted operations on the raw
filesystem.

## Status

Over the last 10 years, a number of good alternatives have grown up.  Computing
power has increased to the point where it is reasonable to encrypt the entire
filesystem of personal computers (and even mobile phones!).  On Linux, ecryptfs
provides a nice dynamically mountable encrypted home directory, and is well
integrated in distributions I use, such as Ubuntu.

EncFS has been dormant for a while.  I've started cleaning up in order to try
and provide a better base for a version 2, but whether EncFS flowers again
depends upon community interest.  In order to make it easier for anyone to
contribute, it is moving a new home on Github.  So if you're interested in
EncFS, please dive in!

## GitHub Transition

GitHub hosting for EncFS is a work in progress.  See also the original, and
more complete, introduction page at http://www.arg0.net/encfs

## Development

The master branch contains the latest stable codebase.  This is where bug fixes
and improvments should go.

The [dev](https://github.com/vgough/encfs/tree/dev) branch contains experimental
work, some of which may be back-ported to the master branch when it is stable. The
dev branch is not stable, and there is no guarantee of backward compatibility
between changes.

