# EncFS - an Encrypted Filesystem

_Build Status_
 - Travis: [![Travis CI](https://travis-ci.org/vgough/encfs.svg?branch=master)](https://travis-ci.org/vgough/encfs)

## About

EncFS provides an encrypted filesystem in user-space. It runs in userspace,
using the FUSE library for the filesystem interface. EncFS is open source
software, licensed under the LGPL.

EncFS is now over 15 years old (first release in 2003).  It was written because
older NFS and kernel-based encrypted filesystems such as CFS had not kept pace with Linux
development.  When FUSE became available, I wrote a CFS replacement for my own
use and released the first version to Open Source in 2003.

EncFS encrypts individual files, by translating all requests for the virtual
EncFS filesystem into the equivalent encrypted operations on the raw
filesystem.

For more info, see:

 - The excellent [encfs manpage](encfs/encfs.pod)
 - The technical overview in [DESIGN.md](DESIGN.md)

## Status

Over the last 15 years, a number of good alternatives have grown up.  Computing
power has increased to the point where it is reasonable to encrypt the entire
filesystem of personal computers (and even mobile phones!).  On Linux, ecryptfs
provides a nice dynamically mountable encrypted home directory, and is well
integrated in distributions I use, such as Ubuntu.

EncFS has been dormant for a while.  I've started cleaning up in order to try
and provide a better base for a version 2, but whether EncFS flowers again
depends upon community interest.  In order to make it easier for anyone to
contribute, it is moving a new home on GitHub (2014).  Since then project has
been updated a few times thanks to several contributors, so if you're
interested in EncFS, please dive in!

## Unique Features

EncFS has a few features still not found anywhere else (as of Dec 2014)
that may be interesting to you:

### Reverse mode

`encfs --reverse` provides an encrypted view of an unencrypted folder.
This enables encrypted remote backups using standard tools like rsync.

### Fast on classical HDDs

EncFS is typically *much* faster than ecryptfs for stat()-heavy workloads
when the backing device is a classical hard disk.
This is because ecryptfs has to to read each file header to determine
the file size - EncFS does not. This is one additional seek for each
stat.
See [PERFORMANCE.md](PERFORMANCE.md) for detailed benchmarks on
HDD, SSD and ramdisk.

### Works on top of network filesystems

EncFS works on network file systems (NFS, CIFS...), while ecryptfs
is known to still have [problems][1].

[1]: https://bugs.launchpad.net/ecryptfs/+bug/277578

## Development

The master branch contains the latest stable codebase.  This is where bug fixes
and improvments should go.

The [dev](https://github.com/vgough/encfs/tree/dev) branch contains experimental
work, some of which may be back-ported to the master branch when it is stable. The
dev branch is not stable, and there is no guarantee of backward compatibility
between changes.

## Donations

How about a nice email instead?

## Windows

EncFS works on Cygwin, there are also some Windows ports.

See [the wiki](https://github.com/vgough/encfs/wiki)
for additional info.

## FAQ

### What settings should I use for Dropbox?

Use **standard mode**. There [have](https://github.com/vgough/encfs/issues/141)
been [reports](https://github.com/vgough/encfs/issues/388)
of a pathological interaction of paranoia mode with Dropbox' rename
detection. The problem seems to be with `External IV chaining`, which is
not active in standard mode.
