# EncFS - an Encrypted Filesystem

**This project is NOT maintained.  For details, see the [Status](#status) section.**

## About

EncFS provides an encrypted filesystem in user-space. It runs in userspace,
using the [FUSE library](https://github.com/libfuse/libfuse) for the filesystem interface. EncFS is open source
software, licensed under the LGPL.

EncFS was first released in 2003, making it one of the earlier FUSE filesystems!
I wrote it because I needed to encrypt my data while traveling, and the existing NFS and
kernel-based encrypted filesystems such as CFS had not kept pace with Linux
development.  When FUSE became available, I wrote a CFS replacement for my own
use and later released it to Open Source when it seemed stable.

EncFS encrypts individual files, by translating all requests for the virtual
EncFS filesystem into the equivalent encrypted operations on the raw
filesystem.

For more info, see:

 - The [encfs manpage](legacy/encfs/encfs.pod) (legacy C++ version)
 - The technical overview in [DESIGN.md](DESIGN.md)

## Status

In the time since EncFS was written, a lot has changed in the security,
privacy, and computing landscapes. Computing power has increased enormously over
what a circa-2003 laptop can provide, and so it is no longer a performance burden
to encrypt the entire filesystem of a personal device. Software encryption has also
spread widely - data encryption is built into most systems and programs, so there is
far less of a need to have a separate encryption system.

EncFS has been dormant for a long time now. I haven't used or worked on EncFS in
many years. I've left the repository here because I don't want to prevent anyone
from using it if they have a need that can't be met otherwise. I'm sure that I have
some very old backups that would still require EncFS to access, so I expect that I
might have to compile it again someday.

Don't expect any updates on this project. You're free to fork it, of course, but
remember that this is a 20+yr old codebase which was only funded by personal
interest, so I wouldn't expect it to live up to modern-day coding standards.

If you're considering setting up a new encrypted filesystem wrapper, I'd recommend
looking into newer alternatives, such as the excellent [GoCryptFS](https://github.com/rfjakob/gocryptfs).

Thank you all for the early support, especially the FUSE author Miklos Szeredi,
and all the interesting discussions at Open Source and Linux meetups over the years.
Valient Gough
May 2024

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
