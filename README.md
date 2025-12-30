# EncFS - an Encrypted Filesystem

![Rust CI](https://github.com/vgough/encfs/actions/workflows/ci.yml/badge.svg)


## About

EncFS provides an encrypted virtual filesystem. It runs in userspace,
using the FUSE library.
EncFS is open source software, licensed under the LGPL.

EncFS was first released in 2003, making it one of the earlier FUSE filesystems!
At the time, there were few options available for Linux, and the kernal modules
that were available had not kept pace with Linux development. This meant that
every kernel upgrade was likely to break the filesystem until the module was
updated. When FUSE became available, I wrote a CFS replacement for my own
use and released it to Open Source.

EncFS encrypts individual files, by translating all requests for the virtual
EncFS filesystem into the equivalent encrypted operations on the raw
filesystem.

For more info, see:

 - The [encfs manpage](legacy/encfs/encfs.pod) (legacy C++ version)
 - The technical overview in [DESIGN.md](DESIGN.md)

If you're considering setting up a new encrypted filesystem, I'd recommend
looking into newer alternatives, such as the excellent
[GoCryptFS](https://github.com/rfjakob/gocryptfs).

## Status - Dec 2025

Data has a long lifespan, and people still have data that was encrypted with EncFS.
I haven't had time or desire to dive into a 23+ year old C++ codebase, and so
the original code hasn't seen many changes. I've recently begun porting EncFS
to Rust as a way to learn Rust. The original goal was to port enough to get
a read-only filesystem working.

Read-only access turned out to be easier than I'd expected, so a stretch goal
is to implement the write APIs.

The old C++ code can still be found in the `legacy` directory, although that may
go away soon. Don't expect new features, this is based on an old design which
was based on what was readily available 

EncFS was a mature program, so while the port is already mostly functional 
in *read-only* mode, I wouldn't trust it yet for modifying data. While the
functionality is likely to be implemented, the new version doesn't have the
nice-to-have features like internationalization of messages.

Some of the issues with the EncFS model would require a new design to resolve,
which is not currently planned.

## FAQ

### What settings should I use for Dropbox?

Use **standard mode**. There [have](https://github.com/vgough/encfs/issues/141)
been [reports](https://github.com/vgough/encfs/issues/388)
of a pathological interaction of paranoia mode with Dropbox' rename
detection. The problem seems to be with `External IV chaining`, which is
not active in standard mode.
