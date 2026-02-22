# EncFS - an Encrypted Filesystem

![Rust CI](https://github.com/vgough/encfs/actions/workflows/ci.yml/badge.svg)


## About

EncFS provides an encrypted virtual filesystem. It runs in userspace,
using the FUSE library. EncFS is open source software, licensed under the LGPL.

EncFS was first released in 2003, making it one of the earlier FUSE filesystems!
At the time, there were few options available for Linux, and the kernel modules
that were available had not kept pace with Linux development. This meant that
every kernel upgrade was likely to break the filesystem until the module was
updated. When FUSE became available, I wrote a CFS replacement for my own
use and released it to Open Source.

EncFS encrypts individual files, by translating all requests for the virtual
EncFS filesystem into the equivalent encrypted operations on the raw
filesystem.

For more info, see:

 - The technical overview in [DESIGN.md](docs/DESIGN.md)

If you're considering setting up a new encrypted filesystem, I'd recommend
looking into newer alternatives, such as the excellent
[GoCryptFS](https://github.com/rfjakob/gocryptfs), or else use full-disk
encryption when possible.

## Status - Jan 2026

Data has a long lifespan, and people still have data that was encrypted with EncFS.
I switched to using full-disk encryption when it became performant enough, and
haven't worked on the codebase in years. I've recently begun porting EncFS
to Rust as a way to learn Rust, which turned out to be easier than I'd expected
with the help of modern-day developer tooling.

The old C++ code has been removed. The code can be found in old branches, or old
releases, but is not being maintained.

EncFS was a mature program, so while the new implementation is already functional 
in *read-only* mode, it is still considered *alpha* and I wouldn't trust it for
important data. 

Overall status

- Core
  - [x] Read operations
  - [x] Basic write operations
  - [x] Truncate w/ holes
- Improvements
  - [x] new tamper-safe configuration file (v7 config)
  - [x] support for a new key derivation function (Argon2id)
  - [x] new block encryption mode (aes-gcm-siv)
- Extended features
  - [ ] reverse encryption mode
- Multi-language
  - [x] basic multi-language support
  - [ ] translations beyond auto-generated FR and DE strings

## FAQ

### What settings should I use for Dropbox?

Disable `External IV chaining`. There [have](https://github.com/vgough/encfs/issues/141)
been [reports](https://github.com/vgough/encfs/issues/388)
of a pathological interaction of IV chaining mode with Dropbox' rename
detection.

IV chaining is on by default, so it must be disabled when creating a new
filesystem: `encfsctl new --no-chained-iv ...`
