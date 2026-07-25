This document provides generic information for compiling EncFS.

If you are looking for specific instructions for your operating system or distribution,
take a look at the **[wiki](https://github.com/vgough/encfs/wiki)**.

## Building the Rust Implementation (Primary)

EncFS v2 (from 2026) is implemented in Rust. To build:

    cargo build --release

To run tests (`task test`), or:

    cargo nextest run --release

To install:

    cargo install --path .

Dependencies:
    * Rust toolchain (stable or nightly)
    * FUSE 3.12 or newer (libfuse3 on Linux, macFUSE on macOS, or a
      compatible fuse3 pkg-config package on FreeBSD)

On macOS, install macFUSE and make its `fuse3.pc` visible to pkg-config, for
example:

    brew install --cask macfuse
    export PKG_CONFIG_PATH="/Library/Filesystems/macfuse.fs/Contents/Resources/lib/pkgconfig:$PKG_CONFIG_PATH"

Cross builds need a target FUSE 3 sysroot and matching `PKG_CONFIG_*`
configuration; a host installation cannot satisfy the target link.
