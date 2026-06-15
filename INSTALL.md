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
    * FUSE library (libfuse or OSXFUSE on macOS)
