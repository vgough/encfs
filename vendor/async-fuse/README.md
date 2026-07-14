# asyncfuse
an async version fuse library for rust
This project contains code derived from [fuse3](https://github.com/Sherlock-Holo/fuse3)
Enhanced and optimized async FUSE implementation.

[![Cargo](https://img.shields.io/crates/v/asyncfuse.svg)](
https://crates.io/crates/asyncfuse)
[![Documentation](https://docs.rs/asyncfuse/badge.svg)](
https://docs.rs/asyncfuse)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](
https://github.com/brewfs/async-fuse)

## feature

- support unprivileged mode by using `fusermount3`
- support `readdirplus` to improve read dir performance
- support posix file lock
- support handles the `O_TRUNC` open flag
- support async direct IO
- support enable `no_open` and `no_open_dir` option

## still not support

- `ioctl` implement
- fuseblk mode

## unstable

- `poll`
- `notify_reply`

## Supported Rust Versions

The minimum supported version is 1.75.

## License

MIT
