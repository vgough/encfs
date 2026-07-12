# rfuse3
an async version fuse library for rust
This project contains code derived from [fuse3](https://github.com/Sherlock-Holo/fuse3)
Enhanced and optimized async FUSE implementation.

[![Cargo](https://img.shields.io/crates/v/rfuse3.svg)](
https://crates.io/crates/rfuse3)
[![Documentation](https://docs.rs/rfuse3/badge.svg)](
https://docs.rs/rfuse3)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](
https://github.com/Sherlock-Holo/rfuse3)

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
