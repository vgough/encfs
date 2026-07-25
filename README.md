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

## Status - Jul 2026

Data has a long lifespan, and people still have data that was encrypted with EncFS.
This project has been mostly dormant for years. I've recently ported EncFS
to Rust as a way to learn Rust and apply newer development tools.

The old C++ code has been removed. The code can be found in old branches, or old
releases, but is not being maintained.

EncFS was a mature program, so while the new implementation is already functional 
it is still considered a *beta* release, and I would always have a separate backup
for anything stored in it.

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
  - [x] reverse encryption mode
- Multi-language
  - [x] basic multi-language support
  - [ ] translations beyond auto-generated FR and DE strings


## Getting started

### Upgrading from a previous config (V4/V5/V6):

While the primary focus has been on providing an updated codebase to support reading old encrypted content,
since writes have been implemented it also makes sense to support newer algorithms.

Some upgrades can be applied to existing filesystems. Use
`encfsctl passwd --upgrade <rootdir>` to convert an existing filesystem to the
V7 config format and switch to the Argon2id key-derivation function. You will be
prompted for the current password and a new one. The tool writes a new `.encfs7`
file; the old config file is left in place and can be removed after verification.
Ensure the volume is not mounted when upgrading.

For scripted or non-interactive setup, use `encfsctl new --stdinpass` or `--extpass <program>`, 
and `encfs -S` or `--extpass` for mounting.


### Create a new encrypted filesystem and mount it in two steps.

**1. Create a new EncFS config** in the directory that will hold the encrypted
files. This creates a V7 config (e.g. `.encfs7`) and prompts for a password:

```bash
mkdir -p ~/encrypted
encfsctl new ~/encrypted
```

**2. Mount the filesystem** with encfs. The first argument is the encrypted root
directory (where the config lives), the second is the mount point where you will
see plaintext:

```bash
mkdir -p ~/mount
encfs ~/encrypted ~/mount
```

You can now read and write files under `~/mount`; they are stored encrypted
under `~/encrypted`. When finished, unmount:

```bash
fusermount -u ~/mount   # Linux
# or: umount ~/mount    # macOS / FreeBSD
```


## Reverse encryption mode (encfsr)

The **encfsr** binary provides *reverse* encryption: your **plaintext** files
live on disk in a source directory, and encfsr mounts a **read-only** virtual
filesystem that exposes the **encrypted** view of that directory. Use this when
you want to back up or sync an encrypted representation of local data (e.g. to
an untrusted or cloud storage) without storing plaintext there.

- **Normal encfs**: encrypted dir → mount point shows plaintext (read/write).
- **encfsr**: plaintext dir → mount point shows encrypted view (read-only).

### Requirements

- A **V7** EncFS config (e.g. `.encfs7`). Older configs are not supported.
- Config should be created **without** per-file IV headers: use
  `encfsctl new --no-unique-iv ...` so the content is deterministic and suitable
  for reverse mode.

### Usage

```bash
encfsr <config> <source_dir> <mount_point>
```

Example: plaintext in `~/Documents`, encrypted view at `/mnt/enc`:

```bash
encfsr ~/Documents/.encfs7 ~/Documents /mnt/enc
```

Then copy or sync from `/mnt/enc` to your backup/cloud target; the content and filenames there are encrypted.

Options (same as encfs where applicable):

- `-f` / `--foreground` — run in foreground (do not daemonize).
- `-S` / `--stdinpass` — read password from stdin (e.g. for scripts).
- `--extpass <program>` — run a program to get the password; `RootDir` is set to the source directory.

Unmount when done: `fusermount -u <mount_point>` (Linux) or `umount <mount_point>` (macOS/FreeBSD).

## Benchmarks

### Algorithm benchmark

`encfsctl speed` will test algorithm performance on your machine. The crypto algorithms are provided
by 3rd party crates, they are not implemented here.

Example output:
```
> ./target/release/encfsctl speed
encfsctl v2.0.0-beta.4; 2026-07-25 macos/aarch64
cpu: Apple M4 Pro; with AES hardware acceleration

AES-256-GCM-SIV            1869.56 MB/s  (default, V7 file content)
AES-128-GCM-SIV            1891.51 MB/s
AES-256-CBC (legacy)       1659.87 MB/s
AES-192-CBC (legacy)       1849.51 MB/s
AES-128-CBC (legacy)       2039.94 MB/s
Blowfish-CBC (legacy)       180.26 MB/s  (deprecated)
```

### Filesystem benchmark

The repository includes an automated filesystem benchmark based on `mdtest`,
which is distributed as part of IOR. It creates a fresh V7 EncFS filesystem,
mounts it with the release binaries, runs all of mdtest's standard directory and
file phases, unmounts it, and removes its temporary files. The benchmark requires:

- a working FUSE installation and permission to mount a FUSE filesystem;
- `mdtest` on `PATH` (or an explicit `MDTEST_BIN`);
- `mpirun` only when running more than one rank.

First save a baseline for the current machine, then compare later runs with it:

```bash
task benchmark-save-baseline
task benchmark
```

The default workload uses one rank, 1,000 items per iteration, five iterations,
and 4,096-byte writes and reads. Results are normalized as mean operations per
second for every operation in mdtest's `SUMMARY rate` table. Comparisons print
every baseline/current/delta value, but performance changes are informational and
never fail the command. Command failures, invalid output, mount/unmount failures,
and missing or incompatible baselines do fail with a diagnostic.

Task variables can select another baseline or workload. For example:

```bash
task benchmark-save-baseline BENCH_ITEMS=100 BENCH_ITERATIONS=2
task benchmark BENCH_ITEMS=100 BENCH_ITERATIONS=2
task benchmark BENCH_PROCS=4 MPIRUN_BIN=/opt/mpi/bin/mpirun
task benchmark BENCH_BASELINE=/path/to/shared-baseline.json MDTEST_BIN=/opt/ior/bin/mdtest
```

The supported variables are `BENCH_BASELINE`, `BENCH_ITEMS`,
`BENCH_ITERATIONS`, `BENCH_PROCS`, `BENCH_BYTES`, `MDTEST_BIN`, `MPIRUN_BIN`,
and `BENCH_MOUNT_TIMEOUT_SECS`. The default baseline is
`.benchmarks/filesystem-baseline.json`, which is ignored by Git. Baselines are
machine-specific: compare results on the same host under similar load. The tool
warns if the recorded host context or mdtest version differs.

### FUSE Support

This has been tested with libfuse3-dev on Linux (Ubuntu 24.04), and on MacOS with MacFuse 5.3.x.

The FUSE support comes from [`typed-fuse`](https://github.com/vgough/typed-fuse),
which is a modern Rust FUSE library on top of the C bindings from libfuse. I tried many FUSE libraries
for Rust and had a lot of trouble getting them working on both Linux and MacOS, along with handling
edge cases and multi-threading. This is an area where Rust libraries are not as mature as the Go
options, and so I went the route of improving on a low-level Rust FFI binding instead of a pure Rust
implementation. This resulted in both fixing the compatibility issues, and speed improvement of 70% - 3000% depending on the system. 

Here's the benchmark results immediately after switching to `typed-fuse`:
```
   Compiling encfs v2.0.0-beta.4
    Finished `bench` profile [optimized] target(s) in 0.69s
     Running benches/filesystem.rs (target/release/deps/filesystem-35066b3af94c35f4)
Filesystem benchmark: ranks=1, items/rank=1000, iterations=5, bytes/file=4096

Values are operations per second (ops/sec); higher is better, so a positive delta is an improvement.
Operation                         Baseline      Current        Delta
-------------------------------- ------------ ------------ ----------
Directory creation                    1546.05      4714.33   +204.93%
Directory removal                     2232.87      5468.78   +144.92%
Directory rename                       948.21      2291.29   +141.65%
Directory stat                       14355.23    444383.09  +2995.62%
File creation                         1387.30      3167.44   +128.32%
File read                             5716.02      9227.67    +61.44%
File removal                          2266.72      4906.89   +116.48%
File stat                            14424.88    497902.58  +3351.69%
Tree creation                         1866.91      4040.45   +116.42%
Tree removal                          1054.19      1354.10    +28.45%

Deltas are informational and do not affect the command exit status.
```

## FAQ

### What settings should I use for Dropbox?

(this is a hold-over from the original encfs FAQ, which presumably still applies)

Disable `External IV chaining`. There [have](https://github.com/vgough/encfs/issues/141)
been [reports](https://github.com/vgough/encfs/issues/388)
of a pathological interaction of IV chaining mode with Dropbox' rename
detection.

IV chaining is on by default, so it must be disabled when creating a new
filesystem: `encfsctl new --no-chained-iv ...`
