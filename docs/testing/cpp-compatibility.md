# Test plan: reading volumes written by C++ EncFS

This plan checks that this build reads what the C++ implementation wrote:
file contents, names and symlink targets, across the V5 and V6 settings
C++ can produce. Run it before a release, and after any change to file IVs,
headers, block layout, name encoding or the read path.

It doesn't check writing (C++ reading what Rust wrote), V7, or reverse mode.

## How it works

1. **C++ side (Linux).** `tests/cpp_compat/make-volumes.sh` creates one
   volume per variant with C++ `encfs`. It writes the same set of files
   into each through the C++ mount and records a manifest of what the mount
   shows (SHA1 per file, target per symlink). It then remounts, and checks
   that C++ reads back what it wrote.
2. **Rust side (any host).** `tests/cpp_compat_test.rs` copies each volume
   to a temp directory and reads it three ways, comparing each with the
   manifest:
   - **mount**: `EncFs` driven directly (names by `decrypt_path`, contents
     by `open` + `read`, targets by `readlink`), the code a FUSE mount runs.
     No FUSE needed on the host.
   - **cat**: `encfsctl cat` of every regular file.
   - **export**: `encfsctl export --fail-on-error` of the whole tree.

   It also reads the C++ fixtures already in `tests/fixtures` (V6 standard,
   V6 paranoia, V5 from encfs 1.4.2), which have no manifest; the three
   readers must agree on them.

## Running it

### With Lima (macOS or Linux host)

Needs a Lima instance running Ubuntu or Debian. The script installs `encfs`
in it if missing.

```sh
task test-cpp-compat
# or, choosing the instance and keeping the volumes:
LIMA_INSTANCE=default VOLUMES=/tmp/cppvols tests/cpp_compat/run-lima.sh
```

`SKIP_CHECK=1` only builds and copies the volumes.

Lima shares the home directory read-only, so the script copies files in and
out with `limactl copy`. It stops the instance when done.

### On a Linux machine with C++ EncFS

```sh
sudo apt install encfs fuse3
OUT=/tmp/cppvols tests/cpp_compat/make-volumes.sh
ENCFS_CPP_VOLUMES=/tmp/cppvols cargo test --test cpp_compat_test -- --ignored --nocapture
```

The two halves can run on different machines: copy the `OUT` directory
across with `tar` (it holds symlinks, some dangling and some named with a
leading `-`).

### Runtime

Building the volumes takes about two minutes. The check took about 35
minutes for 17 volumes, almost all in `cat`: it derives the key once per
file, and C++ volumes set `desiredKDFDuration` to 0.5 s (standard) or 3 s
(paranoia). The mount and export readers take seconds. To check a few
volumes, point `ENCFS_CPP_VOLUMES` at a directory holding copies of just
those (`cp -R`, which keeps symlinks).

## What is covered

### Volume variants

Each starts in C++ standard or paranoia mode. The listed fields are then
edited in `.encfs6.xml` before any file is written, so everything in the
volume is written by C++ under the edited settings. The volume key isn't
bound to these fields.

Standard mode is AES-192, 1024-byte blocks, Block names, chained name IVs,
per-file IV headers, holes allowed. Paranoia mode is AES-256, block MACs (8
bytes) and external IV chaining.

| Variant | Mode and edits | Covers |
|---|---|---|
| `std` | standard | the default C++ volume |
| `paranoia` | paranoia | MACs, external IV chaining (header under path IV) |
| `nochain` | `chainedNameIV=0` | names encrypted per component |
| `mac8` | `blockMACBytes=8` | block MACs without paranoia |
| `mac8-rand` | `blockMACBytes=8 blockMACRandBytes=8` | random MAC bytes (unsupported, see results) |
| `noholes` | `allowHoles=0` | zero blocks stored encrypted |
| `block4096` | `blockSize=4096` | another block size |
| `extiv` | `externalIVChaining=1` | external chaining with headers, no MACs |
| `noheader` | `uniqueIV=0` | files without a header (IV 0) |
| `noheader-mac` | `uniqueIV=0 blockMACBytes=8` | headerless with MACs |
| `noheader-nochain` | `uniqueIV=0 chainedNameIV=0` | headerless, unchained names |
| `noheader-extiv` | `uniqueIV=0 externalIVChaining=1` | headerless files ignore external chaining (IV 0) |
| `noheader-extiv-paranoia` | paranoia, `uniqueIV=0` | the same with MACs |
| `expert-noheader` | expert: AES-128, 2048-byte blocks, Stream names, no per-file IV | Stream names, a config C++ wrote itself without a header |
| `expert-blowfish` | expert: Blowfish-160, 512-byte blocks, Block32 names | Blowfish, Block32 names (C++ may fail to create it, see results) |

`noheader-extiv*` are configs C++ never writes itself: expert mode only asks
about external IV chaining when per-file IVs are on. C++ still mounts them,
and writes files without a header under IV 0. `make-volumes.sh` prints a
note if C++ starts asking about chaining without per-file IVs.

### Files in every volume

| Path | Content | Covers |
|---|---|---|
| `small` | 6 bytes | a single partial block |
| `empty`, `empty2` | 0 bytes (`: >`, `touch`) | no header on disk: C++ writes it with the first data |
| `multi` | 5000 bytes | several blocks, partial last one |
| `oneblock`, `twoblocks` | 1024, 2048 bytes | block-aligned sizes |
| `big` | 300000 bytes | more than one 128 KiB read |
| `sub/dir/nested` | 3000 bytes | chained path IVs two levels down |
| `spaced name ü.txt` | 1 byte | spaces and non-ASCII names |
| `sparse` | 100 bytes, a hole, 100 bytes | holes (or zero blocks) |
| `extended` | truncated up to 50000, then 4 bytes appended | extension through truncate |
| `shrunk` | 5000 bytes truncated to 1500 | truncation inside a block |
| `appended` | 700 + 900 bytes in two opens | appending in a later open |
| `link`, `sub/dir/up` | relative symlinks | symlink targets |
| `abslink` | `/etc/hostname` | absolute target |

## Expected results

Baseline: 2026-11-14, C++ encfs 1.9.5 on Ubuntu 26.04 (aarch64, Lima),
checked with 2.0.0-beta.11 before release (the `encfsctl-fsck` branch). Every line is
`ok` except:

| Volume | Expected | Why |
|---|---|---|
| `mac8-rand` | `FAIL ... load blockMACRandBytes=8 is not supported yet` | not implemented; `EncfsConfig::validate` refuses it |
| `expert-blowfish` | `SKIPPED, C++ failed to create it` | C++ 1.9.5 segfaults creating it on Ubuntu 26.04 (OpenSSL 3 keeps Blowfish in the legacy provider) |

So the test itself fails (because of `mac8-rand`). Compare the `ok`/`FAIL`
lines with the table above, not the exit status. `cat` reports 13 entries
(regular files only), mount and export 16.

Any other `FAIL` is a regression, unless it's one of these:
- **A new C++ version.** `encfs-version` in the volume directory records
  which one wrote the volumes.
- **A harness problem.** For example, a ciphertext name starting with `-`
  needs `--` before it on the `encfsctl` command line.

## Not covered

- **V4 (`.encfs4`).** No fixture exists, and C++ 1.9.5 can't write one. Only
  the V5 fixture from encfs 1.4.2 exercises the binary formats.
- **Blowfish volumes.** Covered only when C++ manages to create
  `expert-blowfish`, e.g. on a system whose OpenSSL still has Blowfish in
  its default provider.
- **Writing.** For example, extending a C++-written empty file with
  `truncate` through the mount, without an open handle, may still fail with
  EIO: the truncate path expects a header. It hasn't been tested.

## History

- 2026-11-14, first run. Found that the mount returned EIO opening a 0-byte
  file on volumes with per-file headers. Fixed in `open_impl`, with a
  regression test in `tests/legacy.rs`. Confirmed from C++ itself that V4–V6
  files without a header use IV 0 even with external IV chaining set
  (`EncfsConfig::headerless_file_iv`).
