# Plan: headerless files with a path IV

Status: mostly done on the `encfsctl-fsck` branch (November 14, 2026),
together with fsck, which now shares forward rename's copy code
(`src/recrypt.rs`). Written November 12, 2026, from an investigation done
during the `encfsctl fsck` work (ADR 0007). All the evidence below comes
from in-process probes (`EncFs`, `ReverseFs` through
`typed_fuse_core::Runtime`) and the `encfsctl` binary. The stacked
`encfs`-on-`encfsr` case was not run live.

Done:

- Step 2: headerless blocks are re-encrypted on rename
  (`crypto::file::reencrypt_blocks`, through `Recrypt::copy_file_contents`).
- Step 3: the copy is synced, and the error propagated, before the source
  is removed; failed child copies abort before `remove_dir_all`.
- Step 5: `encfsctl cat` and `export` use `EncfsConfig::headerless_file_iv`.
- Step 1 in part: `EncfsConfig::external_iv` and `headerless_file_iv`
  exist and serve rename, fsck, `cat` and `export`. `create_impl`,
  `open_impl`, the truncate path and `ReverseFs::file_iv_for_path` still
  have their own copies of the rule.
- Tests: `tests/rename_path_iv_test.rs` (rename in place, into another
  directory, inside a renamed directory, partial block and hole).

Left: step 4 (the legacy IV rule and its validation decision), the
open-handle tests, the in-process stacked restore test and the live test
extension.

## Problem

A headerless file (`unique_iv = false`) on a volume with external IV
chaining has no stored file IV. Its blocks are encrypted under its **path
IV**, which changes when the file's name or (in chained mode) any parent's
name changes. Forward mode adopted this in PR #693 (`headerless_file_iv`,
`src/fs.rs`), released in v2.0.0-beta.8, so that `encfs` can read what
`encfsr` produces. `encfsctl new --no-unique-iv`, the config `encfsr`
requires, creates exactly this combination (chained names, external IV
chaining on, no header).

Two code paths never caught up:

1. **Forward rename copies the bytes without re-encrypting them.**
   `copy_file_with_header_rewrite` re-encrypts the header when there is one.
   Its headerless branch copies the bytes as they are ("No header to
   rewrite: the IV is path-derived"), then the caller removes the source.
   The copy only decrypts under the old path IV.
2. **`encfsctl cat` and `export` decrypt headerless files with IV 0**
   (`FileIv::from_u64(0)` in `cmd_cat` and `export_directory`), ignoring
   external IV chaining. They can't read any file of a reverse volume.

## Evidence

Forward rename, read back after a remount (`EncFs` driven directly):

| Config | Rename in place | Move to another dir | File inside a renamed dir |
|---|---|---|---|
| V7 `--no-unique-iv` (chained names, external chaining) | EIO | EIO | EIO |
| V7 headerless, directory IVs, external chaining | EIO | EIO | OK (plain `rename(2)`) |
| V7 headerless, external chaining off | OK | OK | OK |
| V6 headerless, external chaining, no block MAC | garbage, no error | garbage | garbage |
| V7 with a header (control) | OK | OK | OK |

`encfsctl cat <mirror> a` on a mirror of a reverse view: exit 1, "AES-GCM-SIV
tag verification failed for block 0". `encfsctl export`: the same error as a
warning, and the file is missing from the output.

Reverse view receiving what forward rename sends (create the new name, write
the old ciphertext, close): `write` succeeds, `flush` and `release` return
`EBADMSG`, and an empty plaintext file is left at the new name. The source
entry can then still be unlinked through the view.

## Impact

- **Forward mount of a reverse volume's ciphertext** (a backup mirror opened
  with `encfs`, or a sync of an `encfsr` view): every rename makes the file
  unreadable, and in chained mode a directory rename does this to every file
  below it. The original is deleted by the rename. The ciphertext survives
  but only decrypts under the old path's IV, so recovery needs the old name.
- **`encfs` stacked on `encfsr --write`** (the restore setup in
  `test_encfsr_v7_write_through_forward_mount`): inferred, not run live. The
  reverse view refuses the copy at flush, but `copy_file_with_header_rewrite`
  neither fsyncs nor checks `close()`, so the error is dropped and the rename
  deletes the original through the view. The likely result is the plaintext
  source file deleted and an empty file under the new name. The same holds
  for every file in a renamed chained directory.
- **`encfsctl cat` / `export` / (fsck)**: can't read reverse volumes at all.
  `ls` is unaffected (it only decodes names).
- **Hand-edited V4–V6 configs with `uniqueIV=0` and external chaining**:
  C++ EncFS uses file IV 0 for headerless files whatever the config says
  (`CipherFileIO`: `fileIV` stays 0 without a header) and never offers
  external chaining without unique IVs. Rust uses the path IV, so it can't
  read such files as C++ wrote them, besides the rename bug.

Not affected: configs with a header; headerless configs without external
chaining (file IV 0); hard links (refused with `EPERM` under external
chaining); reverse-mode renames (the plaintext is re-encrypted on the fly).

## Plan

Tests first, each failing on `master`, then the fixes.

### 1. One rule for a file's IV

The rule is spread across `headerless_file_iv` and the external-IV
selection in `create_impl`, `open_impl` and the truncate path (`src/fs.rs`),
`ReverseFs::file_iv_for_path`, `cmd_cat` and `export_directory`
(`src/encfsctl.rs`), and fsck's `Fsck::file_iv` if that has merged. Add
two helpers on `EncfsConfig` and use them everywhere:

- `external_iv(path_iv) -> u64`: `path_iv` with external chaining, else 0.
- `headerless_file_iv(path_iv) -> Option<FileIv>`: `None` when the config
  has a header. Otherwise the external IV on V7, and 0 on V4–V6, as C++
  does (see step 4).

### 2. Re-encrypt headerless files on rename

In `copy_file_with_header_rewrite`'s headerless branch, under the existing
`lock_source_and_dest` locks, read each physical block, decrypt it with
`BlockCodec` under the source's file IV, and encrypt it under the
destination's. Leave all-zero blocks as they are when `allow_holes` is set.
The function is only called with external chaining on, and `src_iv`/`dst_iv`
are the two path IVs.

Put the block loop in `crypto/file.rs` (for example
`reencrypt_headerless(cipher, layout, src, dst, from, to, allow_holes)`).
fsck's `copy_file` has the same loop and should switch to it.

Open handles: handles on the destination path already carry the
destination's `headerless_iv` from `open_impl`, so they match the new bytes.
Handles on the source keep writing to the removed inode, as with headers
today.

### 3. Don't delete the source until the copy is known good

In `copy_file_with_header_rewrite`, after the `BufWriter` flush, `fsync` the
destination (`sync_all`) and propagate its error before returning. Reverse
mode's `fsync` commits the staged write and returns the validation error
(`ReverseFs::fsync` → `commit_staged`), so the stacked setup then fails the
rename and keeps the source. It also makes the copy durable before the
source is removed, which forward rename doesn't guarantee today with or
without headers. `copy_recursive`'s plain `fs::copy` branch and the directory
copy should get the same treatment, so a failed child copy aborts before
`remove_dir_all`.

### 4. Legacy configs match C++

With step 1, V4–V6 headerless files use IV 0. Decide in review whether
`EncfsConfig::validate` should also reject V4–V6 `uniqueIV=0` with
`externalIVChaining=1`, which C++ never writes, or just ignore the flag for
the file IV. Ignoring it is the safer default: C++ reads such a volume, so
Rust should too.

### 5. Fix `encfsctl cat` and `export`

Use `headerless_file_iv` from step 1 instead of `FileIv::from_u64(0)`.

## Tests

- **Forward rename regression** (new test file, `EncFs` driven directly,
  read back after a remount): rename in place, move to another directory,
  chained directory rename with a nested file and symlink, under V7
  `--no-unique-iv`, V7 headerless with directory IVs, and V6 headerless
  without MAC. Include a sparse file with an all-zero block when
  `allow_holes` is set, and a partial last block.
- **Open handles**: a handle opened on the destination path before the
  rename reads the new contents; a write through it lands under the right IV.
- **Stacked restore, in process**: drive a writable `ReverseFs` through
  `Runtime` and check that a copy it refuses at `fsync` leaves the source
  plaintext in place. Forward `EncFs` can't sit on top of it without FUSE,
  so test `copy_file_with_header_rewrite`'s error path directly with a
  destination whose `fsync` fails if a seam is cheap; otherwise rely on the
  Linux live test below.
- **Live** (`tests/encfsr_live_test.rs`, Linux): extend
  `test_encfsr_v7_write_through_forward_mount` to rename a file and a
  directory through the forward mount, then check both the forward view and
  the plaintext source.
- **`encfsctl cat` / `export`** on a mirror of a reverse view (ciphertext
  read through `ReverseFs`), as in the probe.
- **Legacy**: a V6 headerless volume with `externalIVChaining=1` reads with
  IV 0 (match a C++-written fixture if one can be produced).

## Recovery for users already hit

A file renamed by the bug still decrypts under its old path IV. Its old
plaintext path is the only key to it. Consider an `encfsctl` option (or an
fsck mode) that takes an old path and a damaged file and re-encrypts it
under its current path. Out of scope for the fix PR; mention it in the
ChangeLog entry, which should describe the data loss plainly.

## Interaction with the fsck branch

`encfsctl-fsck` already re-encrypts headerless files correctly in
`Fsck::copy_file` and computes file IVs in `Fsck::file_iv`. Whichever PR
merges second moves those to the shared helpers from steps 1 and 2. fsck's
`file_iv` follows step 4's legacy rule as well.

## Order of work

1. Failing tests (rename matrix, `cat`/`export`).
2. `EncfsConfig` IV helpers; switch every call site.
3. Headerless re-encryption in rename.
4. `fsync` before removing the source.
5. Legacy IV rule, with the validation decision.
6. Live test extension; ChangeLog entry naming the affected releases
   (v2.0.0-beta.8 onward) and configs.
