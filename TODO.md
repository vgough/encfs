# Concurrency / correctness TODO (from FUSE race-condition review)

Race conditions where encfs behaves differently from a real filesystem. See the
review discussion for full detail. `cargo build` on an encfs mount is the
reference workload that fails.

- [x] **1. Non-atomic block read-modify-write corrupts data under concurrent writes.**
  Fixed: `EncFs` keeps a table of per-backing-inode `FileState`s (`FileStates`
  in src/fs.rs), keyed by (st_dev, st_ino) so handles opened through different
  plaintext paths share one entry. Each entry is an `RwLock<FileMeta>` that
  guards both the file's byte range and its per-file IV:

  * `read_impl` takes the read lock; `write_impl`, `do_truncate` (passing the
    guard down to `truncate_expand`/`truncate_shrink`), `open_impl`,
    `create_impl` and `copy_file_with_header_rewrite` take the write lock.
  * `O_TRUNC` is no longer passed to `open(2)`, and `create` no longer opens
    with `O_TRUNC` either. Both reset the file and write the new header *under*
    the lock, so the reset can't land on top of another handle's in-flight RMW.
  * The per-file IV lives in the shared `FileMeta`, not on each `FileHandle`.
    A truncating open installs a new IV and every existing handle picks it up
    at the same instant, instead of writing blocks under an IV the header no
    longer names (permanently undecryptable).
  * `copy_file_with_header_rewrite` locks source *and* destination, in
    ascending key order so a reverse rename can't deadlock against it, and
    truncates the destination under that lock.
  * Entries are held by `Weak` and swept on insert, so the table stays within
    ~2x the live handle set instead of growing for the life of the mount.

  Regression tests in tests/concurrent_file_access_test.rs.

  Original report:
  `write_at_internal` (src/crypto/file.rs:411) does unlocked read-decrypt-modify-
  encrypt-write for partial blocks; `truncate_shrink`/`truncate_expand`
  (src/fs.rs:483-601) do read/set_len/rewrite; `FileEncoder::write_at` reads the
  file length first (src/crypto/file.rs:356). Two concurrent writers to the same
  block lose each other's updates, and a truncate racing a write can leave a
  block whose MAC no longer matches (EIO on next read). Fuse3 runs read/write/
  setattr concurrently (shared read lock), so encfs must serialize per file.
  Fix: per-backing-inode `RwLock` in `EncFs`, held for write across the whole
  RMW in `write_impl`, `do_truncate`, `truncate_expand`, `truncate_shrink`, and
  `copy_file_with_header_rewrite` (read lock for `read_impl`).

- [ ] **2. POSIX/BSD locks don't actually lock.**
  `flock(2)` is never forwarded (typed-fuse leaves `ops.flock` unset), so `flock()`
  is a no-op success and two cargos can hold the registry cache lock
  "simultaneously". `fcntl` locks are forwarded (src/fs.rs:1670-1691) but each
  `open` creates a new backing fd. Fix: implement `flock` in the typed-fuse fork and
  pass through to the backing fd.

- [ ] **3. `fsync`/`flush`/`fdatasync` are silent no-ops.**
  The `PathFilesystem` defaults return `Ok(())` and `EncFs` doesn't override
  them, so write→fsync→rename publishing isn't durable. Fix: `fsync` →
  `File::sync_all`/`sync_data` on `handle.file`; `flush` likewise.

- [ ] **4. Directory rename under IV chaining is a non-atomic copy+delete that
  races readers/writers.**
  `rename_internal` (src/fs.rs:138-194) recursive-copies then `remove_dir_all`s;
  a concurrent open/write under the source tree can see a file vanish from both
  names or be copied mid-write (compounding item 1). Fix: exclude data-path ops
  from a directory subtree while it is being renamed (per-directory lock or
  rename-generation counter).

- [x] **5. `do_truncate` without a handle opens a second fd** and truncates
  through it while another handle may be mid-write; both length reads are
  TOCTOU. Re-checked after item 1 landed: fixed by that lock.

  `do_truncate` (src/fs.rs:894) still opens its own fd when no handle was
  passed, but the lock it takes is keyed by *backing inode*, not by fd:
  `FileStates::get` stats the fd and looks up `(st_dev, st_ino)`, so the
  transient fd contends with the same `FileState` as every open `FileHandle` on
  that inode, including ones opened through a different plaintext path.

  Neither length read is TOCTOU any more: `state.write()` is taken *before* the
  first `metadata()` and held across the second (the length read inside
  `FileEncoder::write_at`, and the decode/`set_len`/re-encrypt in
  `truncate_expand`/`truncate_shrink`, which take a `&RwLockWriteGuard` to make
  that structural). Everything that can move the length holds the same lock, and
  every `set_len` in src/fs.rs sits inside one of those regions. The header-IV
  read for the fd-less case is also under the guard and cached into
  `guard.header_iv`, so it cannot observe an IV a concurrent truncating open is
  midway through replacing.

  Not covered by a test: `concurrent_write_and_truncate_same_file` truncates
  *with* a handle, so the `handle: None` branch (a plain `truncate(2)` on a file
  this mount has not opened) exercises the fix only in review, not in CI.

  Residual, benign: `encrypt_path` + `open` is not atomic against a concurrent
  rename of that name, so the fd-less path can truncate the inode that *was* at
  the path. It locks the inode it actually opened, so no torn blocks or bad
  MACs — the same race a real `truncate(2)` has against `rename(2)`.

- [ ] **6. Hard links break per-file IV when `header_size == 0`.**
  `link_impl` only rejects links under `external_iv_chaining` (src/fs.rs:824),
  but with `unique_iv` off the file IV *is* the path IV, so the second name
  decrypts the same ciphertext with the wrong IV. Fix: also reject (or handle)
  hard links when `header_size() == 0`.
