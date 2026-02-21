# pjdfstest Failure Summary for EncFS

This document summarizes the pjdfstest failures observed when running the POSIX filesystem test suite against an EncFS mount, and classifies whether they are likely **EncFS implementation issues**, **EncFS/FUSE design limitations**, or **unsupported features**.

## Executive Summary

| Category | Failure Pattern | Root Cause |
|----------|-----------------|------------|
| **Permission enforcement** | open/06 (142/144), open/07 (23/25), truncate 18, chmod, utimensat | Kernel `default_permissions` or EncFS not checking `req.uid/gid` in truncate |
| **Hard links** | link/* (widespread) | EncFS returns EPERM when `external_iv_chaining` (paranoia); design limitation |
| **Rename** | rename/09 (1900), rename/10 (1616) | Likely complex rename semantics, symlink+IV chaining, or atomicity |
| **UID/GID on create** | open/00 (17-23, 25-28), mkdir, mkfifo, mknod | Backing FS chown or `set_ownership` behavior |
| **lchmod** | chmod/* (tests 32+) | FreeBSD-only; Linux does not support `lchmod` |
| **Truncate permission** | truncate/00 (18), ftruncate | EncFS `truncate()` does not check write permission |
| **Timestamp semantics** | utimensat, various ctime tests | Possible UTIME_OMIT, resolution, or permission checks |

---

## 1. Link Tests — **EncFS / FUSE design limitation**

| Test File | Failed | Total | Pattern |
|-----------|--------|-------|---------|
| link/00.t | 103 | 202 | Most tests |
| link/01.t | 12 | 32 | 14-25 |
| link/03.t | 12 | 13 | 1-12 |
| link/06.t, 07.t, 10.t, 11.t | Many | — | — |

**Cause:** EncFS explicitly returns `EPERM` for `link()` when `external_iv_chaining` is enabled (paranoia mode). Hard links are incompatible with per-path IV chaining because multiple directory entries would share the same ciphertext but require different IV derivation.

```rust
// src/fs.rs:1025-1027
if self.external_iv_chaining {
    return Err(libc::EPERM);
}
```

- In **standard mode**, `link` is implemented via `std::fs::hard_link` on the backing store.
- In **paranoia mode**, hard links are intentionally unsupported.
- Tests also use block/char/socket types; support depends on the backing filesystem.

**Verdict:** EncFS design limitation (and FUSE/backend constraints for non-regular files).

---

## 2. Open Permission Tests — **Permission enforcement**

| Test File | Failed | Total | Description |
|-----------|--------|-------|-------------|
| open/06.t | 142 | 144 | EACCES when opening without required permissions |
| open/07.t | 23 | 25 | O_WRONLY / O_TRUNC permission checks |

**Cause:** These tests create files with strict modes (e.g. 0600) and different uids, then expect `open(2)` to return EACCES when the caller lacks permission.

- EncFS mounts with `default_permissions` by default, so the kernel enforces access using uid/gid/mode from `getattr`.
- Failures are plausible if:
  - The mount uses `--no-default-permissions`, or
  - `set_ownership_fd` fails and files are created with incorrect uid/gid (e.g. backing FS does not allow chown).
- If ownership and mode are correct and `default_permissions` is active, these should pass; widespread failure suggests ownership or mount options.

**Verdict:** Likely **mount configuration** or **ownership preservation** on the backing filesystem.

---

## 3. UID/GID and directory timestamps — **Create semantics**

| Test Files | Failed Range | Typical pattern |
|------------|--------------|-----------------|
| open/00.t | 17-23, 25-28 | Expect uid/gid 65534,65534 or 65533,65532 on create |
| mkdir/00.t | 17-23, 25-28 | Same |
| mkfifo/00.t, mknod/00.t | 17-23, 25-28 | Same |

**Cause:** Tests run operations under different uids (`-u 65534 -g 65534`) and expect created files to have that ownership, and parent directory ctime/mtime to update.

- EncFS uses `set_ownership_fd` / `set_ownership_path` and ignores EPERM for unprivileged mounts; for root mounts, fchown/chown should succeed if the backing FS allows it.
- If the backing store does not support arbitrary chown (e.g. vfat, some NFS, or another FUSE FS), ownership will not match expectations.
- Parent directory timestamp updates are delegated to the backing FS; behavior depends on that FS and `default_permissions`.

**Verdict:** **Backing filesystem** and mount semantics; not necessarily an EncFS bug.

---

## 4. chmod — **Linux vs FreeBSD, possible semantics**

| Test File | Failed | Total | Pattern |
|-----------|--------|-------|---------|
| chmod/00.t | 39 | 119 | 32-34, 36-38, 41-44, 46-48, 51, 74-81, 87, etc. |
| chmod/01.t, 03.t, 05.t, 07.t, 11.t, 12.t | Many | — | — |

**Cause:**

- `chmod/00.t` prints `1..203` if `lchmod` is supported, else `1..119`. On Linux, `lchmod` is not supported, so tests 32+ relate to non-lchmod behavior.
- EncFS `chmod` delegates to `fs::set_permissions(real_path, perms)`, which follows symlinks; that is correct for `chmod` on a symlink (change target).
- Failures may involve:
  - Symlink vs target mode expectations.
  - ctime update on successful vs unsuccessful chmod (tests 88–95).
  - Possible `lstat` mode semantics for symlinks.

**Verdict:** Mix of **Linux lack of lchmod** and possible **chmod/ctime semantics**.

---

## 5. Truncate / ftruncate — **EncFS implementation**

| Test File | Failed | Description |
|-----------|--------|-------------|
| truncate/00.t | 18 | `expect EACCES -u 65534 truncate` (non-owner truncate) |
| truncate/03.t, 05.t, 06.t | Multiple | Permission and edge cases |
| ftruncate/00.t, 03.t, 05.t, 06.t | Multiple | Same |

**Cause:** EncFS `truncate()` does not perform a permission check:

```rust
fn truncate(&self, _req: RequestInfo, path: &Path, fh: Option<u64>, size: u64) -> ResultEmpty {
```

`_req` is unused; there is no check that `req.uid` has write permission. Non-owners can truncate files. `ftruncate` will follow similar logic.

**Verdict:** **EncFS implementation gap** — truncate should validate write permission using `req.uid`/`req.gid` and file metadata.

---

## 6. Rename — **EncFS / FUSE behavior**

| Test File | Failed | Total | Notes |
|-----------|--------|-------|------|
| rename/09.t | 1900 | 2353 | Bulk rename stress |
| rename/10.t | 1616 | 2099 | Bulk rename stress |
| rename/00.t, 02.t, 04.t, 05.t, 12.t–14.t, 20.t, 21.t, 23.t | Many | — | Various rename cases |

**Cause:** EncFS has non-trivial rename behavior:

- Symlinks: when `external_iv_chaining` is enabled, renaming symlinks returns `ENOSYS` because the IV depends on the path.
- Recursive directory renames can trigger similar symlink/IV issues.
- Atomicity, overwrite semantics, and cross-directory renames may differ from native filesystems.
- Large failure counts in rename/09 and rename/10 suggest issues under stress or in edge cases.

**Verdict:** Likely **EncFS implementation and design** around symlinks, IV chaining, and rename semantics.

---

## 7. utimensat — **Timestamps and permissions**

| Test File | Failed | Pattern |
|-----------|--------|---------|
| utimensat/00.t | 17-26 | Timestamp updates |
| utimensat/06.t, 07.t | Multiple | Permission and UTIME_OMIT-style checks |

**Cause:** EncFS implements `utimens` and calls `utimens_permission_check`, so some permission logic exists. Failures may be due to:

- UTIME_NOW / UTIME_OMIT semantics (e.g. FUSE protocol version).
- Resolution or rounding of timestamps.
- Permission checks for non-owners (e.g. setting to “now” vs explicit times).

**Verdict:** Possibly **FUSE protocol** or **EncFS utimens** details; worth checking mount options and FUSE version.

---

## 8. mkdir, mkfifo, mknod — **Creation and permissions**

| Test Files | Failed Range | Pattern |
|------------|--------------|---------|
| mkdir/00.t, 01.t, 03.t, 05.t, 06.t, 10.t | 17-28 and others | UID/GID, mode, timestamps |
| mkfifo/*, mknod/* | Similar | Same |

**Cause:** Same general issues as open/create: ownership on creation, mode, and parent timestamps. EncFS delegates to `libc::mkdir`, `libc::mkfifo`, and `libc::mknod`, then `set_ownership_path`.

**Verdict:** Mostly **backing FS** and **ownership**; some may overlap with chmod/ctime semantics.

---

## 9. unlink, rmdir, symlink — **Mixed**

| Test Files | Notes |
|------------|-------|
| unlink/00.t | 14-16, 18-20, 36-45, etc. — permissions and nlink |
| unlink/11.t | 239/270 — likely permission/nlink heavy |
| rmdir/*, symlink/* | Similar permission and metadata patterns |

**Cause:** Combinations of:

- Permission checks on unlink/rmdir.
- nlink handling (especially with link tests).
- Symlink target handling and path encryption.

**Verdict:** Mix of **EncFS semantics** and **link/permission** behavior.

---

## Recommendations

### High priority (EncFS implementation)

1. **Truncate permission check**  
   Add a permission check in `truncate()` and `ftruncate()` that uses `req.uid`/`req.gid` and file metadata before allowing a truncate.

2. **Rename behavior**  
   Review symlink rename with `external_iv_chaining`, recursive directory renames, and atomicity; consider skipping or documenting known limitations.

### Medium priority (configuration and backend)

3. **Mount options**  
   Ensure tests run with `default_permissions` (i.e. without `--no-default-permissions`) if POSIX permission checks are desired.

4. **Backing filesystem**  
   Use a backing FS that supports chown (e.g. ext4) and clear ownership semantics to reduce uid/gid-related failures.

### Low priority / known limitations

5. **Link**  
   Hard links are unsupported in paranoia mode; this is intentional and documented.

6. **lchmod**  
   Unsupported on Linux; skip or adjust tests that rely on it when running on Linux.

---

## Test execution summary

| Category | Total Failed (approx) | Classification |
|----------|------------------------|----------------|
| link | ~150+ | EncFS design / FUSE |
| rename | ~3500+ | EncFS implementation |
| chmod | ~130+ | Linux + possible semantics |
| open | ~180+ | Permissions / mount / backend |
| truncate/ftruncate | ~30 | EncFS truncate permission |
| mkdir/mkfifo/mknod | ~100+ | Backend + permissions |
| unlink/rmdir | ~300+ | Mixed |
| utimensat | ~26 | FUSE / EncFS utimens |
| symlink | ~20 | EncFS / permissions |

**Conclusion:** The majority of failures fall into three buckets: (1) permission and ownership handling (open, truncate, create), (2) EncFS-specific limitations (link in paranoia, rename with symlinks/IV chaining), and (3) platform/backend behavior (lchmod, backing FS chown, default_permissions).
