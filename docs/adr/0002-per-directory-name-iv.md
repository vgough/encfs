# ADR 0002: Per-directory name IVs stored in a sidecar file (V7)

## Status

Accepted and implemented. The sidecar format, derivation, and cache live in
`src/diriv.rs`; the filesystem side is in `src/fs.rs` (`encrypt_path`,
`mkdir_with_sidecar`, `rmdir_with_sidecar`, `rename_with_directory_ivs`).
Directory IV mode is the default for new V7 filesystems (`encfsctl new`;
`--no-directory-iv` opts out), which settles open question 2. Questions 1, 3
and 4 remain open; this implementation keeps the proposed answers (64-bit
derived tweak, crash-safe copy for externally chained files, reverse mode
rejected). How extended attributes are keyed has since moved to a per-inode
seed (ADR 0003); the xattr rows below are kept as originally decided and
marked superseded.

## Context

EncFS encrypts each filename under a 64-bit IV. With `chained_name_iv` (the
default) that IV is chained from the parent path: `encrypt_filename(name, iv)`
returns the encoded name plus a new IV, which becomes the IV for the next path
component (`EncFs::encrypt_path`, `src/fs.rs`). The chain value of the final
component, the *path IV*, is reused for several other things:

- the external IV that file headers are encrypted under when
  `external_iv_chaining` is set, and the file IV itself when `unique_iv` is off;
- the IV for V7 symlink targets (`SymlinkFormat::EncryptedName`);
- the IV for V7 encrypted extended attributes.

Because every name below a directory depends on that directory's name, a
directory rename cannot be a `rename(2)`. `EncFs::rename_internal` instead
calls `copy_recursive`, which re-creates the whole subtree under new names
(rewriting file headers and symlink targets on the way) and then removes the
source with `remove_dir_all`. That is:

- O(size of subtree) in time and temporary disk space;
- not atomic, and races concurrent readers and writers (open item 4 in
  `TODO.md`);
- lossy: the copy carries permissions and timestamps but not ownership, hard
  links, or extended attributes.

Disabling chaining (`encfsctl new --no-chained-iv`) makes renames cheap but
encrypts every name under the same IV, so equal plaintext names produce equal
ciphertext names everywhere in the volume.

gocryptfs solves the same problem with a per-directory IV: each directory
holds a small plaintext sidecar file (`gocryptfs.diriv`) containing a random IV
that is used to encrypt the names inside that directory. Names then depend only
on their immediate parent, so a directory moves with a single `rename(2)` and
takes its IV with it.

## Decision

Add a V7 operating mode, *directory IV*, in which the IV for the names
inside a directory comes from a random per-directory sidecar file rather than
from the parent path. It replaces `chained_name_iv` for volumes that enable it.
Every existing volume (V4-V7) keeps its current behavior byte-for-byte, because
the new config field is absent/false for them and all legacy code paths are
left in place.

### Config option and invariants

- New field `EncfsConfig::directory_iv: bool` (`#[serde(skip, default)]`; the
  V6 XML format cannot express it).
- `validate()` rejects `directory_iv` unless `config_type == V7`, and rejects
  `directory_iv && chained_name_iv`. The two are alternative sources for the
  same IV.
- `external_iv_chaining` stays independent and may be combined with
  `directory_iv` (see "Entry IV" below).
- The default for new V7 filesystems (`EncfsConfig::standard_v7()`), but
  never enabled by `encfsctl passwd --upgrade`: existing names were
  encrypted under the old scheme. `EncfsConfig::use_chained_name_iv()`
  switches a new config back to path-chained names.

### Sidecar file

Every ciphertext directory, including the volume root, contains:

```
.encfs.diriv    exactly 16 random bytes, plaintext, mode 0444
```

- The value is not secret. It only has to differ between directories.
- Created with `O_CREAT | O_EXCL | O_NOFOLLOW`, written once, never modified.
- Readers reject anything that is not a regular file of exactly 16 bytes.
- The name cannot collide with an encrypted name: neither the Base64 nor the
  Base32 filename alphabet contains `.`. Existing code already skips
  dot-prefixed entries when listing (`directory_snapshot`, `copy_recursive`,
  `find_undecodable_files`) and `.encfs*` entries in `encfsctl ls`/`export`,
  so the sidecar is hidden from the plaintext view without new filtering.

### IV derivation

The existing filename codec takes a 64-bit IV. Rather than introduce a second
filename construction, the 16 sidecar bytes are reduced to the two 64-bit
values the existing interfaces need, using a keyed PRF:

```
d        = HMAC-SHA256(volume_key, "encfs.diriv.v1\0" || diriv)
name_iv  = LE64(d[0..8])     // IV for names inside this directory
node_iv  = LE64(d[8..16])    // unused since ADR 0003 (was: this directory's xattrs)
```

This is exposed as one new `Cipher` trait method. Name ciphertext format,
length limits, and all existing golden vectors are unchanged.

Consequence, stated plainly: the sidecar holds 128 random bits but the name
codec consumes a 64-bit tweak derived from them. Two directories share a name
tweak with probability 2^-64 per pair, and the only effect of such a collision
is that equal names in those two directories encrypt identically. A true
128-bit name tweak would need a new name cipher and is deliberately out of
scope; the 16-byte sidecar leaves room for it without an on-disk change to the
sidecar itself.

### Entry IV

The path IV is replaced by an *entry IV* that depends only on the entry's
parent directory and its own name:

```
(encoded_name, entry_iv) = encrypt_filename(name, name_iv(parent))
```

| Purpose | IV used in directory-IV mode |
|---|---|
| Names inside directory `D` | `name_iv(D)` |
| File header external IV (`external_iv_chaining`) | `entry_iv` |
| File IV when `unique_iv = false` | `entry_iv` (if `external_iv_chaining`) |
| Symlink target (V7 encrypted-name form) | `entry_iv` |
| Xattrs on a file, symlink, or special file | `entry_iv` (superseded: per-inode seed, ADR 0003) |
| Xattrs on a directory | `node_iv` of that directory (superseded: per-inode seed, ADR 0003) |
| Volume root | `entry_iv = 0` |

Nothing below a directory depends on that directory's name or location, and a
directory's own xattrs depend only on its sidecar. `EncfsConfig::
symlink_target_depends_on_path()` becomes true for `directory_iv` as well as
`chained_name_iv`.

### Path resolution

`EncFs::encrypt_path` stays the single funnel and keeps its signature,
returning `(backing_path, entry_iv)`. All tree walkers (forward filesystem and
`encfsctl`) are expressed with two helpers so legacy and directory-IV modes
share one loop:

- `names_iv(backing_dir, path_iv_of_dir)`: the IV for names inside a
  directory. Legacy: returns `path_iv_of_dir` unchanged (the chain value, or 0
  when unchained). Directory IV: reads the sidecar in `backing_dir`.
- `child_path_iv(next_iv)`: `next_iv` when `chained_name_iv || directory_iv`,
  else 0.

For legacy configs this is exactly the existing loop, which is what keeps the
old modes unchanged.

Errors: a missing parent directory is `ENOENT`; a directory that exists but has
a missing, short, long, or non-regular sidecar is `EIO` with a logged error.
A sidecar is never regenerated for a directory that already has entries, since
that would orphan every name inside it.

### Sidecar cache

Without a cache every operation costs open+read+close plus one HMAC per path
component. The cache maps backing directory path to the derived IVs, and a
hit is used without touching the disk.

That rests on one assumption: while a volume is mounted, every change to its
backing directory goes through the mount. Modifying the backing directory
behind a live mount (a sync tool, another machine, manual edits) is
unsupported; a directory replaced that way keeps its old cached IVs until the
next mount, so its names would decode wrongly and new files would be
encrypted under the wrong IV. The filesystem instead keeps the cache in step
with its own changes:

- mkdir inserts the new directory's IVs (it knows the sidecar bytes);
- rmdir drops the entries for the directory and anything below it;
- a directory rename moves the entries for the source subtree to the
  destination, replacing whatever was cached there. Clearing the destination
  is what correctness needs; moving the source keeps the subtree warm.
- Bounded size; cleared wholesale when it grows past a fixed limit.

An earlier revision validated each hit with an `lstat` of the sidecar against
its recorded identity, and refused to cache sidecars changed in the last two
seconds (git's racy-index rule) to stay correct on coarse-timestamp
filesystems. That cost one `lstat` per path component and kept new
directories uncached, to guard against changes the mount does not support.

### Directory lifecycle

A filesystem-wide `RwLock` (the "sidecar lock") is taken for write by mkdir,
rmdir, and directory rename, and for read on the slow path that actually
reads a sidecar into the cache, so in-process lookups never observe a
directory between its creation and its sidecar's, and a cache miss cannot
cache a path a rename has just vacated.

The lock keeps the cache true of the directory *at each path*, but it is not
held across ordinary operations, so the directory at a path can still be
replaced (rename over an empty directory, or rmdir then mkdir) between an
operation reading the parent's IV and creating its entry. The entry would
then sit in the new directory under a name encrypted for the old one,
unreadable for good. Instead of a broader lock, operations that write
IV-dependent names or attributes bind the IV to the directory:

- create, mknod, symlink, link, and file/symlink rename open the parent
  directory (`O_PATH`/`O_SEARCH`), check that the cached IVs were read from
  that inode (each cache entry records the directory's `(st_dev, st_ino)`),
  and create the entry with `*at` calls on the descriptor. A mismatch fails
  the operation with `ENOENT` and drops the entry so a retry reloads it; a
  replacement after the check leaves the descriptor on the unlinked old
  directory, where creation fails with `ENOENT`.
- mkdir and directory rename encrypt the new name under the write lock they
  already hold, which keeps the parent in place.
- (Superseded by ADR 0003, where attribute IVs come from the inode itself.)
  setxattr and removexattr held the read lock while reading a directory's
  `node_iv` and writing the attribute.

Read-only operations are left alone: a stale IV there only yields a
transient `ENOENT` or decode error.

- **mkdir**: create the directory with the requested mode exactly as today,
  create the sidecar, set ownership on both. If the resulting mode denies the
  daemon write/search access, add owner `rwx` temporarily and restore the
  original bits afterward. If the sidecar cannot be written, remove the
  directory and return the error.
- **rmdir**: a directory is empty when the sidecar is its only entry. Read the
  16 bytes, unlink the sidecar, `rmdir`. If `rmdir` fails (for example a file
  was created concurrently), re-create the sidecar with the same bytes so
  names already in the directory stay valid. A directory with no sidecar and no
  entries (left by a crash mid-rmdir) is removed directly. A read-only
  directory gets owner write temporarily, restored if the removal fails.
- **readdir**: decrypt entries with `name_iv` of the directory; the sidecar is
  not listed.
- **Volume root**: `encfsctl new` writes the root sidecar. At
  mount, a missing root sidecar is created only if the root contains no
  ciphertext entries and the mount is writable; otherwise the mount fails with
  a clear error before daemonizing.

### Rename

| Source | Action in directory-IV mode |
|---|---|
| Directory, destination absent | one `rename(2)` |
| Directory, destination an empty directory | remove the destination's sidecar under the sidecar lock, `rename(2)`, restore the sidecar if that fails |
| Regular file, no external IV chaining | `rename(2)`; xattrs are keyed by the inode (ADR 0003) and need nothing |
| Regular file, external IV chaining | existing `copy_file_with_header_rewrite` (crash-safe copy with the header re-encrypted under the new entry IV), copy the xattrs and their seed before restoring the mode, remove the source |
| Symlink | existing re-create with the target re-encrypted under the new entry IV |

`copy_recursive` is never entered for a directory in this mode. Legacy configs
take exactly the branches they take today.

The file case with external IV chaining remains a copy on purpose: rename
followed by an in-place header rewrite would be O(1) but leaves the file
unreadable if the process dies between the two steps. That trade can be
revisited separately.

### Config serialization and compatibility signaling

- `proto/encfs_config.proto`: new enum field on `NameEncoding`

  ```proto
  enum DirectoryIvMode {
    DIRECTORY_IV_MODE_NONE = 0;      // chained_name_iv decides
    DIRECTORY_IV_MODE_SIDECAR = 1;   // 16-byte .encfs.diriv per directory
  }
  DirectoryIvMode directory_iv = 4;
  ```

  The zero value is omitted on the wire, so the encoding and config hash of
  every existing V7 config are unchanged.
- `constants.rs`: `V7_DIRECTORY_IV_CONFIG_VERSION = 4`, and
  `V7_CURRENT_CONFIG_VERSION` moves to it. `required_v7_reader_version()`
  returns 4 when `directory_iv` is set. Older builds therefore stop at the
  existing version gate in `load_v7` with a dedicated error, before they could
  misread names. An unknown enum value is rejected rather than defaulted.

### CLI and tools

- `encfsctl new` sets `directory_iv` (and clears `chained_name_iv`) by
  default and writes the root sidecar. `--no-directory-iv` opts back into
  path-chained names, as do `--no-unique-iv` (reverse-mode configs, see
  below) and `--legacy-file-iv` (older readers cannot open directory IV
  volumes). `--no-chained-iv` then only turns off external IV chaining; with
  `--no-directory-iv` it also turns off name chaining, the V4-like form.
- `encfsctl info` (and `--raw`) shows the setting.
- `encfsctl decode`, `encode`, `cat`, `ls`, `export`, `showcruft` use the
  shared walk helpers. `decode`/`encode` now need the intermediate directories
  to exist on disk in this mode, since the IVs are read from them.
  `showcruft` reports a directory with a missing or invalid sidecar as an issue
  and does not descend into it.
- New strings get `en`/`fr`/`de` entries in `locales/`.

### Reverse mode

`encfsr` refuses a `directory_iv` config with a clear error. Reverse mode has
no ciphertext directory to hold a sidecar; supporting it means synthesizing
deterministic virtual sidecars from the plaintext path (as gocryptfs does) and
is left for a follow-up.

## Consequences

Gains:

- Directory rename is a single atomic `rename(2)` regardless of subtree size,
  including with external IV chaining. Ownership, hard links, and xattrs
  inside the subtree are untouched. Closes `TODO.md` item 4 for volumes in
  this mode.
- Equal names in different directories still encrypt differently, unlike
  `--no-chained-iv`.
- Encrypted xattrs survive file and directory renames.

Costs and trade-offs:

- One extra small file and inode per directory, and one open/read/close per
  directory the first time a mount resolves a path through it.
- The backing directory must not be modified behind a live mount (see
  "Sidecar cache").
- A ciphertext name is no longer bound to its full path. Someone with write
  access to the backing store can move a whole directory elsewhere in the tree
  and its contents still decrypt; with chaining the names would turn to
  garbage. File contents under `external_iv_chaining` are bound to (parent
  directory, name) rather than the full path. gocryptfs makes the same trade.
- Backup and sync tools must keep `.encfs.diriv` with its directory. Losing it
  makes that directory's names unrecoverable; a tool that excludes dotfiles
  must be configured not to.
- No in-place migration. Converting an existing volume means renaming every
  entry (and rewriting externally chained headers); the supported path is to
  create a new volume and copy.
- Limitations shared with chained mode remain: hard links to a file whose
  content IV derives from its entry IV are only consistent under one of the
  names, and `link` stays `EPERM` under `external_iv_chaining`. (Xattrs were
  in the same position until ADR 0003 keyed them by inode.)

## Open questions

1. **64-bit derived tweak vs. a true 128-bit name tweak.** This ADR keeps the
   existing name codec. If full 128-bit separation is a requirement, the
   filename MAC and IV derivation need 128-bit variants and new golden vectors.
2. **Default for new filesystems.** Resolved: directory IV mode is the
   default for `encfsctl new`. New volumes therefore need a reader that
   implements minimum reader version 4; `--no-directory-iv` or
   `--legacy-file-iv` create volumes older builds can open.
3. **External-IV file rename.** Keep the crash-safe copy, or switch to rename
   plus in-place header rewrite.
4. **Reverse mode.** Reject for now, or implement virtual sidecars as part of
   this change.

## Verification

### Old modes unchanged

- All existing unit, integration, and golden-vector tests pass unmodified
  apart from the added struct field in `EncfsConfig` literals.
- Existing V4/V5/V6/V7 fixtures load and decrypt; a V7 config written by the
  current build re-encodes to identical bytes and hash.
- A legacy-mode mount creates no `.encfs.diriv` files, and directory rename
  still takes the `copy_recursive` path.

### Config and compatibility

- V7 round trip with `directory_iv` set; `minimum_reader_version` is 4.
- `validate()` rejects `directory_iv` on non-V7 and together with
  `chained_name_iv`.
- A config requiring version 4 is rejected by a reader capped at 3 with the
  version error, not a hash error.

### Sidecar and derivation

- Missing, short, long, and non-regular sidecars fail closed with `EIO`.
- Derivation is deterministic for a given key and sidecar, and differs across
  sidecars and across keys.
- The same plaintext name in two directories encodes differently.

### Filesystem behavior

- `mkdir` creates a sidecar; `readdir` does not list it; `rmdir` removes it.
- `rmdir` of a non-empty directory returns `ENOTEMPTY` and leaves the sidecar
  bytes intact.
- Renaming a deep directory performs one backing rename: the directory inode,
  its sidecar bytes, and every descendant's ciphertext name are unchanged, and
  all contents read back after a remount, with and without
  `external_iv_chaining`.
- Rename of a directory onto an empty directory succeeds; onto a non-empty one
  fails and both are intact.
- File move across directories, symlink rename, and xattrs on files and
  directories all read back afterward.
- Cache: after directory renames, rmdir and mkdir reuse the same paths, every
  name still resolves to its own directory's IVs, including after a remount.

### Tools and project-wide checks

- `encfsctl new` writes the flag and the root sidecar by default;
  `encode`/`decode`/`ls`/`cat`/`export`/`showcruft` agree with the mounted
  view.
- `encfsr` rejects a directory-IV config.
- `cargo fmt -- --check`, `cargo clippy --all-targets --all-features -- -D
  warnings`, `cargo test`, and the live mount tests.
