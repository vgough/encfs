# ADR 0003: Per-inode IV seed for encrypted extended attributes (V7)

## Status

Accepted and implemented. The seed lives in `src/xattr_name.rs`, the
derivation in `SslCipher::xattr_iv` (`src/crypto/ssl.rs`), the forward
filesystem side in `src/fs.rs` (`xattr_iv`, `xattr_iv_or_create`,
`copy_encrypted_xattrs`) and the reverse side in `src/reverse_fs.rs`
(`xattr_seed_and_iv`). Supersedes the xattr rows of ADR 0002.

## Context

V7 volumes encrypt extended attribute names and values. Until now the IV for
an entry's attributes was its path IV (its entry IV in directory IV mode), or
for a directory in directory IV mode the sidecar's `node_iv`. Anything that
changed the path IV invalidated every attribute on the entry:

- In directory IV mode a file rename re-keyed the attributes from the old
  entry IV to the new one. `setxattr` needs write access to the inode, so a
  read-only (`0444`) file failed the re-key with `EACCES`. The in-place path
  left the attributes under the old IV (unreadable until renamed back); the
  copy path (external IV chaining) restored the mode before re-keying and
  then removed the source, losing them for good. Failures were only logged.
- In chained mode nothing re-keyed at all: any rename of a file, and the
  copy behind a directory rename, silently lost encrypted attributes.
- Hard links have one inode but a path IV per name, so attributes set
  through one link were unreadable through another.

Keying attributes by the file header's IV was considered and rejected: an
`O_TRUNC` open writes a fresh header (so `> file` would orphan every
attribute), reads would need to open the file and so need read permission,
and directories, symlinks, special files and `unique_iv = false` volumes have
no header.

## Decision

Each inode that carries encrypted attributes also carries a random seed:

```
user.encfs.~iv = 16 random bytes                  // stored in the clear
xattr_iv       = LE64(HMAC-SHA256(volume_key, "encfs.xattriv.v1\0" || seed)[0..8])
```

All of an inode's encrypted attributes (names and values, stored under
`user.encfs.<base64>` as before) are encrypted under `xattr_iv`. `~` is in
neither base64 alphabet, so the seed's name can't collide with an encrypted
one; it is never listed through the mount.

- **setxattr** reads the seed, or creates one with `XATTR_CREATE` (a racing
  creator that gets `EEXIST` reads the winner's; FreeBSD, which only
  emulates `XATTR_CREATE`, also serializes creation with a lock). Creating it
  needs the same write access the caller's own `setxattr` needs. With
  `XATTR_REPLACE` and no seed it fails with `ENOATTR` and creates none.
- **getxattr/removexattr** without a seed return `ENOATTR`.
- **listxattr** reads the seed only when encrypted names are present; names
  without a seed beside them (the retired format) are skipped. Reading the
  seed needs read access to the entry, which listing names doesn't on Linux;
  without it the encrypted names are left out rather than failing the list.
- The seed is never removed, so a concurrent `setxattr` can't lose it.
- The seed is read with one fixed-size `getxattr` (a spare byte detects an
  oversized seed even where reads truncate, as on FreeBSD), and the derived
  IV is cached in the inode's node state (`FileState`). A seed never changes
  in place, so the cache is only dropped where the inode behind a state may
  be new (create, mknod, mkdir, symlink, which can reuse a deleted inode's
  number while its state is alive) or have been given another seed (a
  rename's copy onto an existing destination). A node renamed by copy keeps
  its state; the copy carries the seed, so the cached IV stays right. The
  removed source inodes' states are detached from the state table, so a new
  inode the backing filesystem gives a freed number to (ext4, XFS, ZFS and
  UFS reuse them) gets a state of its own instead of sharing the renamed
  entry's. A file that still has other hard links keeps its entry.
- Attribute values are first read into a 256-byte buffer, so the common
  case is one syscall rather than a size probe and a read.
- Directories use the same mechanism in both name-IV modes; the sidecar's
  second derived value is now unused.

Renames:

| Rename | Attributes |
|---|---|
| `rename(2)` of the inode (file or symlink in place, any directory in directory IV mode) | untouched |
| Copy (external IV chaining, symlink re-creation, chained directory copy) | raw bytes of every `user.encfs.*` attribute, seed included, read from the source first, then reconciled onto the destination while it is still writable: values it already holds (as after macOS `fs::copy`, which clones attributes) aren't rewritten, and names only it has are removed; a failure fails the rename and keeps the source |

Reverse mode has no stored seed: it presents
`seed = HMAC-SHA256(volume_key, "encfs.xattrseed.reverse.v1\0" || LE64(path_iv))[0..16]`
on entries that have attributes, so ciphertext copied out of the view
(including the seed) decrypts on a forward mount. With `--write`, setting the
seed to its presented value is a no-op, any other value is `EINVAL`, and
removing it is refused.

### Config

New wire value `XATTR_FORMAT_ENCRYPTED_INODE_IV = 2` with
`minimum_reader_version` 5 (`V7_INODE_XATTR_IV_CONFIG_VERSION`). Every new V7
volume uses it, including those made with the compatibility flags
(`--legacy-file-iv`, `--no-unique-iv`, `--no-directory-iv`), so all new
volumes need a reader that implements version 5.

The old format (wire 0, now `XATTR_FORMAT_ENCRYPTED_PATH_IV`) is not
implemented. On such a volume extended attributes are unavailable
(`EncfsConfig::xattrs_available`): `listxattr` returns an empty list and the
other operations fail with `ENOTSUP`, as on a filesystem without extended
attributes; `encfsr` presents its view the same way. Nothing is read,
written or removed, and the config is never rewritten, so going back to an
earlier version finds its attributes and config exactly as it left them.
Renames that copy an entry still carry its stored attribute bytes across.
`encfs`, `encfsr` and `encfsctl info` warn that attributes are unavailable.

On macOS, macFUSE answers a filesystem's `ENOTSUP` from `setxattr` by
storing attributes in AppleDouble `._` files instead, as on FAT or SMB
volumes. So that these volumes stay as an earlier version left them, `encfs`
and `encfsr` mount them with macFUSE's `noappledouble`: attribute writes then
fail (macFUSE reports `EPERM`), and `._` and `.DS_Store` files are refused
and hidden, so Finder doesn't save view settings there. Plaintext-format and V4-V6 volumes pass
attributes through unchanged; `user.encfs.*` names there (encrypted copies
from earlier builds) are hidden and no longer read.

## Consequences

- Renames never touch attributes, and read-only files keep theirs.
- Hard links share attributes.
- Attributes survive truncation and header rewrites.
- One extra 16-byte attribute per inode that has encrypted attributes, and
  one extra `setxattr` the first time an inode gets an attribute. macOS sets
  `com.apple.provenance` on every new file and directory, so on macOS that
  is every creation; `encfs --no-apple-xattr` (macFUSE `noapplexattr`) keeps
  `com.apple.*` attributes off the volume altogether.
- Attributes are bound to an inode, not a name: someone with write access to
  the backing store can move a file with its attributes and seed, and they
  still decrypt. This is the trade ADR 0002 already accepted for directory
  contents.
- `listxattr` on an entry with encrypted attributes now reads one attribute
  value, which on Linux needs read permission on the entry; without it the
  encrypted names aren't listed.
- Backup tools must keep `user.*` attributes together; dropping the seed
  makes the others unreadable.
- Existing encrypted attributes on V7 volumes created before this change are
  lost to the new reader; there is no migration.
