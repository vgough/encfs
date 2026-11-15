# ADR 0007: `encfsctl fsck` recovers sync-conflict copies

## Status

Accepted, and implemented as `encfsctl fsck` (`src/fsck.rs`, with the
command line in `src/encfsctl/fsck.rs`). Recorded November 11, 2026, as an
alternative to PR #724 ("new sync-conflict behavior paragraph under reverse
mode"). The goal is the same:
conflict copies that sync tools make must not be lost. This design gets
there offline, with a new `encfsctl fsck` command, and leaves the live
filesystems unchanged. It builds on PR #725 (`Cipher::decrypt_entry_name`).

An earlier draft of this ADR handled conflict copies inside a live `encfsr`
mount: tagged plaintext names for conflict copies, plus a hidden store for
tool-private files. That draft is summarized under Alternatives considered.

## Context

Sync tools keep both versions of a file changed in two places. They write one
of them under the original name plus a suffix. When the synced directory is
an EncFS ciphertext tree, the name gets a suffix the cipher never produced:

| Tool | Conflict copy of `<V>` |
|---|---|
| Syncthing | `<V>.sync-conflict-<yyyymmdd>-<hhmmss>-<device id>` |
| Nextcloud desktop | `<V> (conflicted copy [<user> ]<yyyy-MM-dd hhmmss>)`; old clients `<V>_conflict-<date>-<time>` |
| Dropbox desktop | `<V> (<user>'s conflicted copy <date>)`, `<V> (Case Conflict)`, in the system language |
| rclone bisync | `<V>.conflict1`, `<V>.conflict2` (`..path1`, `..path2` before v1.66; the suffix is configurable) |

A ciphertext name contains no `.`, so tools that put their marker before an
extension append it instead. The tools also leave temp files behind when
interrupted: Syncthing's `.syncthing.<V>.tmp`, Nextcloud's `.<V>.~<hex>`,
and rclone's `<V>.<hash>.partial`, where rclone may truncate `<V>`. Their
own state also lives in the directory: `.stfolder`, `.stignore`,
`.stversions/`, `.sync_<hex>.db*`.

Where those names end up depends on the mode:

- **Forward mode** (the encrypted directory is what gets synced, and `encfs`
  mounts it). Conflict copies and temp files land on disk in the ciphertext
  tree. The mount hides them, because readdir skips names that don't decrypt
  and names starting with `.`. `encfsctl showcruft` lists them, but nothing
  recovers them. The synced directory is an ordinary directory, so any of
  these tools can sync it. A tool that writes into it while it is mounted
  needs the README's settings for that case (no directory IVs, no chaining),
  because the mount caches directory IVs.
- **Reverse mode** (`encfsr` presents a plaintext source as ciphertext, and
  the view is what gets synced). The ciphertext tree exists only on the
  remote, or in a mirror of it. A conflict copy written *through* a live
  `--write` view is rejected with `ENOENT` and never reaches disk.

PR #724 makes the live reverse view accept `<V> <suffix>` and store the copy
in the plaintext source behind a marker. Reviewing it, and then extending it
to every surveyed tool, needed authenticated tags in plaintext names, a
persistent hidden store for tool files, commit-on-rename, and a new
classification step on every lookup. That is a lot of new behavior in the
mount's hottest path to cover a rare event, and each piece came with its own
edge cases.

## Decision

Add `encfsctl fsck`. It scans a ciphertext tree offline, classifies every
name that doesn't decrypt, and reports or repairs each one. The live `encfs`
and `encfsr` mounts don't change.

```text
encfsctl fsck [--config <file>] [--fix] [--yes] [--older-than <hours>]
              [--extpass <program>] [--force] [-v] <rootdir>
```

- With no flags, fsck only reports. The exit status is 0 when it finds
  nothing and 1 when it finds something.
- `--fix` asks about each finding: recover, recover under a name the user
  types, delete, skip, or quit, with the default action for that class
  pre-selected. `--fix --yes` applies the defaults without asking. `--fix`
  without `--yes` needs a terminal and refuses to run without one, rather
  than read answers from a pipe.
- `--config` names the config file when `<rootdir>` doesn't contain one. A
  mirror of a reverse view usually does, since the view serves `.encfs7` at
  its root. It is needed only when the sync excluded it. The config in use
  is recognized by its inode wherever it sits in the tree and whatever its
  name, so it is never classified, let alone deleted as a copy of itself.
- fsck refuses to modify a tree that is currently mounted, because the
  forward mount caches directory IVs. It checks the mount table
  (`/proc/self/mountinfo` on Linux, `getmntinfo` on macOS and FreeBSD) for
  an `encfs@<rootdir>` source, under the canonical and the absolute root.
  `--force` skips that check. Report-only mode doesn't check.
- It also asks the user to stop the sync tool while it runs. fsck is not safe
  against a tool writing into the same tree.
- Run it on **one replica only**, and let the sync tool carry the result to
  the others. Recovering on two replicas at once writes new files on both,
  particularly through the headerless re-encrypt path. That makes fresh
  conflicts.

`showcruft` keeps its output, and it is a subset of fsck's report. It now
runs fsck's report-only scan with its own handler, which prints only the
names not starting with `.` (and unreadable directory IVs) as before, so the
two commands walk the tree and skip names the same way.

### Classification

fsck walks the tree with the same IV logic as `export`. Directory IV mode
reads each `.encfs.diriv`, and chained names derive from the parent. It
classifies every entry whose name fails `decrypt_entry_name`, in this order.

1. **EncFS metadata conflict.** The name is a copy of `.encfs.diriv`,
   `.encfs7`, `.encfs6.xml`, `.encfs5` or `.encfs4`. These names contain
   dots, so the tools mark them in two ways. Nextcloud, Dropbox and bisync
   append to a name that starts with its only dot (`.encfs7 (conflicted
   copy …)`) and otherwise insert before the extension (`.encfs6 (…).xml`).
   Syncthing always inserts before Go's `filepath.Ext`, which starts at the
   last dot, so `.encfs7` becomes `.sync-conflict-….encfs7` and
   `.encfs.diriv` becomes `.encfs.sync-conflict-….diriv`. fsck accepts both
   forms. Config copies are only looked for at the root. The live names and
   mkdir's `.encfs.<hex>` staging directories are passed over. See Metadata
   conflicts.
2. **Tool state.** The name matches a known tool's state file: `.stfolder`,
   `.stignore`, `.stversions`, `.sync_*.db`, `.sync_*.db-wal`,
   `.sync_*.db-shm` (and the older `._sync_*` forms), `.dropbox`,
   `.dropbox.attr`, `.dropbox.cache`, `.nextcloudsync.log`,
   `.owncloudsync.log`, or bisync's `RCLONE_TEST`. fsck never touches these,
   lists them only with `-v`, and doesn't count them as problems.
3. **Stale temp.** The name matches a known temp pattern:
   `.syncthing.*.tmp`, `~syncthing~*.tmp`, `.*.~<hex>`, or `*.partial`.
   fsck offers to delete one only if it is older
   than `--older-than`, which defaults to 24 hours. Syncthing keeps temps for
   a day so it can resume, and a younger temp may be in use. fsck's own
   temps (`.encfs.fsck-<hex>`, see Recovering) are always stale, since only
   a crash leaves one behind.
4. **Conflict copy.** The name is a decodable base plus a suffix, and the
   entry's contents verify as a copy of that base. See Finding the base.
   The default action is recover.
5. **Unknown.** Everything else is reported, as `showcruft` reports it. It is
   deleted only when the user chooses that for the specific entry, and
   `--yes` never deletes it.

Other names starting with `.` are skipped, as in `showcruft`.

### Finding the base

The base of a conflict copy is a prefix `B` of the name `V = B ‖ S`, where:

- `B` decrypts with `decrypt_entry_name` under the directory's names IV,
  giving `P`. That call refuses a `P` that isn't a single path component
  (PR #725).
- `B` is canonical: `encrypt_filename(P, iv).0 == B`. This rejects
  lower-case block32 and stray trailing bits.
- `S` is non-empty.

fsck tries the split at the first byte outside the name encoder's canonical
alphabet first. Base64 uses `,`, `-`, `0-9`, `A-Z` and `a-z`; block32 uses
`A-Z` and `2-7`. That split covers every suffix the surveyed tools write.
fsck then tries every shorter prefix, longest first. That covers suffixes
that continue inside the alphabet, such as a hypothetical `-DEVICE` under
base64. This costs at most one decrypt per byte of the name, and it only
runs on names that already failed to decrypt.

A base passing the 16-bit name checksum is not evidence enough: a random
prefix passes it with probability 2⁻¹⁶. The contents can confirm the base,
but only when the config binds them to the name.

- **Bound.** The contents depend on `P`'s path IV, and the format
  authenticates them:
  - a V7 file with external IV chaining, under chained names or directory
    IVs: its file IV comes from `P`'s path IV, through the header or, when
    headerless (`unique_iv = false`), directly. Its first block must
    authenticate under it. A wrong base fails there, so the rest of the
    file isn't read, and checking a large conflict copy costs one block.
    An all-zero block, which a volume allowing holes reads as zeros,
    proves nothing and is passed over to the next one, and a file with no
    other block (empty, or only a header) is only probable. A headerless
    file *without* external IV chaining has file IV 0 whatever its name, as
    in `EncFs::create_impl` and `ReverseFs::file_iv_for_path`, so it isn't
    bound;
  - a legacy file with block MACs and external IV chaining: the header must
    decrypt under `P`'s path IV and the first block MAC must verify, as
    above. Legacy MACs are 1 to 8 bytes, so a wrong base passes one with
    probability 2⁻⁸ˣ for `x` bytes, which checking further blocks would
    have lowered. With short MACs, verified is the weaker claim;
  - a directory under chained names: its children's names must decode
    under `P`'s chained IV. When every child not starting with `.` decodes,
    the candidate is verified. When only some do, or the directory is empty,
    it is probable. When none do, the candidate is ruled out;
  - a symlink whose target encryption uses `P`'s IV: the target must decrypt.

  The tool copied the entry byte for byte, so a real copy passes and a false
  base fails. A passing candidate is **verified**. Contents that can't be
  read (a permission error, an I/O error) rule nothing out: the candidate
  stays, as probable, and the read error is reported as a warning.
- **Not bound.** Every other config, including the README's Dropbox settings:
  `--no-chained-iv` turns external IV chaining off, so a file's blocks
  authenticate under its own header IV whatever its name is. The same goes
  for legacy files without block MACs, and for directories in directory IV
  mode or with no name IV. Any valid entry of the volume passes for any `P`
  that clears the checksum. fsck still checks what it can (the file must at
  least be valid ciphertext of this volume), but the candidate is only
  **probable**.

`--yes` recovers the only verified candidate, if exactly one is verified.
When none is verified, it recovers the only probable candidate that comes
from the first split (at the first byte outside the alphabet) and whose
`P` names an existing sibling, which is what a real conflict copy looks
like. Anything else is offered without a default, and `--yes` skips it.
Each shorter prefix tried is another 2⁻¹⁶ chance of a false match, so the
every-prefix search only produces probable candidates unless the contents
bind. Such a false match almost never also names an existing sibling, so it
doesn't stop `--yes` from recovering the one that does.

fsck lists every candidate that passes: verified ones first, then those
naming an existing sibling, then first splits, then longer bases. A wrong
choice gives the recovered data a meaningless name. It loses no data, and
the user can rename it in the mount.

### Recovering a conflict copy

Recovery gives the copy an ordinary encrypted name, so the mount shows it
like any other file.

1. **Choose a plaintext name.** Use `stem(P) ‖ " (" ‖ s ‖ ")" ‖ ext(P)`,
   where `s` is the suffix with leading spaces, dots and underscores removed,
   and one pair of enclosing parentheses removed. `ext(P)` is `P`'s last
   `.xxx` of 1-10 ASCII alphanumerics, not at the start of the name, or
   nothing. An empty `s` becomes `conflict`. If that name exists, fsck adds
   ` 2`, ` 3`, and so on before the extension (`report (conflict1) 2.docx`).
   If `enc(N)` is longer than 255 bytes, fsck shortens `s` until it fits.
   With `--fix`, the user can type another name, which must be free.

   ```text
   report.docx + ".sync-conflict-20230709-123456-ABCDEFG" → report (sync-conflict-20230709-123456-ABCDEFG).docx
   report.docx + " (conflicted copy alice 2023-07-09 123456)" → report (conflicted copy alice 2023-07-09 123456).docx
   report.docx + ".conflict1" → report (conflict1).docx
   ```

   An entry that decodes under a conflicting `.encfs.diriv` copy (see
   Metadata conflicts) is recovered under its own name `P` when that is
   free, and otherwise under `P` with the sidecar copy's suffix.

2. **Move it under the new name.** The new name `N` is encrypted under the
   directory's names IV. How the contents move depends on whether they depend
   on the path:
   - **Contents don't depend on the path** (no external IV chaining, or a
     directory in directory IV mode): `rename(2)` the entry to `enc(N)`,
     refusing to replace anything (`renameat2(RENAME_NOREPLACE)` or
     `renameatx_np(RENAME_EXCL)`, or a check first where neither exists).
   - **Header IV bound to the path** (`unique_iv` with external IV
     chaining, the V7 default): rewrite the header from `P`'s path IV to
     `N`'s.
   - **Headerless file with a path IV** (`unique_iv = false` with external
     IV chaining, which reverse volumes may use): decrypt every block under
     `P`'s IV and re-encrypt it under `N`'s. All-zero blocks stay as they
     are.
   - **Directory in chained-name mode**: every descendant's name and path IV
     change, so the subtree is rebuilt under the new names, as forward-mode
     directory rename does. Descendants whose own bytes don't depend on the
     path (files without external IV chaining) are hard-linked into it
     rather than copied, where the backing filesystem allows links.

   These rules live in `src/recrypt.rs` (`Recrypt::copy_tree`), which
   forward-mode rename uses too, with hooks for the mount's per-inode
   locks and state. Every rule but the plain rename builds the new entry
   under a temp name `.encfs.fsck-<hex>` in the same directory, syncs every
   file and directory in it, renames it to `enc(N)` without replacing
   anything, and syncs the parent. The source is then renamed aside to
   another temp name and removed. A crash leaves either the source or both,
   never neither, and a source that can't be removed is left under a temp
   name, which the next run deletes as stale, rather than as a conflict
   copy it would recover a second time; the recovery itself has succeeded,
   and the failed removal is reported as a warning.

   Inside a re-encrypted directory, a name that doesn't decode is usually
   copied (or linked) byte for byte. A conflict copy is the exception: if
   `--yes` would recover it, its base is re-encrypted with the directory
   and its suffix kept, so it is still recoverable in the new directory,
   where fsck goes on to recover it. One whose base is uncertain keeps its
   old bytes, with a warning.
3. **Copy metadata.** Mode, timestamps and extended attributes carry over.
   Per-inode xattrs (ADR 0003) are keyed by a seed stored on the inode, so an
   in-place rename keeps them valid. When the entry is rewritten, the copy
   carries the attributes a mount shows with
   `encfs::fs::copy_backing_xattrs`: the stored encrypted ones, seed first,
   where the volume encrypts them, and every attribute where they pass
   through unencrypted (V4–V6, or V7 with plaintext attributes).
   Ownership isn't changed: fsck runs as the user who owns the tree.

**Delete** removes the entry. For a directory, it asks once for the whole
subtree.

### Metadata conflicts

These are the findings that matter most. A conflicted sidecar or config can
make a whole directory, or the whole volume, unreadable.

- **`.encfs.diriv` copy.** If its bytes equal the live sidecar's, delete it.
  Otherwise the two machines created the directory independently, and names
  written on one side won't decode under the other side's sidecar. For each
  undecodable entry in that directory, fsck tries the copy's IV. Each entry
  that decodes under it is offered for a rename to `enc(P)` under the live
  sidecar, using the same move rules as recovery. If the plaintext name is
  taken, the entry goes through the conflict-copy naming instead. A
  conflict copy the other side's sync tool made of such an entry has its
  base encrypted under the copy's IV, so fsck also looks for conflict-copy
  bases under it. Sidecar copies come last in their directory, so these
  entries are handled first. Once nothing depends on the copy, whether a
  whole name or a conflict copy's base, fsck offers to delete it, and
  `--yes` does. While something does, deleting it isn't offered.
- **Config copy** (`.encfs7`, `.encfs6.xml`, …). fsck unlocks the copy with
  the same password, loading it in the format of the config it copies
  (`EncfsConfig::load_with_type`), since nothing in a V4 config's bytes
  tells it from V5. If it yields the same volume key and an equivalent config,
  it is a harmless duplicate, and fsck offers to delete it. The keys are
  compared by what both ciphers produce for the same names, header and
  MAC input, so no key leaves the cipher. "Equivalent" means every setting
  that affects encryption matches; the KDF parameters and salt may
  differ. If not,
  fsck reports it and changes nothing: one side changed the password or the
  settings, and only the user can choose. The report gives the commands to
  inspect both (`encfsctl info`).

### Reverse mode

A reverse volume's ciphertext only exists remotely, so fsck runs against a
copy or a mount of the remote, such as `rclone mount` or a directory a sync
tool keeps:

```text
encfsctl fsck --fix /mnt/remote-mirror        # mirror includes .encfs7
encfsctl fsck --config ~/Documents/.encfs7 --fix /mnt/remote-mirror
```

Recovery renames each conflict copy on the remote to an ordinary ciphertext
name, re-encrypting its contents for that name because reverse volumes are
headerless. The next sync down through an `encfsr --write` view then
delivers it as an ordinary file, which the view already accepts. No change
to `encfsr` is needed.

What this design doesn't do: a tool that creates the conflict copy *inside*
the live view still fails there, exactly as on master. That covers bisync
renaming its Path1 loser, the Nextcloud and Syncthing clients, and anything
else that renames in place. Syncthing and Nextcloud can't sync through a
reverse view anyway, because they need dot-prefixed temp and state files.
The documentation should say so plainly:

- Use `encfsr` for one-way backup, and for restore with rclone (with
  `--inplace`, because rclone's `.partial` temp names don't decrypt).
- For two-way sync with conflict handling, sync a forward-mode encrypted
  directory and mount it with `encfs`.

## Consequences

- **The live mounts don't change.** There are no new lookup paths, no hidden
  store, no tags in plaintext names, and no new false positives on create.
  The mounts behave exactly as on master.
- **Recovery is explicit, and verified where the format allows.** Where
  the contents are bound to the name, a base that passes the 16-bit checksum
  by chance is rejected. Where they aren't (no external IV chaining, which
  includes the README's Dropbox settings), `--yes` recovers only the common
  shape: the first split, with an existing sibling. A false match there
  (about 2⁻¹⁶ per copy) gives recovered data a meaningless name. It never
  loses data.
- **Conflict copies stay invisible until fsck runs.** In forward mode, the
  mount keeps hiding them, as today. Users need to know to run fsck. The
  forward mount could log once per directory when readdir skips a name that
  looks like a conflict copy (a decodable prefix followed by a suffix), and
  suggest `encfsctl fsck`. That costs nothing until such a name exists. See
  Open questions.
- **No compatibility questions.** Recovered names are ordinary names, so any
  EncFS version, including C++ EncFS for V6 volumes, reads the result.
  Upgrading changes no listing. There is no marker word or tag format to fix
  forever.
- **The remote sees renames.** Recovering a copy renames it in the synced
  tree. With external IV chaining, its contents are rewritten too, so the
  sync tool uploads a new file and deletes the old name.
- **A recovered copy shares IVs with its original.** The sync tool copied
  the entry byte for byte, and recovery keeps its file IV (the header is
  re-encrypted, not regenerated), so the copy and the original encrypt
  under the same file IV. In directory IV mode, a recovered directory also
  shares its `.encfs.diriv` with the original. That doesn't matter while
  one is a stale copy, but later edits to both encrypt under one IV: under
  AES-GCM-SIV that shows which blocks are equal, and legacy modes leak more.
  Fresh IVs would mean re-encrypting every recovered file and subtree, which
  fsck doesn't do.
- **Reverse `--write` stays limited**, as described under Reverse mode.

PR #724 review findings, against this design: findings 1–3, 5, 8, 9 and 10
concerned the live mapping, and don't arise because there is none. Finding 4
(only space suffixes) is covered by the every-prefix search. Finding 6
(length) becomes a check that `enc(N)` fits the backing directory's name
limit; if it doesn't, fsck shortens the suffix part of `N`. Finding 7
(symlinks) is covered by the symlink content check.

## Sync tool coverage

Checked on November 11, 2026 against each tool's documentation or source.
None of the tools was run.

| Tool | Forward mode (synced ciphertext dir) | Reverse mode |
|---|---|---|
| Syncthing | Copies recovered; `.syncthing.*.tmp` cleaned once older than 24 hours; `.stfolder`, `.stignore`, `.stversions` left alone | Can't sync through a `--write` view (dot-prefixed temps, `.stfolder`). fsck works on a ciphertext mirror |
| Nextcloud desktop | Copies (both naming forms) recovered; `.<V>.~<hex>` cleaned; `.sync_*.db*` left alone | As Syncthing |
| Dropbox desktop | Copies and `(Case Conflict)` recovered; `.dropbox*` left alone | The Dropbox folder can't be a FUSE mount. fsck works on a Dropbox folder holding a ciphertext mirror |
| rclone bisync | `.conflict1`/`.conflict2`, custom suffixes and `..path1`/`..path2` recovered; `.partial` cleaned | Path2-side copies recovered on the remote. A Path1 loser rename inside the view fails, as on master |
| rclone sync/copy | No conflict copies. `.partial` leftovers, including truncated ones, cleaned | Restore with `--inplace` |

## Alternatives considered

- **PR #724: accept `<V> <suffix>` in the live reverse view.** Rejected. Its
  marker is unauthenticated, so it leaks names users chose and renames
  existing files on upgrade. It handles only space suffixes and adds 2⁻¹⁶
  false positives on create.
- **The earlier draft of this ADR: live classification in `encfsr`.** View
  names were classified as ordinary, a suffixed copy with a keyed tag in its
  plaintext name, or a private name kept in a hidden per-directory store,
  with renames from the store committing their contents. It would have let
  Syncthing and Nextcloud sync through a reverse view. Rejected for now. It
  puts a new decision into every lookup, adds a persistent store, a tag
  format and a commit path, and keeps a 2⁻¹⁶ false-positive rate. All of
  that is to handle in the hot path a rare event that can be fixed
  afterwards. If two-way sync through a reverse view becomes a goal, that
  design is the starting point. The draft was never committed, so this
  summary is its only record.
- **Recover automatically at mount time.** Rejected. It would modify the
  synced tree while the sync tool is running, and the user wouldn't choose.
- **Extend `showcruft` instead of adding a command.** Rejected. `showcruft`
  is read-only, and changing what it does would surprise scripts that use it.
  fsck's report-only mode covers the same ground. `showcruft` shares fsck's
  scan instead, keeping its output.

## Open questions

- Should the forward mount log a hint when readdir hides a name that looks
  like a conflict copy? This means one prefix decrypt per skipped name and
  one log line per directory.
- Is the built-in tool pattern list enough, or should users be able to add
  patterns (`--temp-pattern`, `--state-pattern`)?
- Should `--yes` also apply recoveries that leave a name collision behind
  (`… 2`)? It does now.
- Is detecting a mount from the mount table enough? `--fsname` can hide the
  `encfs@<root>` source.

## Verification

Implemented in `tests/fsck_test.rs` and the unit tests in `src/fsck.rs`
and `src/encfsctl/fsck.rs`. The tests build volumes through `EncFs`, plant
conflict copies byte for byte as a sync tool would, run fsck, and read the
results back through a fresh `EncFs`. The reverse mirror case drives a
writable `ReverseFs` through `typed_fuse_core::Runtime`. Deliberate
breakages each make tests fail: always renaming, copying headerless files
raw, accepting failed content checks, and dropping the shorter-prefix
search. The mount check needs a real mount and has no automated test; it
was checked by hand against a macFUSE mount.

- **Classification.** A forward-mode tree containing:
  - each tool's conflict names over files, directories and symlinks;
  - suffixes inside the alphabet;
  - fresh and stale temps, and tool state files;
  - `.encfs.diriv` and config copies (identical and different);
  - random junk.

  Run under stream and block32, with and without directory IVs and external
  IV chaining, and with V6 and V7. Each entry lands in the expected class.
- **No false recovery where contents are bound.** On a V7 volume with
  external IV chaining, a file whose name has a decodable prefix but whose
  contents belong to another file is classified Unknown and never recovered.
- **Unbound configs.** On a `--no-chained-iv` volume, the same file is
  classified probable. `--yes` recovers it only if it uses the first split
  and its base names an existing sibling.
- **Recovery.** After `--fix --yes`, the mount lists each recovered file under
  its new name with the original contents, mode, mtime and xattrs. Covered
  for every move rule: in-place rename, header rewrite, headerless
  re-encrypt, and chained directory subtree.
- **Sidecar conflict.** Names created under a conflicting `.encfs.diriv` are
  renamed under the live sidecar and become visible. The copy is then
  deleted.
- **Config conflict.** Both an identical copy and a password-changed copy;
  only the first is deleted.
- **Safety.** fsck refuses a mounted tree without `--force`. Report-only mode
  modifies nothing (compare tree hashes). `--yes` never deletes Unknown
  entries, and never deletes temps younger than `--older-than`. A base that
  decrypts to `..` or `/x` is never used (PR #725).
- **Reverse mirror.** fsck with `--config` on a mirror of a reverse view
  recovers a bisync `.conflict2` copy. Syncing it down through
  `encfsr --write` with rclone `--inplace` creates the plaintext file in the
  source.
