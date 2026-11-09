# ADR 0004: Control requests over extended attributes on the mount root

## Status

Accepted and implemented in forward mode (`encfs`). The protocol and its
policy (which names are requests, who may ask, what is stored and listed, what
skips the idle lock) live in `src/rpc.rs` (`is_request`, `respond`,
`refuse_write`, `without_requests`, `is_request_admission`, the `Mount`
trait). The filesystem side is the `getxattr`/`listxattr`/`setxattr`/
`removexattr` wrappers, `EncFs::admit` and `impl rpc::Mount for EncFs` in
`src/fs.rs`, and the client is `encfsctl rpc`. `encfsr` does not answer
requests yet; `src/rpc.rs` has no dependency on `EncFs`, so it can, by calling
the same functions ahead of its own `xattrs_available()` checks.

## Context

Tools need to ask a running mount about itself: which build is serving it,
where its encrypted directory is, and whether it is read-only or idle-locked.
The mount table's `encfs@<root>` source answers only part of that, and
`--fsname` replaces it. The daemon has no socket or other channel. Adding one
would bring its own discovery, permissions and cleanup. The mount point
itself is already a well-known, permission-checked handle on the process.

## Decision

A request is a `getxattr(2)` of a reserved name on the mount root, and the
reply is the attribute's value:

```
getxattr(<mountpoint>, "user.encfs.rpc.<command>[?key=value&...]")
  -> {"protocol":1,"ok":true,"result":{...}}
  -> {"protocol":1,"ok":false,"error":{"code":"...","message":"..."}}
```

- **Name.** `<command>` and keys match `[a-z0-9_-]+`. Values are
  percent-encoded: clients encode everything except RFC 3986 unreserved
  characters, and the server decodes `%XX` and requires UTF-8. FreeBSD
  refuses a `/` in an attribute name (see `src/xattr_name.rs`), and values
  such as paths would otherwise contain one. The `user.` namespace is the one
  every platform passes through. FreeBSD's fusefs adds it to the bare name
  given to `extattr_get_file`. Names are capped at 127 bytes on macOS (255 on
  Linux), and the prefix takes 15 of them.
- **Reply.** JSON, always carrying `protocol` (currently 1) and `ok`. Error
  codes are stable (`invalid_request`, `unknown_command`, `invalid_params`,
  `unavailable`).
  Messages are English, for people, and not part of the contract.
- **Errors go in the reply, not in errno.** A filesystem that isn't encfs,
  or an encfs build before this one, answers `ENOATTR` (`ENODATA` on Linux).
  If a current build did the same for a command it doesn't know, a client
  couldn't tell "too old" from "not encfs". errno is kept for transport and
  access: `EACCES` and `ERANGE`.
- **Only the root answers.** On any other node the name is an ordinary
  attribute, so nothing about existing files changes.
- **Only the mount's owner (or root) may ask.** Callers whose uid is not the
  daemon's euid get `EACCES`. With `--public` other users can reach the root,
  and `info` names the encrypted directory even where `--fsname` hides it.
- **Requests are not attributes.** `setxattr` and `removexattr` of a
  request name on the root fail with `EPERM`. That reserves the prefix for
  later commands and keeps anyone from storing a value getxattr could never
  return. `listxattr` on the root never lists request names, so `cp -a`,
  `rsync -X` and `tar` don't try to copy them. An attribute an earlier build
  stored under such a name on the root is shadowed and left out of listings.
- **Answered while idle-locked.** The idle lock is applied in `EncFs::admit`,
  which typed-fuse calls before taking its locks, with an `Admission` that
  carries the attribute name and whether the request addresses the root.
  `rpc::is_request_admission` picks out getxattr, setxattr and removexattr of
  a request name on the root, and those skip the lock. So `info` reports
  `idle_lock.locked: true` instead of failing, and a write to a request name
  fails with `EPERM` without prompting, since a successful prompt would
  unlock the mount for a call that can't succeed.
- **Works without extended attributes.** Requests are intercepted before the
  `xattrs_available()` check, so V4-V6 volumes and V7 volumes in the old
  path-IV format answer too.

### `info`

Takes no parameters. The result holds `version`, `build`
(`build_info::VERSION`), the daemon's `pid`, `root` (the canonical encrypted
directory), `mount_point`, `read_only`, a `config` summary (`format`,
`cipher`, `name_encoding`, `key_size`, `block_size`, `block_mac_bytes`,
`unique_iv`, `chained_name_iv`, `external_iv_chaining`, `directory_iv`,
`xattrs_available`), `idle_lock` (`null`, or `timeout_secs` and `locked`),
and `commands`, the names of every command this build understands. Clients
can check `commands` before sending a newer request. A listed command can
still fail on a mount that lacks what it acts on: `lock` is listed without an
idle lock, which `idle_lock: null` shows. The list comes from the same table
that dispatches requests (the `HANDLERS` table in `src/rpc.rs`), so it can't
drift: adding a command means adding a row there.

`root` and `mount_point` are JSON strings, and JSON can only carry Unicode.
A path that isn't valid UTF-8 (which Linux and FreeBSD allow) is reported
with each invalid byte sequence replaced by U+FFFD, so the reported string
names a different path, possibly none. Clients that open these paths should
check them first, for example by comparing `root` with the mount table's
`encfs@<root>` source, or fall back to the mount point they called. They are
exact for every UTF-8 path, which includes every macOS path. A lossless form
(say, a base64 `root_bytes` beside `root`) can be added later without changing
these fields.

### `lock`

Takes no parameters. Engages the idle lock at once, as if its timeout had
passed (`IdleLock::lock`), and returns the lock's new state (`timeout_secs`,
`locked`). The next data operation then prompts for authentication. A mount
without an idle lock (no `--touchid`) answers with the `unavailable` error.

`lock` changes state over getxattr, which reads are expected to use. That is
acceptable here because locking only ever takes access away and is
idempotent. A size probe that repeats the call, or a stray read of the name,
can do no more than lock an already locked mount. Locking on a read-only mount
still makes sense, so it isn't refused there.

## Consequences

- One stateless syscall per request. It needs no write access, so read-only
  mounts answer, and there is no session to clean up.
- A reply can't take more than the attribute size limit (64 KiB on Linux).
- The usual size probe (a size-0 getxattr, then the read) can fail with
  `ERANGE` if the reply changes in between, for example when the lock
  engages. Clients should retry, or do as `encfs::rpc::call` does and read
  once into a 64 KiB buffer.
- getxattr can't carry a request body, and setxattr can't return one.
  Commands that change state in ways that aren't idempotent, or that grant
  access, will need another shape, such as a setxattr of a request name whose
  outcome is read back with getxattr. The `EPERM` reservation keeps that open.
