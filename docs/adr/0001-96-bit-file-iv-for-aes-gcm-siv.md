# ADR 0001: 96-bit file IVs for AES-GCM-SIV (V7) filesystems

## Status

Proposed

## Context

New EncFS filesystems default to the V7 config format with AES-GCM-SIV block
encryption (`EncfsConfig::standard_v7()`, `src/config.rs:182`). Every file gets
a random per-file IV, stored encrypted in an on-disk header when `uniqueIV` is
set, and mixed with the per-block index to build the AES-GCM-SIV nonce and AAD
for each block.

That per-file IV is hardcoded to 64 bits throughout the implementation:

- `file_iv: u64` runs through the `Cipher` trait (`src/crypto/cipher.rs:38-90`).
- The on-disk header is a fixed 8 bytes, gated only by `uniqueIV`
  (`Config::header_size()`, `src/config.rs:862-864`).
- The AES-GCM-SIV nonce/AAD construction mixes a 64-bit `file_iv` with the
  64-bit block number (`src/crypto/ssl.rs:860-872`):

  ```rust
  fn aes_gcm_siv_nonce(file_iv: u64, block_num: u64) -> [u8; 12] {
      let mut nonce = [0u8; 12];
      nonce[..8].copy_from_slice(&(file_iv ^ (block_num >> 32)).to_le_bytes());
      nonce[8..].copy_from_slice(&(block_num as u32).to_le_bytes());
      nonce
  }
  ```

AES-GCM-SIV already receives a 96-bit nonce from this implementation. The
limitation is that only 64 random bits distinguish files; the remaining nonce
bits encode the block number. A collision between two random file IVs therefore
causes equal block numbers in those files to reuse nonces. AES-GCM-SIV is
nonce-misuse resistant, so a repeat is not catastrophic, but it can reveal that
the corresponding plaintext blocks are equal and reduces the construction's
security margin.

[RFC 8452](https://www.rfc-editor.org/rfc/rfc8452.html), the specification for
AES-GCM-SIV, defines a 96-bit nonce, recommends randomly generated nonces, and
describes the residual equality leakage when a nonce repeats. NIST SP 800-38D
is about GCM rather than AES-GCM-SIV and is not the normative basis for this
decision.

This is scoped to the AES-GCM-SIV block path only. The legacy CBC/CFB block
mode (V4-V6, and V7-with-legacy-cipher) keeps its existing 64-bit file IV /
HMAC-derived IV scheme untouched. Headerless configurations (`unique_iv =
false`), including all reverse-mode configurations, also retain their existing
64-bit path-derived IV.

## Decision

Widen the random per-file IV used by AES-GCM-SIV files with stored headers from
64 to 96 bits and make it the default for newly created V7 filesystems. Every
existing filesystem (V4-V7, including existing 64-bit V7/GCM-SIV volumes)
continues to use the legacy 64-bit path because the new config field defaults
to false when absent. Surface the setting in `encfsctl info`.

This compatibility guarantee is one-way: new 96-bit volumes require software
that implements this ADR. The 64-bit opt-out exists for interoperability with
older EncFS implementations and other tooling.

The current V7 protobuf has no serialized config-version or minimum-reader
field. `load_v7()` instead assigns `DEFAULT_CONFIG_VERSION` to the in-memory
`EncfsConfig`, so that value cannot currently be used to reject an unsupported
V7 wire format. This ADR adds an authenticated minimum-reader version gate for
V7 and uses the wide-IV feature as its first version increment.

### Config option and invariants

Add a new boolean config field, `wide_file_iv`, alongside the `unique_iv` field
it depends on:

- `EncfsConfig` has `#[serde(rename = "wideFileIV", default)] pub
  wide_file_iv: bool` next to `unique_iv`. This in-memory bool is a two-way
  view onto the `FileIvWidth` wire enum described under Config serialization;
  application code above the protobuf boundary never sees the enum.
- **New forward V7 filesystems** (`EncfsConfig::standard_v7()`):
  `wide_file_iv = true` by default.
- **Every existing config** (V4, V5, V6 XML, and pre-existing V7 protobuf
  configs without the field): `wide_file_iv = false`, and decrypts exactly as
  before, byte-for-byte. V4/V5 constructors and every direct `EncfsConfig`
  literal must set the value explicitly; serde/protobuf defaults cover formats
  that are actually deserialized.
- `validate()` (`src/config.rs:276`) rejects `wide_file_iv = true` unless both
  `unique_iv = true` and `block_mode() == BlockMode::AesGcmSiv`. Thus V4-V6,
  V7 legacy block mode, and headerless V7 filesystems can only use the 64-bit
  representation.
- `header_size()` (`src/config.rs:862-864`) returns 12 when `wide_file_iv` is
  set, 8 for a stored narrow IV, and 0 when `unique_iv` is false.
- `set_v7_key()` and `save()` validate the config before hashing, wrapping the
  key, or writing it. Invalid combinations must not be persisted.
- `wide_file_iv = true` requires the wide-IV minimum reader version described
  under Config serialization. A lower declared minimum is invalid.

The setting is immutable after filesystem creation. Changing it on an existing
volume would change every file's header boundary and every block's nonce/AAD,
as well as the config hash used to wrap the volume key. No in-place migration
is provided by this ADR, and mixed 8-byte/12-byte headers in one volume are not
supported. A future migration feature would need a transactional whole-volume
rewrite with explicit crash recovery.

### File-IV representation

Introduce a small `FileIv` value type in the crypto layer rather than passing
an unconstrained `u128` through public interfaces. It stores a value in the
range `0..2^96` and provides checked operations for the two formats:

- `FileIv::from_u64(value)` constructs a narrow or headerless IV.
- `FileIv::from_wide_be_bytes([u8; 12])` constructs a wide IV.
- `FileIv::try_from_u128(value)` rejects values at or above `2^96`.
- `to_wide_be_bytes()` returns exactly 12 bytes.
- `try_to_u64()` returns an error if any of the upper 32 bits are set.

An internal `u128` is a convenient implementation, but it is not itself the
wire format. There must be no unchecked `as u64` truncation. This keeps the
legacy boundary explicit and prevents accidental acceptance of values above
`2^96 - 1`.

### Header wire format

The decrypted header is the unsigned file-IV integer in big-endian order,
matching the existing 8-byte format:

- Narrow header plaintext: `file_iv.to_be_bytes()` as exactly 8 bytes.
- Wide header plaintext: `FileIv::to_wide_be_bytes()` as exactly 12 bytes,
  equivalent to bytes 4 through 15 of a checked `u128::to_be_bytes()` value.

Header encryption remains the existing EncFS stream transform using the
external/path IV. `encrypt_header` generates exactly 8 or 12 random bytes as
selected by the config, interprets them as above, and encrypts those same
bytes. `decrypt_header` requires exactly the configured header length,
decrypts it, and parses it using the same big-endian rule.

`encrypt_header_with_iv` rejects a `FileIv` that does not fit the configured
width. In particular, the narrow branch calls `try_to_u64()` rather than
truncating, and the wide branch rejects values outside the 96-bit invariant.

### AES-GCM-SIV nonce and AAD wire format

The narrow branch remains byte-identical to the current implementation:

```text
narrow_nonce = LE64(file_iv_u64 XOR (block_num >> 32))
               || LE32(block_num mod 2^32)                 # 12 bytes
narrow_aad   = LE64(file_iv_u64) || LE64(block_num)        # 16 bytes
```

The wide branch uses the checked 96-bit integer value held by `FileIv`:

```text
mixed        = file_iv_u128 XOR u128(block_num)
wide_nonce   = first 12 bytes of LE128(mixed)               # 12 bytes
wide_aad     = first 12 bytes of LE128(file_iv_u128)
               || LE64(block_num)                           # 20 bytes
```

"First 12 bytes" means indices `0..12` of Rust's `u128::to_le_bytes()` result.
The four unused high bytes of the `u128` are never included in the nonce or
AAD. Header encoding is deliberately big-endian for compatibility with the
existing header, while nonce/AAD integer fields are little-endian to match the
existing AES-GCM-SIV construction.

The AAD contains the complete 12-byte file IV and 8-byte block number
separately, so distinct `(file_iv, block_num)` pairs remain fully bound even
when the XOR-derived nonce happens to repeat.

### Cipher trait / SslCipher

`SslCipher` gets a `wide_file_iv: bool` field (default false), set once via a
new `set_wide_file_iv(&mut self, wide: bool)` method, following the existing
`set_name_encoding` pattern. `EncfsConfig::get_cipher()` wires it up before
boxing the cipher.

The `Cipher` trait and `SslCipher` implementation change as follows:

- `encrypt_header(&self, external_iv: u64) -> Result<(Vec<u8>, FileIv)>`
- `encrypt_header_with_iv(&self, file_iv: FileIv, external_iv: u64) ->
  Result<Vec<u8>>`
- `decrypt_header(&self, header: &mut [u8], external_iv: u64) ->
  Result<FileIv>`
- `encrypt_block_aes_gcm_siv_inplace` and
  `decrypt_block_aes_gcm_siv_inplace` take `FileIv`.
- `encrypt_block_inplace` and `legacy_decrypt_block_inplace` keep `u64`; their
  callers convert with checked `FileIv::try_to_u64()`.
- New: `fn set_wide_file_iv(&mut self, wide: bool);`

The narrow header, nonce, AAD, ciphertext, and tag must remain byte-identical
to the pre-change implementation.

### Block, file, filesystem, and utility layers

`FileIv` becomes the canonical file-IV type between header parsing and block
crypto:

- `src/crypto/block.rs`: `BlockCodec::decrypt_block`/`encrypt_block` and the
  AES-GCM-SIV helpers take `FileIv`; legacy helpers use checked conversion.
- `src/crypto/file.rs`: `FileDecoder`/`FileEncoder`, their constructors, and
  stored file-IV fields use `FileIv`.
- `src/fs.rs`: `FileHandle::file_iv()`, `FileMeta.header_iv`,
  `headerless_file_iv()`, truncate, rename/copy, create, open, read, and write
  paths use `FileIv`. `headerless_file_iv()` wraps its existing `u64` path IV
  with `FileIv::from_u64`.
- `src/reverse_fs.rs`: reverse mode remains semantically 64-bit and headerless.
  Its staged state may keep `u64`, but calls into `BlockCodec` must convert via
  `FileIv::from_u64`. Reverse mode does not exercise the wide header format.
- `src/encfsctl.rs`: `cat`, export, rename/copy helpers, info, and raw-info
  formatting must handle `FileIv` and the dynamic header size.

All direct `EncfsConfig` literals and direct cipher construction in tests must
set the new field or cipher setting explicitly.

### Config serialization and compatibility signaling

- `proto/encfs_config.proto` adds an enum, not a bool, so a future width can
  be introduced without adding another field to `AesGcmSivBlockCipher`:

  ```protobuf
  enum FileIvWidth {
    FILE_IV_WIDTH_64 = 0;
    FILE_IV_WIDTH_96 = 1;
  }

  message AesGcmSivBlockCipher {
    ...
    FileIvWidth file_iv_width = 4;
  }
  ```

  `FILE_IV_WIDTH_64` is deliberately the zero value: an absent/omitted field
  (every config written before this ADR) decodes as 64-bit, matching the
  narrow default described below. `file_iv_width` is added to
  `AesGcmSivBlockCipher` only, not to `BasicBlockCipher`. No 128-bit value is
  defined by this ADR; see the extensibility note below for what adding one
  later requires.
  - A proto3 enum field is varint-encoded the same as `bool` for the values
    0 and 1, so this is not a wire-format or config-hash change relative to
    a bool field: existing fixtures, golden vectors, and the frozen
    pre-change-schema test are unaffected.
  - `EncfsConfig.wide_file_iv: bool` converts to/from `FileIvWidth` only at
    the protobuf boundary (`encfs_config_to_proto_v7()` and `load_v7()`);
    both conversions use an exhaustive `match` on `FileIvWidth`, not `bool`
    equality, so adding `FILE_IV_WIDTH_128` later is a compile error at
    exactly those two sites until each is reconsidered.
  - **Extensibility and safety:** prost decodes an unrecognized enum value
    (e.g. a future `FILE_IV_WIDTH_128` read by a build that predates it) to
    the zero variant rather than failing, so an unaware reader would treat a
    128-bit volume as 64-bit and compute the wrong header size. This is the
    same fail-open risk any unknown protobuf enum value has, so it is not
    guarded by the enum itself: adding any new `FileIvWidth` value must bump
    `V7_CURRENT_CONFIG_VERSION`, require the matching minimum reader version
    in `validate()`, and add a loader test proving the preceding reader
    version rejects it — the same mechanism this ADR already requires for
    any reader-breaking V7 change (see the minimum-reader-field discussion
    below). An old reader must never reach the point of interpreting an
    unrecognized width; the version gate must reject it first.
- The top-level V7 `Config` message adds `uint32 minimum_reader_version = 8;`.
  It is top-level because it gates interpretation of the entire config, not
  just the block cipher.
- Define explicit V7 format constants independent of the legacy/V6 date-style
  `DEFAULT_CONFIG_VERSION`:

  ```text
  V7_BASE_CONFIG_VERSION         = 1
  V7_WIDE_FILE_IV_CONFIG_VERSION = 2
  V7_CURRENT_CONFIG_VERSION      = 2
  ```

- On the protobuf wire, `minimum_reader_version = 0` means
  `V7_BASE_CONFIG_VERSION`. This special default is required because all V7
  configs written before this field was introduced omit it. Base/narrow
  configs continue to encode zero/omit the field so their protobuf and config
  hash remain readable by pre-change tools.
- Wide configs encode `minimum_reader_version =
  V7_WIDE_FILE_IV_CONFIG_VERSION`. They may not encode zero or version 1.
- `EncfsConfig` retains the effective V7 minimum-reader value so validation,
  saving, and `encfsctl info` do not have to infer it again. Non-V7 configs set
  it to zero/unused. All direct config literals must initialize it.
- `encfs_config_to_proto_v7()` writes `file_iv_width` in the GCM-SIV branch,
  mapping `wide_file_iv` to `FileIvWidth::FileIvWidth96` or `FileIvWidth64`.
- `load_v7()` reads `file_iv_width` from the GCM-SIV branch and matches it
  back to `wide_file_iv: bool`, treating an unrecognized wire value the same
  as `FileIvWidth64` (see the extensibility note above — this is safe only
  because any reader-breaking new value must also raise the minimum reader
  version, which is checked earlier in `load_v7()` and rejects the config
  before this conversion runs). The `Legacy` branch, including the
  AES-GCM-SIV-via-sentinel backward-compatibility path, always yields
  `wide_file_iv = false`.
- `encfs_config_to_proto_v7()` also writes the top-level minimum-reader field,
  using protobuf zero for the effective base version as described above.
- Immediately after protobuf decoding, and before config-hash verification or
  interpretation of any feature fields, `load_v7()` converts wire value zero
  to the effective base version and compares it with
  `V7_CURRENT_CONFIG_VERSION`. A higher value fails with a dedicated error such
  as `V7 config requires reader version N; this build supports through M`.
- `validate()` rejects an effective minimum-reader version below the maximum
  required by enabled features. For this ADR, wide IVs require version 2 while
  all existing V7 features require version 1. It also rejects versions above
  the current implementation when constructing or saving a config.
- `format_v7_config_raw()` displays both the raw protobuf value and its
  effective value when raw zero maps to the base version.
- V6 XML has no equivalent field and the XML writer does not emit one.

The field is part of the authenticated V7 protobuf and therefore contributes
to `v7_config_hash_from_proto()`. A pre-change reader does not know the field,
will normally discard it while decoding, and will recompute a different config
hash. Such readers fail closed before decrypting or writing file data. Released
readers may report this as "config hash mismatch (tampered or corrupted)";
that misleading legacy error is accepted because it cannot be changed
retroactively. This forward incompatibility must be called out in release notes
and the user documentation. A frozen pre-change-schema compatibility test must
lock in the fail-closed behavior.

The minimum-reader field is itself included in `v7_config_hash_from_proto()`.
Starting with this ADR, every future V7 change that an older reader cannot
safely interpret must first increment `V7_CURRENT_CONFIG_VERSION`, set the
config's minimum reader version to that value, and add a loader test proving
that the preceding reader version rejects it before config-hash validation.
Fields that do not change required reader semantics need not raise the minimum.

Released pre-change readers cannot benefit from the new early version check;
they still fail closed via config-hash mismatch. Readers implementing this ADR
and later reject future unsupported versions with the dedicated version error.
Users who need pre-change tooling use `--legacy-file-iv`, which emits the
base-version/zero minimum-reader field as well as `wide_file_iv = false`.

### CLI

- `encfsctl new` adds `--legacy-file-iv`, alongside `--no-chained-iv` and
  `--no-unique-iv`. It sets `config.wide_file_iv = false` on an otherwise
  default V7 config.
- `--no-unique-iv` also unconditionally sets `wide_file_iv = false`, because a
  headerless/reverse-mode config cannot use the wide format. Combining it with
  `--legacy-file-iv` is allowed and redundant rather than an error.
- Both `--legacy-file-iv` and `--no-unique-iv` lower the effective V7 minimum
  reader version to `V7_BASE_CONFIG_VERSION`, which serializes as protobuf zero.
  Otherwise the compatibility flags would still produce a config that
  pre-change readers reject because of the new version field.
- `encfsctl info` reports the file-IV width when
  `block_mode() == BlockMode::AesGcmSiv`. It prints literal `96-bit` or
  `64-bit`. The 96-bit default is green and the supported but non-optimal
  64-bit setting is red, following the existing convention of highlighting
  settings that differ from current security defaults.
- For V7, `encfsctl info` also reports the effective minimum reader version and
  the maximum version supported by the running build.
- `encfsctl info --raw` prints `file_iv_width` in the GCM-SIV cipher section,
  as the symbolic enum name (e.g. `FILE_IV_WIDTH_96`). An unrecognized wire
  value prints as `FILE_IV_WIDTH_UNKNOWN(N)` rather than being silently
  folded into a known name, since this raw view is a diagnostic aid and
  should show what is actually on disk.
- Help text and user-visible labels are added in English, French, and German.

## Consequences

- New forward V7/AES-GCM-SIV filesystems get 96 random per-file bits, reducing
  cross-file nonce collisions and equality leakage compared with the 64-bit
  seed. AES-GCM-SIV still receives a 96-bit nonce in both formats.
- Every filesystem created before this change continues to decrypt unchanged,
  since an absent field means the narrow path.
- New wide volumes are intentionally not readable by pre-change tools. Those
  tools fail closed through the authenticated config hash; users needing
  interoperability must opt into 64-bit headers at creation time.
- V7 now has an explicit, authenticated minimum-reader version. Implementations
  of this ADR fail early with a version error for future required features,
  instead of misclassifying them as config corruption.
- There is no in-place width conversion and no mixed-width volume format.
- The `FileIv` refactor touches the cipher, block, file, forward filesystem,
  reverse filesystem boundaries, control utility, config literals, and many
  tests. Checked conversions make the legacy/wide boundary explicit.
- `architecture.md` and `docs/DESIGN.md` must describe the conditional
  0/8/12-byte header layout and distinguish the 64-bit file seed from the
  96-bit AES-GCM-SIV nonce. CLI and reverse-mode documentation must explain
  that headerless configurations remain 64-bit.

## Verification

### Exact wire compatibility

- Keep the existing narrow encrypted-header golden byte unchanged.
- Add a fixed narrow AES-GCM-SIV vector covering file IV, block number, nonce,
  AAD, plaintext, ciphertext, and tag. This, not the existing object-safety
  header test alone, is the regression guard for old V7/GCM-SIV files.
- Add a fixed wide vector covering the 12-byte plaintext header, encrypted
  header, parsed `FileIv`, block number, nonce, 20-byte AAD, plaintext,
  ciphertext, and tag.
- Test the maximum accepted 96-bit value, rejection of values above it, and
  rejection when a wide value reaches a narrow/legacy conversion.

### Config and compatibility

- `EncfsConfig::standard_v7()` has `wide_file_iv == true` and
  `header_size() == 12`.
- Loading a pre-field V7 fixture yields `wide_file_iv == false`,
  `header_size() == 8`, and byte-identical decryption.
- V4, V5, V6, V7 legacy-message, and GCM-SIV-via-sentinel loads always select
  the narrow path.
- V7 save/load round trips preserve both true and false values and config-hash
  validation succeeds.
- An absent/zero minimum-reader field loads as V7 base version 1. Narrow configs
  re-encode it as zero; wide configs encode version 2.
- A config whose minimum reader version is greater than
  `V7_CURRENT_CONFIG_VERSION` is rejected with the dedicated version error
  before config-hash comparison, key derivation, or feature interpretation.
- Validation rejects `wide_file_iv = true` with minimum reader version 0/1 and
  accepts it at version 2. Base/narrow configs remain valid at effective
  version 1.
- A frozen pre-change protobuf decoder/schema rejects a wide config through a
  config-hash mismatch rather than accepting it as an 8-byte-header volume.
- A frozen version-2 decoder/schema rejects a synthetic future version-3
  config through the version gate, even when that config contains unknown
  fields that the decoder drops.
- `validate()`, `set_v7_key()`, and `save()` reject wide IVs combined with
  `unique_iv = false` or a non-GCM-SIV block mode.

### Filesystem and CLI behavior

- Add forward `EncFs` file-codec and live-mount round trips for wide and narrow
  V7/GCM-SIV volumes.
- Exercise create/open/read/write, empty-file sizing, partial-block writes,
  truncate grow/shrink, rename with external IV chaining, and directory-copy
  paths with 12-byte headers.
- Exercise `encfsctl cat` and export on both widths.
- `encfsctl new` creates a 96-bit volume by default;
  `--legacy-file-iv` creates an 8-byte-header volume; and `--no-unique-iv`
  creates a valid headerless volume with `wide_file_iv == false`. The default
  encodes minimum reader version 2; both compatibility flags encode protobuf
  zero/effective version 1. Test the redundant combination of both flags.
- `encfsctl info` and `info --raw` show the correct values, including green for
  96-bit and red for 64-bit when color is enabled. Standard V7 info shows the
  effective minimum reader version and the build's supported maximum; raw info
  distinguishes protobuf zero from effective base version 1.
- Reverse-mode unit/live tests remain headerless and explicitly set
  `wide_file_iv = false`. They verify narrow V7/GCM-SIV round trips and that
  reverse-mode config creation still works; they do not claim to exercise the
  96-bit header path.

### Project-wide checks

- Update the English, French, and German locale entries.
- Update `architecture.md`, `docs/DESIGN.md`, README/reverse-mode guidance, and
  release notes for the new default and forward-compatibility boundary.
- Run `cargo fmt -- --check`, `cargo clippy --all-targets --all-features -- -D
  warnings`, and `cargo test`. Run the forward live-mount cases where FUSE is
  available.
