# OpenSSL Removal Migration Plan

## Goal

Remove the direct `openssl` crate dependency from this project while preserving EncFS compatibility guarantees and test coverage.

## Scope

Current direct OpenSSL usage appears in these areas:

- `src/crypto/ssl.rs`
  - Legacy cipher operations (AES/Blowfish CFB/CBC)
  - PBKDF2-HMAC-SHA1 and legacy BytesToKey derivation
  - HMAC-SHA1 based MAC/IV derivation
  - Random IV generation for file headers
- `src/crypto/aead.rs`
  - AES-256-GCM key wrapping for V7 config
- `src/config.rs`
  - Random salt and volume key generation in tests/helpers
- `src/encfsctl.rs`
  - Random salt generation and setup flows
- `src/lib.rs`
  - SHA1 hashing in tests
- `Cargo.toml`
  - `openssl = "0.10.81"`

## Constraints

- Compatibility with existing EncFS filesystems is non-negotiable.
- Legacy behavior in `src/crypto/ssl.rs` must remain bit-for-bit compatible.
- Public behavior of `encfs` and `encfsctl` should not change.
- Migration should be done in small, reviewable phases.

## Proposed Target Dependencies

- Randomness: `getrandom` (or `rand_core` + `getrandom`)
- SHA1: `sha1`
- HMAC: `hmac`
- PBKDF2: `pbkdf2`
- Legacy block/stream ciphers:
  - AES: `aes` + `cbc` + `cfb-mode`
  - Blowfish: `blowfish` + `cbc` + `cfb-mode`
- V7 AEAD: `aes-gcm` (or `ring` if preferred for AEAD only)

Note: choose one consistent crypto stack (prefer RustCrypto crates) to reduce long-term maintenance risk.

## Migration Phases

### Phase 0: Baseline and Guardrails

Status: complete.

1. Record baseline behavior:
   - `cargo test`
   - `cargo clippy --all-targets --all-features -- -D warnings`
2. Add compatibility vectors where missing:
   - Known ciphertext/plaintext vectors for filename, header, block crypto, and key unwrap.
3. Document invariants in tests:
   - Endianness details
   - MAC folding behavior (`mdLen - 1` XOR reduction)
   - Legacy IV derivation semantics

Exit criteria:

- Test suite is green before migration starts.
- At least one deterministic compatibility test exists per critical primitive.

### Phase 0 Progress Log (2026-06-13)

Completed:

- Baseline test run: `cargo test` passed.
- Baseline lint gate: `cargo clippy --all-targets --all-features -- -D warnings` passed.
- Added deterministic guardrail tests in `src/crypto/ssl.rs`:
   - `test_phase0_pbkdf2_sha1_known_vector`
   - `test_phase0_mac64_no_iv_known_vector`
   - `test_phase0_calculate_iv_uses_little_endian_seed`
   - `test_phase0_key_wrap_known_vector_and_unwrap`
   - `test_phase0_filename_header_block_known_vectors`

Recorded vectors/invariants now covered by tests:

- PBKDF2-HMAC-SHA1 stable output for fixed inputs.
- MAC folding behavior for `mac_64_no_iv_with_key`:
   - XOR-reduce digest bytes excluding the last byte.
   - Interpret folded 8 bytes as big-endian `u64`.
- IV derivation (`calculate_iv`, major >= 3):
   - HMAC input uses little-endian seed bytes.
   - Explicit guardrail against accidental big-endian regression.
- Key unwrap/wrap (`encrypt_key`/`decrypt_key`) deterministic compatibility vector.
- Filename encryption deterministic vector (`encrypt_filename` stream mode).
- Header encryption deterministic vector (`encrypt_header_with_iv`).
- Full and partial block encryption deterministic vectors (`encrypt_block_inplace`).

Result: Phase 0 exit criteria are satisfied.

### Phase 1: Remove OpenSSL from Non-Crypto-Critical Paths

1. Replace random byte generation calls:
   - `src/encfsctl.rs`
   - `src/config.rs`
   - `src/crypto/ssl.rs` header IV generation
   - `src/crypto/aead.rs` nonce generation
2. Replace test-only OpenSSL SHA1 in `src/lib.rs` with `sha1` crate.

Exit criteria:

- No OpenSSL imports remain outside `src/crypto/ssl.rs` and `src/crypto/aead.rs` (except temporary feature-gated code).
- All tests remain green.

### Phase 2: Migrate V7 AEAD (`src/crypto/aead.rs`)

Status: complete.

1. Replace OpenSSL AES-256-GCM calls with `aes-gcm` crate.
2. Preserve wire format exactly:
   - `nonce (12) || ciphertext || tag (16)`
3. Verify failure mode semantics for wrong key/AAD and tampered blob.

Exit criteria:

- V7 config tests pass unchanged.
- Round-trip and tamper tests remain green.

### Phase 2 Progress Log (2026-06-13)

Completed:

- Replaced OpenSSL AES-256-GCM calls in `src/crypto/aead.rs` with `aes-gcm` crate (`Aes256Gcm`).
- Preserved encoded key wire format exactly as:
   - nonce (12) || ciphertext || tag (16)
- Kept V7 decrypt failure semantics for wrong key/AAD/tampered data.
- Added deterministic structure/failure coverage in AEAD unit tests:
   - `blob_layout_and_tamper_failures`

Validation:

- `cargo test --lib crypto::aead::tests` passed.
- Full test suite passed via `task test`.

Result: Phase 2 exit criteria are satisfied.

### Phase 3: Migrate Hash/HMAC/KDF Primitives in Legacy Path

Status: complete.

1. Replace PBKDF2-HMAC-SHA1 with `pbkdf2` + `hmac` + `sha1`.
2. Replace HMAC-SHA1 usage in:
   - `mac_64_with_key`
   - `mac_64_no_iv_with_key`
   - `mac_32_with_key`
   - `calculate_iv` (major >= 3 path)
3. Reimplement legacy BytesToKey derivation using `sha1` crate while preserving round behavior.

Exit criteria:

- Existing fixtures and compatibility tests produce identical outputs to pre-migration.
- No behavior change in password derivation and key validation paths.

### Phase 3 Progress Log (2026-06-13)

Completed:

- Replaced PBKDF2-HMAC-SHA1 in `src/crypto/ssl.rs` with RustCrypto `pbkdf2` + `sha1`.
- Replaced HMAC-SHA1 usage in:
   - `mac_64_with_key`
   - `mac_64_no_iv_with_key`
   - `mac_32_with_key`
   - `calculate_iv` (major >= 3 path)
   using RustCrypto `hmac` + `sha1`.
- Reimplemented legacy BytesToKey derivation using `sha1` crate while preserving 16-round behavior.
- Added runtime dependencies in `Cargo.toml`:
   - `hmac = "0.12"`
   - `pbkdf2 = "0.12"`
   - moved `sha1 = "0.10"` from dev-dependencies to dependencies.

Validation:

- `cargo test --lib test_phase0_` passed.
- `cargo test --test config_compatibility test_legacy_kdf` passed.
- `cargo test --test passwd_upgrade_test` passed.
- Full suite passed via `task test`.

Result: Phase 3 exit criteria are satisfied.

### Phase 4: Migrate Legacy Cipher Operations (`src/crypto/ssl.rs`)

1. Replace OpenSSL `Crypter` CFB/CBC for:
   - AES-128/192/256 CFB + CBC
   - Blowfish CFB + CBC
2. Preserve exact behavior for:
   - No padding on block mode (`pad(false)` equivalent)
   - Stream mode two-pass encode/decode choreography
   - Legacy file block processing (full block CBC, partial block CFB)
3. Keep algorithm selection logic and interface names stable.

Exit criteria:

- Legacy fixtures decrypt identically.
- Integration tests for write/read compatibility pass.
- Live mount tests pass (when enabled).

### Phase 5: Remove OpenSSL Dependency and Cleanup

1. Remove OpenSSL imports from all source files.
2. Remove `openssl` from `Cargo.toml` and lockfile update.
3. Update docs (`README.md`, `INSTALL.md`) to remove OpenSSL runtime/build assumptions.
4. Run full quality gates:
   - `cargo fmt -- --check`
   - `cargo clippy --all-targets --all-features -- -D warnings`
   - `cargo test`
   - optional: live mount tests

Exit criteria:

- `cargo tree -i openssl` returns no results.
- CI passes without OpenSSL crate.

## Validation Matrix

For each phase, validate all of:

- Unit tests in affected modules
- Integration tests in `tests/`
- Compatibility fixtures:
  - V5/V6 legacy fixtures
  - V7 AEAD config flow
- Manual smoke:
  - `encfsctl info`
  - filename encode/decode
  - mount + read/write small and large files

## Risk Register

1. Behavior drift in legacy crypto internals.
   - Mitigation: deterministic vector tests and fixture-based assertions.
2. Blowfish mode mismatch across crate implementations.
   - Mitigation: cross-check against known fixtures before removing dual path.
3. AEAD format mismatch (`nonce|ct|tag`).
   - Mitigation: strict binary format tests.
4. Subtle endian regressions in MAC/IV derivation.
   - Mitigation: explicit test vectors for endian-sensitive paths.

## Rollout Strategy

- Land one phase per PR.
- Keep PRs small and independently testable.
- Prefer temporary compatibility assertions over broad refactors.
- If any compatibility regression appears, stop and fix before proceeding.

## Suggested PR Breakdown

1. PR 1: Baseline tests + random/test hashing migration
2. PR 2: V7 AEAD migration
3. PR 3: PBKDF2/HMAC/SHA1 + BytesToKey migration
4. PR 4: AES/Blowfish CFB/CBC migration
5. PR 5: Remove OpenSSL from manifest/docs + final cleanup

## Definition of Done

- OpenSSL crate removed from dependencies.
- All tests and compatibility checks pass.
- Existing EncFS volumes remain readable/writable where currently supported.
- Migration decisions and rationale are documented in this file.
