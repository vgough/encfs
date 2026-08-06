# Security

## Audit

[EncFS Security Audit](https://defuse.ca/audits/encfs.htm) — Taylor Hornby,
funded by Igor Sviridov, January–February 2014. Audited **EncFS 1.7.4** (the
original C++ implementation).

This repository is a from-scratch Rust rewrite (currently v2.0.0-beta.6) that
adds a new V7 on-disk format (AES-GCM-SIV + Argon2id) alongside read/write
support for the legacy V4-V6 formats the audit covers. Consequently most
"resolved" rows below mean the issue is *structurally superseded by the V7
design*, not patched line-by-line in the old construction. Legacy formats are
intentionally frozen (V4/V5 read-only; V6 read/write) for backward
compatibility, so their inherent weaknesses persist by design — see
`architecture.md`'s "Known Tech Debt" section.

## Checklist

| # | Audit finding | Status | Notes |
|---|---|---|---|
| 2.1 | Same key for encryption and authentication | **Resolved (V7)** | AES-GCM-SIV is a single-key AEAD, designed for exactly this combined use (`crypto/ssl.rs` `encrypt_block_aes_gcm_siv_inplace`). Legacy CBC+HMAC still reuses one key — inherent to the frozen V4-V6 format. |
| 2.2 | Stream cipher ("shuffle/flip") for the last file block | **Resolved (V7)** | `crypto/block.rs:274-292` routes partial *and* full blocks through the same AES-GCM-SIV AEAD path — no shuffle/flip. Legacy mode still does two-pass shuffle/flip stream encoding (`crypto/ssl.rs:262-501`, `legacy_stream_decode`) — inherent to the frozen wire format. |
| 2.3 | Per-block IV via block-number XOR | **Resolved for new V7 volumes** | AES-GCM-SIV is nonce-misuse-resistant, and new V7 filesystems default to a 96-bit file IV (`wide_file_iv`, ADR 0001; `aes_gcm_siv_nonce_wide`, `crypto/ssl.rs:923`). Caveat: headerless configs, `--legacy-file-iv`/`--no-unique-iv`, and **all reverse-mode volumes** still derive the narrow 64-bit IV (`aes_gcm_siv_nonce_narrow`, `crypto/ssl.rs:902`; used by `reverse_fs.rs:450,533`) — narrower but not catastrophic given SIV's misuse resistance. |
| 2.4 | Unauthenticated file holes (all-zero blocks bypass MAC) | **Still relevant** | `crypto/block.rs:148-157` treats any all-zero on-disk block as a sparse hole and returns zero plaintext *before* dispatching to AES-GCM-SIV — the authentication tag is never checked, even in V7's "always authenticated" mode. `allow_holes` defaults to `true` for new V7 filesystems (`config.rs:229`). An attacker with ciphertext write access can zero any block undetected. This is the audit's highest-exploitability finding and remains live. |
| 2.5 | Non-constant-time MAC comparison | **Resolved** | Legacy per-block MAC check now XOR-accumulates over all bytes with no early exit (`crypto/block.rs:206-217`, `fail |= expected ^ stored`). V7 tag verification is handled by the `aes-gcm-siv` crate's constant-time comparison. (Other integer MAC checks in `ssl.rs` use `!=` on fixed-width `u16`/`u32`/`u64` — a single-instruction compare, not the variable-length memcmp pattern the audit flagged.) |
| 2.6 | Insufficient (64-bit) MAC length | **Resolved (V7)** | V7 uses a 16-byte (128-bit) AES-GCM-SIV tag; config validation requires `block_mac_bytes == 16` for V7. Legacy format is capped at 8 bytes (`0..=8`) — inherent to the frozen V4-V6 format. |
| 2.7 | MAC enforcement is config-controlled (attacker with ciphertext access can disable it) | **Resolved (V7)** | Verified in code: `v7_config_hash_from_proto` (`config.rs:1238-1246`) SHA-256-hashes the *entire* protobuf config — including `allow_holes` and `block_mac_bytes` (`proto/encfs_config.proto:56,91`) — and that hash is the AAD for the AES-256-GCM volume-key wrap (`config.rs:1114`). Tampering with any config field fails decryption. Note `ignore_legacy_mac_mismatch` (`block.rs:213`) is a *runtime* opt-out of legacy MAC failure (the inverse of the audit's request) — moot for V7, where tag verification is unconditional. |
| 3.1 | Plaintext/MAC-order leakage (padding-oracle-style) | **Resolved** | Filename decoding verifies the MAC before trusting padding (`crypto/ssl.rs:632-633`, comment: "Fix Padding Oracle: Verify MAC before checking padding"). V7 data blocks use AEAD decrypt-in-place, which only yields plaintext after tag verification succeeds (`crypto/block.rs:235-239`) — nothing is exposed on failure. |
| 3.2 | Chosen-ciphertext attack from uniform key usage | **Not applicable (V7)** | AES-GCM-SIV is designed to be CCA-resistant under a single key, with nonce/AAD binding per file+block. Legacy CBC+HMAC retains the theoretical exposure — inherent to the frozen format. |
| 3.3 | Buffer overflow in name encoding (StreamNameIO/BlockNameIO) | **Resolved** | Structural: full Rust rewrite with zero `unsafe` blocks in `src/crypto/*.rs` or the name-encoding paths. Bounds-checked slices eliminate the out-of-bounds-write class of bug the audit found in the C++ implementation. |
| 3.4 | Inadequate (64-bit) IV size | **Resolved for new V7 volumes** | 96-bit per-file IV is now the default for newly created V7 filesystems (`wide_file_iv`, ADR 0001, `config.rs:230`). Caveat: headerless configs, `--no-unique-iv`, `--legacy-file-iv`, and all reverse-mode volumes (`reverse_fs.rs:450,533`) remain on the 64-bit path-derived/random IV for compatibility. |

## Bottom line

The only checklist item still genuinely open is **2.4 (unauthenticated file
holes)** — and it applies even to new V7/AES-GCM-SIV filesystems, since
`allow_holes` defaults on. Everything else is either resolved by the V7 AEAD
design, resolved structurally by the Rust rewrite, or an accepted, documented
trade-off confined to the frozen legacy V4-V6 formats.

Keeping file "holes" is a deliberate performance/sparse-file tradeoff, not an
oversight, but it does mean hole regions don't get the same integrity guarantee
as real data blocks. If holes were encrypted, then a simple "truncate" command
on an encrypted file could cause encfs to fill the disk with encrypted zeros.

