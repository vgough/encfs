//! AEAD key wrap for V7 config: encrypt/decrypt volume key with AES-256-GCM,
//! using config hash as additional authenticated data (AAD).

use anyhow::{Context, Result};
use aes_gcm::aead::{AeadInPlace, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce, Tag};

/// Nonce length for AES-GCM (96 bits recommended).
pub const GCM_NONCE_LEN: usize = 12;
/// Tag length for AES-GCM.
pub const GCM_TAG_LEN: usize = 16;
/// Key length for AES-256-GCM.
pub const AEAD_KEY_LEN: usize = 32;

/// Encrypts `plaintext` with AES-256-GCM using `key` (32 bytes) and `aad`.
/// Returns: nonce (12) || ciphertext || tag (16).
pub fn encrypt(key: &[u8], aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
    if key.len() != AEAD_KEY_LEN {
        anyhow::bail!("AEAD key must be {} bytes", AEAD_KEY_LEN);
    }

    let cipher = Aes256Gcm::new_from_slice(key).context("AEAD key init failed")?;
    let mut nonce = [0u8; GCM_NONCE_LEN];
    getrandom::fill(&mut nonce)
        .map_err(|e| anyhow::anyhow!("Failed to generate nonce: {}", e))?;
    let nonce = Nonce::from_slice(&nonce);

    let mut ciphertext = plaintext.to_vec();
    let tag = cipher
        .encrypt_in_place_detached(nonce, aad, &mut ciphertext)
        .map_err(|e| anyhow::anyhow!("AEAD encrypt: {}", e))?;

    let mut out = Vec::with_capacity(GCM_NONCE_LEN + ciphertext.len() + GCM_TAG_LEN);
    out.extend_from_slice(nonce);
    out.extend_from_slice(&ciphertext);
    out.extend_from_slice(&tag);
    Ok(out)
}

/// Decrypts `encrypted` (nonce (12) || ciphertext || tag (16)) with AES-256-GCM.
/// Returns plaintext, or errors if the tag does not verify (wrong key or tampered data).
pub fn decrypt(key: &[u8], aad: &[u8], encrypted: &[u8]) -> Result<Vec<u8>> {
    if key.len() != AEAD_KEY_LEN {
        anyhow::bail!("AEAD key must be {} bytes", AEAD_KEY_LEN);
    }
    if encrypted.len() < GCM_NONCE_LEN + GCM_TAG_LEN {
        anyhow::bail!(
            "AEAD blob too short (need at least {} bytes)",
            GCM_NONCE_LEN + GCM_TAG_LEN
        );
    }

    let (nonce, rest) = encrypted.split_at(GCM_NONCE_LEN);
    let (ciphertext, tag) = rest.split_at(rest.len() - GCM_TAG_LEN);

    let cipher = Aes256Gcm::new_from_slice(key).context("AEAD key init failed")?;
    let nonce = Nonce::from_slice(nonce);
    let tag = Tag::from_slice(tag);

    let mut plaintext = ciphertext.to_vec();
    cipher
        .decrypt_in_place_detached(nonce, aad, &mut plaintext, tag)
        .map_err(|e| anyhow::anyhow!(
            "AEAD decrypt failed (wrong password or tampered config): {}",
            e
        ))?;

    Ok(plaintext)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        let key = [0u8; AEAD_KEY_LEN];
        let aad = b"config hash placeholder";
        let plaintext = b"volume key blob";
        let encrypted = encrypt(key.as_slice(), aad, plaintext).unwrap();
        assert!(encrypted.len() > plaintext.len());
        let decrypted = decrypt(key.as_slice(), aad, &encrypted).unwrap();
        assert_eq!(decrypted.as_slice(), plaintext);
    }

    #[test]
    fn wrong_key_fails() {
        let key = [0u8; AEAD_KEY_LEN];
        let mut wrong_key = [0u8; AEAD_KEY_LEN];
        wrong_key[0] = 1;
        let aad = b"aad";
        let plaintext = b"secret";
        let encrypted = encrypt(key.as_slice(), aad, plaintext).unwrap();
        assert!(decrypt(wrong_key.as_slice(), aad, &encrypted).is_err());
    }

    #[test]
    fn wrong_aad_fails() {
        let key = [0u8; AEAD_KEY_LEN];
        let aad = b"aad1";
        let plaintext = b"secret";
        let encrypted = encrypt(key.as_slice(), aad, plaintext).unwrap();
        assert!(decrypt(key.as_slice(), b"aad2", &encrypted).is_err());
    }

    #[test]
    fn blob_layout_and_tamper_failures() {
        let key = [7u8; AEAD_KEY_LEN];
        let aad = b"layout-check";
        let plaintext = b"volume key blob";
        let encrypted = encrypt(key.as_slice(), aad, plaintext).unwrap();

        // Wire format: nonce (12) || ciphertext (len == plaintext) || tag (16).
        assert_eq!(encrypted.len(), GCM_NONCE_LEN + plaintext.len() + GCM_TAG_LEN);

        let mut tampered_ct = encrypted.clone();
        tampered_ct[GCM_NONCE_LEN] ^= 0x01;
        assert!(decrypt(key.as_slice(), aad, &tampered_ct).is_err());

        let mut tampered_tag = encrypted.clone();
        let tag_start = tampered_tag.len() - GCM_TAG_LEN;
        tampered_tag[tag_start] ^= 0x80;
        assert!(decrypt(key.as_slice(), aad, &tampered_tag).is_err());

        let mut tampered_nonce = encrypted;
        tampered_nonce[0] ^= 0x40;
        assert!(decrypt(key.as_slice(), aad, &tampered_nonce).is_err());
    }
}
