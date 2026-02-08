//! AEAD key wrap for V7 config: encrypt/decrypt volume key with AES-256-GCM,
//! using config hash as additional authenticated data (AAD).

use anyhow::{Context, Result};
use openssl::rand::rand_bytes;
use openssl::symm::{decrypt_aead, encrypt_aead, Cipher};

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
    let mut nonce = [0u8; GCM_NONCE_LEN];
    rand_bytes(&mut nonce).context("Failed to generate nonce")?;

    let cipher = Cipher::aes_256_gcm();
    let mut tag = [0u8; GCM_TAG_LEN];
    let ciphertext =
        encrypt_aead(cipher, key, Some(&nonce), aad, plaintext, &mut tag).context("AEAD encrypt")?;

    let mut out = Vec::with_capacity(GCM_NONCE_LEN + ciphertext.len() + GCM_TAG_LEN);
    out.extend_from_slice(&nonce);
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

    let cipher = Cipher::aes_256_gcm();
    decrypt_aead(cipher, key, Some(nonce), aad, ciphertext, tag).context(
        "AEAD decrypt failed (wrong password or tampered config)",
    )
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
}
