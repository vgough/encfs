//! The `Cipher` abstraction over EncFS volume cryptography.
//!
//! Historically `SslCipher` was the single concrete cipher type, referenced
//! directly by the block codec, file codec, and filesystem layers. `Cipher`
//! turns that surface into an object-safe trait so a new cipher becomes a new
//! implementation rather than another arm in `SslCipher`'s internal `match`.
//!
//! Construction (`new`) and key derivation (`derive_key*`) intentionally stay
//! OFF the trait — they have no `&self` receiver and would break object safety.
//! Build a boxed cipher through [`build`].

use crate::config::Interface;
use crate::crypto::ssl::SslCipher;
use anyhow::Result;

/// Object-safe facade over a volume cipher: file-content block crypto, header
/// IV handling, filename encoding, xattr crypto, and volume-key wrapping.
///
/// Every method takes `&self`/`&mut self` and concrete arguments and returns a
/// `Result`, so `dyn Cipher` is object-safe and can be held as `Box<dyn Cipher>`
/// / `&dyn Cipher` by the codec and filesystem layers.
pub trait Cipher: Send + Sync {
    /// Length in bytes of the cipher IV.
    fn iv_len(&self) -> usize;

    /// Install the volume key and IV (derived/unwrapped by the config layer).
    fn set_key(&mut self, key: &[u8], iv: &[u8]);

    /// Select the filename encoding (block vs stream) from the name interface.
    fn set_name_encoding(&mut self, iface: &Interface);

    // --- file-content block crypto (used by BlockCodec) ---

    /// MAC-64 without a chained IV — the legacy per-block integrity tag.
    fn mac_64_no_iv(&self, data: &[u8]) -> Result<u64>;

    /// Encrypt one file block in place (full block → CBC, partial → CFB).
    fn encrypt_block_inplace(
        &self,
        data: &mut [u8],
        block_num: u64,
        file_iv: u64,
        block_size: u64,
    ) -> Result<()>;

    /// Decrypt one legacy (CBC/CFB) file block in place.
    fn legacy_decrypt_block_inplace(
        &self,
        data: &mut [u8],
        block_num: u64,
        file_iv: u64,
        block_size: u64,
    ) -> Result<()>;

    /// Encrypt one block with AES-GCM-SIV (V7), returning the detached tag.
    fn encrypt_block_aes_gcm_siv_inplace(
        &self,
        data: &mut [u8],
        block_num: u64,
        file_iv: u64,
    ) -> Result<[u8; 16]>;

    /// Decrypt and verify one AES-GCM-SIV (V7) block in place.
    fn decrypt_block_aes_gcm_siv_inplace(
        &self,
        data: &mut [u8],
        tag: &[u8],
        block_num: u64,
        file_iv: u64,
    ) -> Result<()>;

    // --- file header IV (used by the file codec) ---

    /// Generate a fresh per-file IV header, returning `(header, file_iv)`.
    fn encrypt_header(&self, external_iv: u64) -> Result<(Vec<u8>, u64)>;

    /// Encrypt a specific per-file IV into its on-disk header.
    fn encrypt_header_with_iv(&self, file_iv: u64, external_iv: u64) -> Result<Vec<u8>>;

    /// Decrypt a per-file IV header, returning the file IV.
    fn decrypt_header(&self, header: &mut [u8], external_iv: u64) -> Result<u64>;

    // --- filename crypto (used by the filesystem layers) ---

    /// Encrypt a filename, returning `(encoded_name, next_iv)`.
    fn encrypt_filename(&self, plaintext_name: &[u8], iv: u64) -> Result<(String, u64)>;

    /// Decrypt an encoded filename, returning `(plaintext, next_iv)`.
    fn decrypt_filename(&self, encoded_name: &str, iv: u64) -> Result<(Vec<u8>, u64)>;

    /// Maximum plaintext name length that fits within `max_encoded_len`.
    fn max_plaintext_name_len(&self, max_encoded_len: u32) -> u32;

    // --- xattr crypto (used by the filesystem layers) ---

    fn encrypt_xattr_name(&self, name: &[u8], path_iv: u64) -> Result<Vec<u8>>;
    fn decrypt_xattr_name(&self, encrypted_name: &[u8], path_iv: u64) -> Result<Vec<u8>>;
    fn encrypt_xattr_value(&self, value: &[u8], path_iv: u64) -> Result<Vec<u8>>;
    fn decrypt_xattr_value(&self, encrypted_value: &[u8], path_iv: u64) -> Result<Vec<u8>>;

    // --- volume-key wrapping (used by config + encfsctl) ---

    fn encrypt_key(&self, volume_key: &[u8], user_key: &[u8], user_iv: &[u8]) -> Result<Vec<u8>>;
    fn decrypt_key(&self, encrypted_key: &[u8], user_key: &[u8], user_iv: &[u8]) -> Result<Vec<u8>>;
    fn decrypt_key_legacy(
        &self,
        encrypted_key: &[u8],
        user_key: &[u8],
        user_iv: &[u8],
    ) -> Result<Vec<u8>>;
}

/// Construct a boxed cipher for the given cipher interface and key size.
///
/// This owns the cipher-selection decision (`match (iface.name, key_size)`)
/// that used to live only inside `SslCipher::new`.
pub fn build(iface: &Interface, key_size: i32) -> Result<Box<dyn Cipher>> {
    Ok(Box::new(SslCipher::new(iface, key_size)?))
}

/// `SslCipher` is currently the only `Cipher` implementation. Each method
/// forwards to the existing inherent method of the same name; inherent methods
/// take resolution priority over trait methods on a concrete receiver, so the
/// forwarding does not recurse.
impl Cipher for SslCipher {
    fn iv_len(&self) -> usize {
        self.iv_len
    }

    fn set_key(&mut self, key: &[u8], iv: &[u8]) {
        SslCipher::set_key(self, key, iv)
    }

    fn set_name_encoding(&mut self, iface: &Interface) {
        SslCipher::set_name_encoding(self, iface)
    }

    fn mac_64_no_iv(&self, data: &[u8]) -> Result<u64> {
        SslCipher::mac_64_no_iv(self, data)
    }

    fn encrypt_block_inplace(
        &self,
        data: &mut [u8],
        block_num: u64,
        file_iv: u64,
        block_size: u64,
    ) -> Result<()> {
        SslCipher::encrypt_block_inplace(self, data, block_num, file_iv, block_size)
    }

    fn legacy_decrypt_block_inplace(
        &self,
        data: &mut [u8],
        block_num: u64,
        file_iv: u64,
        block_size: u64,
    ) -> Result<()> {
        SslCipher::legacy_decrypt_block_inplace(self, data, block_num, file_iv, block_size)
    }

    fn encrypt_block_aes_gcm_siv_inplace(
        &self,
        data: &mut [u8],
        block_num: u64,
        file_iv: u64,
    ) -> Result<[u8; 16]> {
        SslCipher::encrypt_block_aes_gcm_siv_inplace(self, data, block_num, file_iv)
    }

    fn decrypt_block_aes_gcm_siv_inplace(
        &self,
        data: &mut [u8],
        tag: &[u8],
        block_num: u64,
        file_iv: u64,
    ) -> Result<()> {
        SslCipher::decrypt_block_aes_gcm_siv_inplace(self, data, tag, block_num, file_iv)
    }

    fn encrypt_header(&self, external_iv: u64) -> Result<(Vec<u8>, u64)> {
        SslCipher::encrypt_header(self, external_iv)
    }

    fn encrypt_header_with_iv(&self, file_iv: u64, external_iv: u64) -> Result<Vec<u8>> {
        SslCipher::encrypt_header_with_iv(self, file_iv, external_iv)
    }

    fn decrypt_header(&self, header: &mut [u8], external_iv: u64) -> Result<u64> {
        SslCipher::decrypt_header(self, header, external_iv)
    }

    fn encrypt_filename(&self, plaintext_name: &[u8], iv: u64) -> Result<(String, u64)> {
        SslCipher::encrypt_filename(self, plaintext_name, iv)
    }

    fn decrypt_filename(&self, encoded_name: &str, iv: u64) -> Result<(Vec<u8>, u64)> {
        SslCipher::decrypt_filename(self, encoded_name, iv)
    }

    fn max_plaintext_name_len(&self, max_encoded_len: u32) -> u32 {
        SslCipher::max_plaintext_name_len(self, max_encoded_len)
    }

    fn encrypt_xattr_name(&self, name: &[u8], path_iv: u64) -> Result<Vec<u8>> {
        SslCipher::encrypt_xattr_name(self, name, path_iv)
    }

    fn decrypt_xattr_name(&self, encrypted_name: &[u8], path_iv: u64) -> Result<Vec<u8>> {
        SslCipher::decrypt_xattr_name(self, encrypted_name, path_iv)
    }

    fn encrypt_xattr_value(&self, value: &[u8], path_iv: u64) -> Result<Vec<u8>> {
        SslCipher::encrypt_xattr_value(self, value, path_iv)
    }

    fn decrypt_xattr_value(&self, encrypted_value: &[u8], path_iv: u64) -> Result<Vec<u8>> {
        SslCipher::decrypt_xattr_value(self, encrypted_value, path_iv)
    }

    fn encrypt_key(&self, volume_key: &[u8], user_key: &[u8], user_iv: &[u8]) -> Result<Vec<u8>> {
        SslCipher::encrypt_key(self, volume_key, user_key, user_iv)
    }

    fn decrypt_key(&self, encrypted_key: &[u8], user_key: &[u8], user_iv: &[u8]) -> Result<Vec<u8>> {
        SslCipher::decrypt_key(self, encrypted_key, user_key, user_iv)
    }

    fn decrypt_key_legacy(
        &self,
        encrypted_key: &[u8],
        user_key: &[u8],
        user_iv: &[u8],
    ) -> Result<Vec<u8>> {
        SslCipher::decrypt_key_legacy(self, encrypted_key, user_key, user_iv)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Compile-time + runtime proof that `Cipher` is object-safe and the
    /// factory yields a working `Box<dyn Cipher>`.
    #[test]
    fn build_yields_object_safe_cipher() {
        let iface = Interface {
            name: "ssl/aes".to_string(),
            major: 3,
            minor: 0,
            age: 0,
        };
        let mut cipher: Box<dyn Cipher> = build(&iface, 256).expect("build cipher");
        let key = [0x44u8; 32];
        let iv = [0x55u8; 16];
        cipher.set_key(&key, &iv);

        // Exercise one path through the trait object to confirm dispatch works.
        let header = cipher
            .encrypt_header_with_iv(0x0f1e2d3c4b5a6978, 0x8877665544332211)
            .expect("header via dyn Cipher");
        assert_eq!(header, [0x68, 0xd9, 0xed, 0x17, 0x09, 0x3d, 0x81, 0xc1]);
        assert_eq!(cipher.iv_len(), 16);
    }
}
