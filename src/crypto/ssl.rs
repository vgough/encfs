use crate::config::Interface;
use aes::{Aes128, Aes192, Aes256};
use aes_gcm_siv::aead::{AeadInPlace, KeyInit as AeadKeyInit};
use aes_gcm_siv::{Aes128GcmSiv, Aes256GcmSiv, Nonce, Tag};
use anyhow::{Result, anyhow};
use argon2::{Algorithm, Argon2, Params, Version};
use blowfish::Blowfish;
use cbc::cipher::block_padding::NoPadding;
use cbc::cipher::{BlockDecryptMut, BlockEncryptMut, KeyIvInit as BlockKeyIvInit};
use cfb_mode::cipher::AsyncStreamCipher;
use hmac::digest::KeyInit as HmacKeyInit;
use hmac::{Hmac, Mac};
use pbkdf2::pbkdf2_hmac;
use rust_i18n::t;
use sha1::{Digest, Sha1};
use zeroize::Zeroize;

type HmacSha1 = Hmac<Sha1>;

#[derive(Debug, Clone, Copy, PartialEq)]
enum LegacyCipherKind {
    Aes128,
    Aes192,
    Aes256,
    Blowfish,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum NameEncoding {
    Stream,
    Block,
}

/// Main cryptographic wrapper for EncFS.
/// Handles key derivation, file content encryption (stream/block), and filename encryption.
pub struct SslCipher {
    pub iv_len: usize,
    cipher_kind: LegacyCipherKind,
    key: Vec<u8>,
    iv: Vec<u8>,
    name_encoding: NameEncoding,
    iface: Interface,
}

impl Drop for SslCipher {
    fn drop(&mut self) {
        self.key.zeroize();
        self.iv.zeroize();
    }
}

impl SslCipher {
    fn hmac_sha1(key: &[u8]) -> Result<HmacSha1> {
        HmacSha1::new_from_slice(key).map_err(|e| anyhow!("Failed to initialize HMAC-SHA1: {}", e))
    }

    pub fn new(iface: &Interface, key_size: i32) -> Result<Self> {
        let cipher_kind = match (iface.name.as_str(), key_size) {
            ("ssl/aes", 128) => LegacyCipherKind::Aes128,
            ("ssl/aes", 192) => LegacyCipherKind::Aes192,
            ("ssl/aes", 256) => LegacyCipherKind::Aes256,
            ("ssl/blowfish", _) => LegacyCipherKind::Blowfish,
            _ => {
                return Err(anyhow!(
                    "{}",
                    t!(
                        "lib.error_unsupported_cipher",
                        name = iface.name,
                        key_size = key_size
                    )
                ));
            }
        };

        let iv_len = match cipher_kind {
            LegacyCipherKind::Blowfish => 8,
            _ => 16,
        };

        Ok(Self {
            iv_len,
            cipher_kind,
            key: vec![],
            iv: vec![],
            name_encoding: NameEncoding::Stream, // Default
            iface: iface.clone(),
        })
    }

    pub fn set_name_encoding(&mut self, iface: &Interface) {
        if iface.name == "nameio/block" {
            self.name_encoding = NameEncoding::Block;
        } else {
            self.name_encoding = NameEncoding::Stream;
        }
    }

    fn block_size(&self) -> usize {
        match self.cipher_kind {
            LegacyCipherKind::Blowfish => 8,
            _ => 16,
        }
    }

    fn stream_encrypt_inplace(&self, data: &mut [u8], key: &[u8], iv: &[u8]) -> Result<()> {
        match self.cipher_kind {
            LegacyCipherKind::Aes128 => {
                let cipher = cfb_mode::Encryptor::<Aes128>::new_from_slices(key, iv)
                    .map_err(|e| anyhow!("AES-128-CFB init failed: {}", e))?;
                cipher.encrypt(data);
            }
            LegacyCipherKind::Aes192 => {
                let cipher = cfb_mode::Encryptor::<Aes192>::new_from_slices(key, iv)
                    .map_err(|e| anyhow!("AES-192-CFB init failed: {}", e))?;
                cipher.encrypt(data);
            }
            LegacyCipherKind::Aes256 => {
                let cipher = cfb_mode::Encryptor::<Aes256>::new_from_slices(key, iv)
                    .map_err(|e| anyhow!("AES-256-CFB init failed: {}", e))?;
                cipher.encrypt(data);
            }
            LegacyCipherKind::Blowfish => {
                let cipher = cfb_mode::Encryptor::<Blowfish>::new_from_slices(key, iv)
                    .map_err(|e| anyhow!("Blowfish-CFB init failed: {}", e))?;
                cipher.encrypt(data);
            }
        }

        Ok(())
    }

    fn stream_decrypt_inplace(&self, data: &mut [u8], key: &[u8], iv: &[u8]) -> Result<()> {
        match self.cipher_kind {
            LegacyCipherKind::Aes128 => {
                let cipher = cfb_mode::Decryptor::<Aes128>::new_from_slices(key, iv)
                    .map_err(|e| anyhow!("AES-128-CFB init failed: {}", e))?;
                cipher.decrypt(data);
            }
            LegacyCipherKind::Aes192 => {
                let cipher = cfb_mode::Decryptor::<Aes192>::new_from_slices(key, iv)
                    .map_err(|e| anyhow!("AES-192-CFB init failed: {}", e))?;
                cipher.decrypt(data);
            }
            LegacyCipherKind::Aes256 => {
                let cipher = cfb_mode::Decryptor::<Aes256>::new_from_slices(key, iv)
                    .map_err(|e| anyhow!("AES-256-CFB init failed: {}", e))?;
                cipher.decrypt(data);
            }
            LegacyCipherKind::Blowfish => {
                let cipher = cfb_mode::Decryptor::<Blowfish>::new_from_slices(key, iv)
                    .map_err(|e| anyhow!("Blowfish-CFB init failed: {}", e))?;
                cipher.decrypt(data);
            }
        }

        Ok(())
    }

    fn block_encrypt_inplace(&self, data: &mut [u8], key: &[u8], iv: &[u8]) -> Result<()> {
        let mut out = vec![0u8; data.len()];

        match self.cipher_kind {
            LegacyCipherKind::Aes128 => {
                let cipher = cbc::Encryptor::<Aes128>::new_from_slices(key, iv)
                    .map_err(|e| anyhow!("AES-128-CBC init failed: {}", e))?;
                cipher
                    .encrypt_padded_b2b_mut::<NoPadding>(data, &mut out)
                    .map_err(|e| anyhow!("AES-128-CBC encrypt failed: {}", e))?;
            }
            LegacyCipherKind::Aes192 => {
                let cipher = cbc::Encryptor::<Aes192>::new_from_slices(key, iv)
                    .map_err(|e| anyhow!("AES-192-CBC init failed: {}", e))?;
                cipher
                    .encrypt_padded_b2b_mut::<NoPadding>(data, &mut out)
                    .map_err(|e| anyhow!("AES-192-CBC encrypt failed: {}", e))?;
            }
            LegacyCipherKind::Aes256 => {
                let cipher = cbc::Encryptor::<Aes256>::new_from_slices(key, iv)
                    .map_err(|e| anyhow!("AES-256-CBC init failed: {}", e))?;
                cipher
                    .encrypt_padded_b2b_mut::<NoPadding>(data, &mut out)
                    .map_err(|e| anyhow!("AES-256-CBC encrypt failed: {}", e))?;
            }
            LegacyCipherKind::Blowfish => {
                let cipher = cbc::Encryptor::<Blowfish>::new_from_slices(key, iv)
                    .map_err(|e| anyhow!("Blowfish-CBC init failed: {}", e))?;
                cipher
                    .encrypt_padded_b2b_mut::<NoPadding>(data, &mut out)
                    .map_err(|e| anyhow!("Blowfish-CBC encrypt failed: {}", e))?;
            }
        }

        data.copy_from_slice(&out);
        Ok(())
    }

    fn block_decrypt_inplace(&self, data: &mut [u8], key: &[u8], iv: &[u8]) -> Result<()> {
        let mut out = vec![0u8; data.len()];

        match self.cipher_kind {
            LegacyCipherKind::Aes128 => {
                let cipher = cbc::Decryptor::<Aes128>::new_from_slices(key, iv)
                    .map_err(|e| anyhow!("AES-128-CBC init failed: {}", e))?;
                cipher
                    .decrypt_padded_b2b_mut::<NoPadding>(data, &mut out)
                    .map_err(|e| anyhow!("AES-128-CBC decrypt failed: {}", e))?;
            }
            LegacyCipherKind::Aes192 => {
                let cipher = cbc::Decryptor::<Aes192>::new_from_slices(key, iv)
                    .map_err(|e| anyhow!("AES-192-CBC init failed: {}", e))?;
                cipher
                    .decrypt_padded_b2b_mut::<NoPadding>(data, &mut out)
                    .map_err(|e| anyhow!("AES-192-CBC decrypt failed: {}", e))?;
            }
            LegacyCipherKind::Aes256 => {
                let cipher = cbc::Decryptor::<Aes256>::new_from_slices(key, iv)
                    .map_err(|e| anyhow!("AES-256-CBC init failed: {}", e))?;
                cipher
                    .decrypt_padded_b2b_mut::<NoPadding>(data, &mut out)
                    .map_err(|e| anyhow!("AES-256-CBC decrypt failed: {}", e))?;
            }
            LegacyCipherKind::Blowfish => {
                let cipher = cbc::Decryptor::<Blowfish>::new_from_slices(key, iv)
                    .map_err(|e| anyhow!("Blowfish-CBC init failed: {}", e))?;
                cipher
                    .decrypt_padded_b2b_mut::<NoPadding>(data, &mut out)
                    .map_err(|e| anyhow!("Blowfish-CBC decrypt failed: {}", e))?;
            }
        }

        data.copy_from_slice(&out);
        Ok(())
    }

    /// Derives the User Key from the password using PBKDF2-HMAC-SHA1.
    pub fn derive_key(
        password: &str,
        salt: &[u8],
        iterations: i32,
        key_len: usize,
    ) -> Result<Vec<u8>> {
        if iterations <= 0 {
            return Err(anyhow!("PBKDF2 iterations must be positive"));
        }

        let mut key = vec![0u8; key_len];
        pbkdf2_hmac::<Sha1>(password.as_bytes(), salt, iterations as u32, &mut key);
        Ok(key)
    }

    /// Legacy key derivation for EncFS cipher interface version 2.
    /// Uses BytesToKey algorithm with SHA1 and 16 rounds.
    pub fn derive_key_legacy(password: &str, key_len: usize, iv_len: usize) -> Result<Vec<u8>> {
        // BytesToKey with SHA1, 16 rounds, no salt (matching SSL_Cipher.cpp line 452-454)
        let total_len = key_len + iv_len;
        let mut out = Vec::with_capacity(total_len);
        let mut digest = [0u8; 20];
        let mut has_prev_digest = false;
        let pass_bytes = password.as_bytes();

        while out.len() < total_len {
            let mut hasher = Sha1::new();
            if has_prev_digest {
                hasher.update(digest);
            }
            hasher.update(pass_bytes);
            digest.copy_from_slice(&hasher.finalize());

            // 16 total rounds of hashing.
            for _ in 1..16 {
                let round_digest = Sha1::digest(digest);
                digest.copy_from_slice(&round_digest);
            }
            has_prev_digest = true;

            let to_copy = std::cmp::min(digest.len(), total_len - out.len());
            out.extend_from_slice(&digest[..to_copy]);
        }

        Ok(out)
    }

    /// Derives the User Key from the password using Argon2id.
    pub fn derive_key_argon2id(
        password: &str,
        salt: &[u8],
        memory_cost: u32,
        time_cost: u32,
        parallelism: u32,
        key_len: usize,
    ) -> Result<Vec<u8>> {
        let params = Params::new(memory_cost, time_cost, parallelism, Some(key_len))
            .map_err(|e| anyhow!("Failed to create Argon2 parameters: {}", e))?;

        let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

        let mut key = vec![0u8; key_len];
        argon2
            .hash_password_into(password.as_bytes(), salt, &mut key)
            .map_err(|e| anyhow!("Argon2 key derivation failed: {}", e))?;

        Ok(key)
    }

    fn flip_bytes(buf: &mut [u8]) {
        let mut bytes_left = buf.len();
        let mut offset = 0;
        let mut rev_buf = [0u8; 64];

        while bytes_left != 0 {
            let to_flip = std::cmp::min(rev_buf.len(), bytes_left);
            for i in 0..to_flip {
                rev_buf[i] = buf[offset + to_flip - (i + 1)];
            }
            buf[offset..offset + to_flip].copy_from_slice(&rev_buf[..to_flip]);
            bytes_left -= to_flip;
            offset += to_flip;
        }
    }

    fn unshuffle_bytes(buf: &mut [u8]) {
        for i in (1..buf.len()).rev() {
            buf[i] ^= buf[i - 1];
        }
    }

    /// Decrypts the Volume Key using the User Key.
    ///
    /// The Volume Key is stored encrypted in the config file.
    /// Format: [checksum(4 bytes)] [encrypted_key(N bytes)]
    /// Verification uses MAC_32 (part of HMAC-SHA1).
    pub fn decrypt_key(
        &self,
        encrypted_key: &[u8],
        user_key: &[u8],
        user_iv: &[u8],
    ) -> Result<Vec<u8>> {
        // 1. Checksum (first 4 bytes)
        if encrypted_key.len() < 4 {
            return Err(anyhow!("Encrypted key too short"));
        }
        let checksum_bytes = &encrypted_key[..4];
        let checksum = u32::from_be_bytes(checksum_bytes.try_into()?);

        let mut data = encrypted_key[4..].to_vec();

        // 2. Decrypt
        self.legacy_stream_decode(&mut data, checksum as u64, user_key, user_iv)?;

        // 3. Verify Checksum (MAC_32)
        let calculated_mac = Self::mac_32_with_key(&data, 0, user_key)?;

        if calculated_mac != checksum {
            return Err(anyhow!(
                "Volume key checksum mismatch: expected {:08x}, got {:08x}",
                checksum,
                calculated_mac
            ));
        }

        Ok(data)
    }

    pub fn decrypt_key_legacy(
        &self,
        encrypted_key: &[u8],
        user_key: &[u8],
        user_iv: &[u8],
    ) -> Result<Vec<u8>> {
        // Same as decrypt_key but uses legacy MAC calculation
        // 1. Checksum (first 4 bytes, Big Endian)
        if encrypted_key.len() < 4 {
            return Err(anyhow!("Encrypted key too short"));
        }
        let checksum_bytes = &encrypted_key[..4];
        let checksum = u32::from_be_bytes(checksum_bytes.try_into()?);

        let mut data = encrypted_key[4..].to_vec();

        // 2. Decrypt using stream_decode (with shuffle/flip)
        self.legacy_stream_decode(&mut data, checksum as u64, user_key, user_iv)?;

        // 3. Verify Checksum (MAC_32) - legacy uses the user_key for HMAC
        let calculated_mac = Self::mac_32_with_key(&data, 0, user_key)?;

        if calculated_mac != checksum {
            return Err(anyhow!(
                "Volume key checksum mismatch (legacy): expected {:08x}, got {:08x}",
                checksum,
                calculated_mac
            ));
        }

        Ok(data)
    }

    /// Encrypts the Volume Key using the User Key.
    ///
    /// The Volume Key is encrypted and stored in the config file.
    /// Format: [checksum(4 bytes)] [encrypted_key(N bytes)]
    /// Uses MAC_32 (part of HMAC-SHA1) for checksum.
    pub fn encrypt_key(
        &self,
        volume_key: &[u8],
        user_key: &[u8],
        user_iv: &[u8],
    ) -> Result<Vec<u8>> {
        // 1. Calculate Checksum (MAC_32)
        let checksum = Self::mac_32_with_key(volume_key, 0, user_key)?;

        // 2. Encrypt using two-pass stream encoding (matching C++ streamEncode)
        let mut data = volume_key.to_vec();

        // Pass 1: shuffle, encrypt with iv64, flip, shuffle
        Self::shuffle_bytes(&mut data);
        let ivec1 = self.calculate_iv(checksum as u64, user_key, user_iv)?;
        self.stream_encrypt_inplace(&mut data, user_key, &ivec1)?;
        Self::flip_bytes(&mut data);
        Self::shuffle_bytes(&mut data);

        // Pass 2: encrypt with iv64+1
        let ivec2 = self.calculate_iv(checksum as u64 + 1, user_key, user_iv)?;
        self.stream_encrypt_inplace(&mut data, user_key, &ivec2)?;

        // 3. Prepend checksum (4 bytes, Big Endian)
        let mut result = Vec::with_capacity(4 + data.len());
        result.extend_from_slice(&checksum.to_be_bytes());
        result.extend_from_slice(&data);

        Ok(result)
    }

    // ... (stream_decode, calculate_iv, etc.)

    pub fn mac_16(&self, data: &[u8], iv: u64) -> Result<(u16, u64)> {
        let mac64 = self.mac_64(data, iv)?;
        let mac32 = ((mac64 >> 32) as u32) ^ (mac64 as u32);
        let mac16 = ((mac32 >> 16) as u16) ^ (mac32 as u16);
        Ok((mac16, mac64))
    }

    pub fn mac_64_with_key(data: &[u8], iv: u64, key: &[u8]) -> Result<u64> {
        if key.is_empty() {
            return Ok(0);
        }

        let mut signer = Self::hmac_sha1(key)?;
        signer.update(data);
        signer.update(&iv.to_le_bytes());
        let hmac = signer.finalize().into_bytes();

        // EncFS XORs only mdLen - 1 bytes (skips last byte)!
        let mut h = [0u8; 8];
        for (i, &b) in hmac.iter().take(hmac.len() - 1).enumerate() {
            h[i % 8] ^= b;
        }

        // C++ constructs u64 Big Endian: value = (value << 8) | h[i]
        Ok(u64::from_be_bytes(h))
    }

    /// EncFS MAC_64 without chained IV.
    ///
    /// This matches the legacy C++ implementation when `chainedIV == nullptr`:
    /// HMAC-SHA1(key, data), XOR-reduce all but the last digest byte into 8 bytes,
    /// then interpret those 8 bytes as a big-endian `u64`.
    pub fn mac_64_no_iv_with_key(data: &[u8], key: &[u8]) -> Result<u64> {
        if key.is_empty() {
            return Ok(0);
        }

        let mut signer = Self::hmac_sha1(key)?;
        signer.update(data);
        let hmac = signer.finalize().into_bytes();

        // EncFS XORs only mdLen - 1 bytes (skips last byte)!
        let mut h = [0u8; 8];
        for (i, &b) in hmac.iter().take(hmac.len().saturating_sub(1)).enumerate() {
            h[i % 8] ^= b;
        }

        Ok(u64::from_be_bytes(h))
    }

    pub fn mac_64_no_iv(&self, data: &[u8]) -> Result<u64> {
        Self::mac_64_no_iv_with_key(data, &self.key)
    }

    pub fn mac_32_with_key(data: &[u8], _iv: u64, key: &[u8]) -> Result<u32> {
        // For key verification, EncFS does NOT include IV in HMAC.
        // So we need a version of mac_64 that doesn't include IV.

        if key.is_empty() {
            return Ok(0);
        }

        let mut signer = Self::hmac_sha1(key)?;
        signer.update(data);
        // NO IV update here for key verification!

        let hmac = signer.finalize().into_bytes();

        // EncFS XORs only mdLen - 1 bytes (skips last byte)!
        let mut h = [0u8; 8];
        for (i, &b) in hmac.iter().take(hmac.len() - 1).enumerate() {
            h[i % 8] ^= b;
        }

        // C++ constructs u64 Big Endian: value = (value << 8) | h[i]
        let mac64 = u64::from_be_bytes(h);
        Ok(((mac64 >> 32) as u32) ^ (mac64 as u32))
    }

    pub fn mac_64(&self, data: &[u8], iv: u64) -> Result<u64> {
        Self::mac_64_with_key(data, iv, &self.key)
    }
    /// Standard stream decoding for EncFS.
    ///
    /// EncFS uses a unique "shuffle/flip" algorithm on top of the cipher
    /// to diffuse changes. It performs two passes of encryption/decryption
    /// with different IVs (derived from the block IV).
    pub fn legacy_stream_decode(
        &self,
        data: &mut [u8],
        iv64: u64,
        key: &[u8],
        iv: &[u8],
    ) -> Result<()> {
        // EncFS does TWO passes of decryption:
        // Pass 1: setIVec(iv64 + 1), decrypt, unshuffle, flip
        // Pass 2: setIVec(iv64), decrypt, unshuffle

        // Pass 1
        let ivec1 = self.calculate_iv(iv64 + 1, key, iv)?;
        self.stream_decrypt_inplace(data, key, &ivec1)?;

        Self::unshuffle_bytes(data);
        Self::flip_bytes(data);

        // Pass 2
        let ivec2 = self.calculate_iv(iv64, key, iv)?;
        self.stream_decrypt_inplace(data, key, &ivec2)?;

        Self::unshuffle_bytes(data);
        Ok(())
    }

    fn calculate_iv(&self, seed: u64, key: &[u8], iv: &[u8]) -> Result<Vec<u8>> {
        if self.iface.major >= 3 {
            // HMAC(key, iv || seed)
            let mut signer = Self::hmac_sha1(key)?;
            signer.update(iv);
            signer.update(&seed.to_le_bytes()); // EncFS uses little endian for seed in HMAC
            let hmac = signer.finalize().into_bytes();

            let mut new_iv = vec![0u8; self.iv_len];
            let len = std::cmp::min(self.iv_len, hmac.len());
            new_iv[..len].copy_from_slice(&hmac[..len]);

            Ok(new_iv)
        } else {
            self.set_iv_old(seed, iv)
        }
    }

    fn set_iv_old(&self, seed: u64, iv: &[u8]) -> Result<Vec<u8>> {
        // Legacy IV generation (EncFS < 1.5 ish, major < 3)
        // seed is u64 but legacy code treated it as unsigned int (u32) mostly?
        // C++ code uses `unsigned int seed`. So we cast.
        let seed = seed as u32;

        let var1 = (0x060a4011u32).wrapping_mul(seed);
        let var2 = (0x0221040du32).wrapping_mul(seed ^ 0xD3FEA11C);

        // Start with the master IV

        let mut new_iv = vec![0u8; self.iv_len];
        if iv.len() < self.iv_len {
            return Err(anyhow::anyhow!("Master IV too short"));
        }
        new_iv.copy_from_slice(&iv[..self.iv_len]);

        if self.iv_len >= 8 {
            new_iv[0] ^= ((var1 >> 24) & 0xff) as u8;
            new_iv[1] ^= ((var2 >> 16) & 0xff) as u8;
            new_iv[2] ^= ((var1 >> 8) & 0xff) as u8;
            new_iv[3] ^= (var2 & 0xff) as u8;
            new_iv[4] ^= ((var2 >> 24) & 0xff) as u8;
            new_iv[5] ^= ((var1 >> 16) & 0xff) as u8;
            new_iv[6] ^= ((var2 >> 8) & 0xff) as u8;
            new_iv[7] ^= (var1 & 0xff) as u8;
        }

        if self.iv_len > 8 {
            // 16 byte IV support (AES)
            // ivec[8 + 0] ^= (var1)&0xff;
            // ...
            new_iv[8] ^= (var1 & 0xff) as u8;
            new_iv[8 + 1] ^= ((var2 >> 8) & 0xff) as u8;
            new_iv[8 + 2] ^= ((var1 >> 16) & 0xff) as u8;
            new_iv[8 + 3] ^= ((var2 >> 24) & 0xff) as u8;
            new_iv[8 + 4] ^= ((var1 >> 24) & 0xff) as u8;
            new_iv[8 + 5] ^= ((var2 >> 16) & 0xff) as u8;
            new_iv[8 + 6] ^= ((var1 >> 8) & 0xff) as u8;
            new_iv[8 + 7] ^= (var2 & 0xff) as u8;
        }

        Ok(new_iv)
    }

    pub fn decrypt_filename(&self, encoded_name: &str, iv: u64) -> Result<(Vec<u8>, u64)> {
        match self.name_encoding {
            NameEncoding::Stream => self.decrypt_filename_stream(encoded_name, iv),
            NameEncoding::Block => self.decrypt_filename_block(encoded_name, iv),
        }
    }

    fn decrypt_filename_stream(&self, encoded_name: &str, iv: u64) -> Result<(Vec<u8>, u64)> {
        // 1. Base64 Decode
        let data = Self::filename_base64_decode(encoded_name)?;

        // 2. Extract Checksum
        if data.len() < 2 {
            return Err(anyhow!("Filename too short"));
        }

        // Checksum is first 2 bytes (big endian)
        let checksum = ((data[0] as u16) << 8) | (data[1] as u16);

        // 3. Decrypt Name
        let mut name_data = data[2..].to_vec();

        // IV for name decryption is checksum ^ directory_iv
        let name_iv = (checksum as u64) ^ iv;

        self.legacy_stream_decode(&mut name_data, name_iv, &self.key, &self.iv)?;

        // 4. Verify Checksum
        let (calculated_mac, new_iv) = self.mac_16(&name_data, iv)?;
        if calculated_mac != checksum {
            return Err(anyhow!(
                "Checksum mismatch in filename: expected {:04x}, got {:04x}",
                checksum,
                calculated_mac
            ));
        }

        // 5. Return bytes
        Ok((name_data, new_iv))
    }

    fn decrypt_filename_block(&self, encoded_name: &str, iv: u64) -> Result<(Vec<u8>, u64)> {
        // 1. Base64 Decode
        let data = Self::filename_base64_decode(encoded_name)?;

        if data.len() < 2 {
            return Err(anyhow!("Filename too short"));
        }

        // 2. Extract MAC
        let checksum = ((data[0] as u16) << 8) | (data[1] as u16);

        // 3. Decrypt
        let mut block_data = data[2..].to_vec();
        let bs = self.block_size();

        if block_data.len() < bs || block_data.len() % bs != 0 {
            return Err(anyhow!("Block data length invalid"));
        }

        // IV for name decryption is checksum ^ directory_iv
        let name_iv = (checksum as u64) ^ iv;
        self.legacy_block_decode(&mut block_data, name_iv, &self.key, &self.iv)?;

        // 4. Verify MAC (over decrypted data INCLUDING padding)
        // Fix Padding Oracle: Verify MAC *before* checking padding.

        let (calculated_mac, new_iv) = self.mac_16(&block_data, iv)?;
        if calculated_mac != checksum {
            return Err(anyhow!(
                "Checksum mismatch in filename: expected {:04x}, got {:04x}",
                checksum,
                calculated_mac
            ));
        }

        // 5. Remove Padding
        // Padding is the last byte.
        let padding = *block_data.last().ok_or(anyhow!("Empty block data"))? as usize;
        if padding > bs || padding == 0 || padding > block_data.len() {
            return Err(anyhow!("Invalid padding: {}", padding));
        }

        let final_len = block_data.len() - padding;
        block_data.truncate(final_len);

        Ok((block_data, new_iv))
    }

    pub fn encrypt_filename(&self, plaintext_name: &[u8], iv: u64) -> Result<(String, u64)> {
        match self.name_encoding {
            NameEncoding::Stream => self.encrypt_filename_stream(plaintext_name, iv),
            NameEncoding::Block => self.encrypt_filename_block(plaintext_name, iv),
        }
    }

    pub fn max_plaintext_name_len(&self, max_encoded_len: u32) -> u32 {
        let max_bytes = (max_encoded_len * 6) / 8;
        if max_bytes <= 2 {
            return 0; // Too small to hold checksum
        }
        match self.name_encoding {
            NameEncoding::Stream => max_bytes - 2,
            NameEncoding::Block => {
                let bs = self.block_size() as u32;
                let max_bs_multiple = max_bytes - 2;
                let max_blocks = (max_bs_multiple / bs) * bs;
                if max_blocks == 0 { 0 } else { max_blocks - 1 }
            }
        }
    }

    fn encrypt_filename_stream(&self, plaintext_name: &[u8], iv: u64) -> Result<(String, u64)> {
        // 1. Calculate Checksum
        let (checksum, new_iv) = self.mac_16(plaintext_name, iv)?;

        // 2. Construct Buffer
        let mut data = Vec::with_capacity(2 + plaintext_name.len());
        data.push((checksum >> 8) as u8);
        data.push((checksum & 0xff) as u8);
        data.extend_from_slice(plaintext_name);

        // 3. Encrypt
        // IV for name encryption is checksum ^ directory_iv
        let name_iv = (checksum as u64) ^ iv;

        let mut name_data = data[2..].to_vec();
        self.stream_encode(&mut name_data, name_iv, &self.key, &self.iv)?;

        // Copy back encrypted data
        data.splice(2.., name_data);

        // 4. Base64 Encode
        let encoded = Self::filename_base64_encode(&data)?;
        Ok((encoded, new_iv))
    }

    fn encrypt_filename_block(&self, plaintext_name: &[u8], iv: u64) -> Result<(String, u64)> {
        let bs = self.block_size();

        // 1. Calculate Padding
        let len = plaintext_name.len();
        let padding = bs - (len % bs);

        // 2. Construct Buffer
        // [MAC (2)] [Plaintext] [Padding]
        let mut data = Vec::with_capacity(2 + len + padding);
        data.push(0); // Placeholder
        data.push(0);
        data.extend_from_slice(plaintext_name);
        for _ in 0..padding {
            data.push(padding as u8);
        }

        // 3. Calculate MAC (over Plaintext + Padding)
        let (checksum, new_iv) = self.mac_16(&data[2..], iv)?;

        // Store MAC
        data[0] = (checksum >> 8) as u8;
        data[1] = (checksum & 0xff) as u8;

        // 4. Encrypt
        let name_iv = (checksum as u64) ^ iv;

        let mut block_data = data[2..].to_vec();
        self.block_encode(&mut block_data, name_iv, &self.key, &self.iv)?;

        // Copy back
        data.splice(2.., block_data);

        // 5. Base64 Encode
        let encoded = Self::filename_base64_encode(&data)?;
        Ok((encoded, new_iv))
    }

    pub fn stream_encode(&self, data: &mut [u8], iv64: u64, key: &[u8], iv: &[u8]) -> Result<()> {
        // Pass 1: Shuffle -> Encrypt(IV)
        Self::shuffle_bytes(data);

        let ivec = self.calculate_iv(iv64, key, iv)?;
        self.stream_encrypt_inplace(data, key, &ivec)?;

        // Pass 2: Flip -> Shuffle -> Encrypt(IV+1)
        Self::flip_bytes(data);
        Self::shuffle_bytes(data);

        let ivec2 = self.calculate_iv(iv64 + 1, key, iv)?;
        self.stream_encrypt_inplace(data, key, &ivec2)?;

        Ok(())
    }

    pub fn block_encode(&self, data: &mut [u8], iv64: u64, key: &[u8], iv: &[u8]) -> Result<()> {
        let ivec = self.calculate_iv(iv64, key, iv)?;
        self.block_encrypt_inplace(data, key, &ivec)
    }

    fn filename_base64_encode(data: &[u8]) -> Result<String> {
        // Custom Base64 encoding
        // 1. changeBase2 (pack 8-bit bytes into 6-bit values)
        // 2. B64ToAscii (map 0-63 to chars)

        let mut b64_vals = Vec::new();
        let mut work: u32 = 0;
        let mut work_bits = 0;

        for &b in data {
            work |= (b as u32) << work_bits;
            work_bits += 8;

            while work_bits >= 6 {
                b64_vals.push((work & 0x3f) as u8);
                work >>= 6;
                work_bits -= 6;
            }
        }
        if work_bits > 0 {
            b64_vals.push((work & 0x3f) as u8);
        }

        let mut s = String::with_capacity(b64_vals.len());
        for v in b64_vals {
            let c = match v {
                0 => ',',
                1 => '-',
                2..=11 => (b'0' + (v - 2)) as char,
                12..=37 => (b'A' + (v - 12)) as char,
                38..=63 => (b'a' + (v - 38)) as char,
                _ => return Err(anyhow!("Invalid base64 value: {}", v)),
            };
            s.push(c);
        }

        Ok(s)
    }

    fn shuffle_bytes(buf: &mut [u8]) {
        if buf.len() < 2 {
            return;
        }
        for i in 0..buf.len() - 1 {
            buf[i + 1] ^= buf[i];
        }
    }

    pub fn decrypt_header(&self, header: &mut [u8], external_iv: u64) -> Result<u64> {
        // Decrypt header using stream cipher and external IV
        // Header is 8 bytes.
        // We use self.key and self.iv (which is the volume key/iv).
        self.legacy_stream_decode(header, external_iv, &self.key, &self.iv)?;

        let mut file_iv = 0u64;
        for &b in header.iter() {
            file_iv = (file_iv << 8) | (b as u64);
        }

        Ok(file_iv)
    }

    pub fn encrypt_header(&self, external_iv: u64) -> Result<(Vec<u8>, u64)> {
        // Generate random 64-bit file IV
        let mut file_iv_bytes = [0u8; 8];
        getrandom::fill(&mut file_iv_bytes)
            .map_err(|e| anyhow!("Failed to generate random IV: {}", e))?;

        let file_iv = u64::from_be_bytes(file_iv_bytes);
        let mut header = file_iv_bytes.to_vec();

        // Encrypt header using stream cipher and external IV
        self.stream_encode(&mut header, external_iv, &self.key, &self.iv)?;

        Ok((header, file_iv))
    }

    pub fn encrypt_header_with_iv(&self, file_iv: u64, external_iv: u64) -> Result<Vec<u8>> {
        let file_iv_bytes = file_iv.to_be_bytes();
        let mut header = file_iv_bytes.to_vec();

        // Encrypt header using stream cipher and external IV
        self.stream_encode(&mut header, external_iv, &self.key, &self.iv)?;

        Ok(header)
    }

    pub fn encrypt_block_inplace(
        &self,
        data: &mut [u8],
        block_num: u64,
        file_iv: u64,
        block_size: u64,
    ) -> Result<()> {
        let iv64 = block_num ^ file_iv;

        if data.len() as u64 == block_size {
            // Full block - use block cipher (CBC)
            self.block_encode(data, iv64, &self.key, &self.iv)
        } else {
            // Partial block - use stream cipher (CFB)
            self.stream_encode(data, iv64, &self.key, &self.iv)
        }
    }

    fn aes_gcm_siv_nonce(file_iv: u64, block_num: u64) -> [u8; 12] {
        let mut nonce = [0u8; 12];
        nonce[..8].copy_from_slice(&(file_iv ^ (block_num >> 32)).to_le_bytes());
        nonce[8..].copy_from_slice(&(block_num as u32).to_le_bytes());
        nonce
    }

    fn aes_gcm_siv_aad(file_iv: u64, block_num: u64) -> [u8; 16] {
        let mut aad = [0u8; 16];
        aad[..8].copy_from_slice(&file_iv.to_le_bytes());
        aad[8..].copy_from_slice(&block_num.to_le_bytes());
        aad
    }

    pub fn encrypt_block_aes_gcm_siv_inplace(
        &self,
        data: &mut [u8],
        block_num: u64,
        file_iv: u64,
    ) -> Result<[u8; 16]> {
        if self.iface.name != "ssl/aes" {
            return Err(anyhow!("AES-GCM-SIV block mode requires ssl/aes cipher"));
        }
        if self.key.is_empty() {
            return Err(anyhow!("Cipher key is not initialized"));
        }

        let nonce_bytes = Self::aes_gcm_siv_nonce(file_iv, block_num);
        let nonce = Nonce::from(nonce_bytes);
        let aad = Self::aes_gcm_siv_aad(file_iv, block_num);

        let tag = match self.key.len() {
            16 => {
                let cipher = Aes128GcmSiv::new_from_slice(&self.key)
                    .map_err(|e| anyhow!("Invalid AES-128-GCM-SIV key: {}", e))?;
                cipher
                    .encrypt_in_place_detached(&nonce, &aad, data)
                    .map_err(|_| anyhow!("AES-GCM-SIV encryption failed for block {}", block_num))?
            }
            32 => {
                let cipher = Aes256GcmSiv::new_from_slice(&self.key)
                    .map_err(|e| anyhow!("Invalid AES-256-GCM-SIV key: {}", e))?;
                cipher
                    .encrypt_in_place_detached(&nonce, &aad, data)
                    .map_err(|_| anyhow!("AES-GCM-SIV encryption failed for block {}", block_num))?
            }
            other => {
                return Err(anyhow!(
                    "AES-GCM-SIV block mode requires 128-bit or 256-bit AES key (got {} bytes)",
                    other
                ));
            }
        };

        Ok(tag.into())
    }

    pub fn decrypt_block_aes_gcm_siv_inplace(
        &self,
        data: &mut [u8],
        tag: &[u8],
        block_num: u64,
        file_iv: u64,
    ) -> Result<()> {
        if self.iface.name != "ssl/aes" {
            return Err(anyhow!("AES-GCM-SIV block mode requires ssl/aes cipher"));
        }
        if self.key.is_empty() {
            return Err(anyhow!("Cipher key is not initialized"));
        }
        if tag.len() != 16 {
            return Err(anyhow!(
                "Invalid AES-GCM-SIV tag length {} (expected 16)",
                tag.len()
            ));
        }

        let nonce_bytes = Self::aes_gcm_siv_nonce(file_iv, block_num);
        let nonce = Nonce::from(nonce_bytes);
        let aad = Self::aes_gcm_siv_aad(file_iv, block_num);
        let tag = Tag::from_slice(tag);

        match self.key.len() {
            16 => {
                let cipher = Aes128GcmSiv::new_from_slice(&self.key)
                    .map_err(|e| anyhow!("Invalid AES-128-GCM-SIV key: {}", e))?;
                cipher
                    .decrypt_in_place_detached(&nonce, &aad, data, tag)
                    .map_err(|_| {
                        anyhow!(
                            "AES-GCM-SIV tag verification failed for block {}",
                            block_num
                        )
                    })?
            }
            32 => {
                let cipher = Aes256GcmSiv::new_from_slice(&self.key)
                    .map_err(|e| anyhow!("Invalid AES-256-GCM-SIV key: {}", e))?;
                cipher
                    .decrypt_in_place_detached(&nonce, &aad, data, tag)
                    .map_err(|_| {
                        anyhow!(
                            "AES-GCM-SIV tag verification failed for block {}",
                            block_num
                        )
                    })?
            }
            other => {
                return Err(anyhow!(
                    "AES-GCM-SIV block mode requires 128-bit or 256-bit AES key (got {} bytes)",
                    other
                ));
            }
        }

        Ok(())
    }

    pub fn legacy_decrypt_block_inplace(
        &self,
        data: &mut [u8],
        block_num: u64,
        file_iv: u64,
        block_size: u64,
    ) -> Result<()> {
        let iv64 = block_num ^ file_iv;

        if data.len() as u64 == block_size {
            // Full block - use block cipher (CBC)
            self.legacy_block_decode(data, iv64, &self.key, &self.iv)
        } else {
            // Partial block - use stream cipher (CFB)
            self.legacy_stream_decode(data, iv64, &self.key, &self.iv)
        }
    }
    pub fn legacy_block_decode(
        &self,
        data: &mut [u8],
        iv64: u64,
        key: &[u8],
        iv: &[u8],
    ) -> Result<()> {
        let ivec = self.calculate_iv(iv64, key, iv)?;
        self.block_decrypt_inplace(data, key, &ivec)
    }
    pub fn set_key(&mut self, key: &[u8], iv: &[u8]) {
        self.key = key.to_vec();
        self.iv = iv.to_vec();
    }

    fn filename_base64_decode(s: &str) -> Result<Vec<u8>> {
        let mut b64_vals = Vec::with_capacity(s.len());
        for c in s.chars() {
            let v = match c {
                ',' => 0,
                '-' => 1,
                '0'..='9' => 2 + (c as u8 - b'0'),
                'A'..='Z' => 12 + (c as u8 - b'A'),
                'a'..='z' => 38 + (c as u8 - b'a'),
                _ => return Err(anyhow!("Invalid char in filename: {}", c)),
            };
            b64_vals.push(v);
        }

        let mut out = Vec::new();
        let mut work: u32 = 0;
        let mut work_bits = 0;

        for v in b64_vals {
            work |= (v as u32) << work_bits;
            work_bits += 6;

            while work_bits >= 8 {
                out.push((work & 0xff) as u8);
                work >>= 8;
                work_bits -= 8;
            }
        }

        Ok(out)
    }

    /// Encrypts xattr data (name or value) using block encryption with MAC-then-Encrypt.
    /// Format: [data] [MAC(2 bytes)] [padding] -> encrypted
    /// MAC is calculated first, then appended to data, then everything is encrypted.
    /// Uses path_iv directly (not MAC-dependent) for true MAC-then-Encrypt.
    /// The iv_offset distinguishes between name and value encryption.
    fn encrypt_xattr_data(&self, data: &[u8], path_iv: u64, iv_offset: u64) -> Result<Vec<u8>> {
        // 1. Calculate MAC (MAC_16) over the plaintext data
        let (mac, _) = self.mac_16(data, path_iv)?;

        // 2. Construct buffer: [data] [MAC(2 bytes)]
        let mut buffer = Vec::with_capacity(data.len() + 2);
        buffer.extend_from_slice(data);
        buffer.push((mac >> 8) as u8);
        buffer.push((mac & 0xff) as u8);

        // 3. Pad to block size
        let bs = self.block_size();
        let padding = bs - (buffer.len() % bs);
        for _ in 0..padding {
            buffer.push(padding as u8);
        }

        // 4. Encrypt using block cipher
        // Use path_iv with offset to distinguish between name and value encryption
        let iv_seed = path_iv.wrapping_add(iv_offset);
        self.block_encode(&mut buffer, iv_seed, &self.key, &self.iv)?;

        Ok(buffer)
    }

    /// Decrypts xattr data (name or value) using block encryption with MAC-then-Encrypt.
    /// Format: [data] [MAC(2 bytes)] [padding] -> encrypted
    /// The iv_offset distinguishes between name and value decryption.
    fn decrypt_xattr_data(
        &self,
        encrypted_data: &[u8],
        path_iv: u64,
        iv_offset: u64,
    ) -> Result<Vec<u8>> {
        let bs = self.block_size();

        // 1. Check minimum size (must be at least one block)
        #[allow(clippy::manual_is_multiple_of)] // is_multiple_of is unstable on stable Rust
        if encrypted_data.len() < bs || encrypted_data.len() % bs != 0 {
            return Err(anyhow!("Encrypted xattr data length invalid"));
        }

        // 2. Decrypt first (MAC-then-Encrypt: decrypt before verifying MAC)
        let mut data = encrypted_data.to_vec();
        let iv_seed = path_iv.wrapping_add(iv_offset);
        self.legacy_block_decode(&mut data, iv_seed, &self.key, &self.iv)?;

        // 3. Remove padding
        if data.is_empty() {
            return Err(anyhow!("Decrypted xattr data is empty"));
        }
        let padding = *data.last().ok_or(anyhow!("Empty data"))? as usize;
        if padding > bs || padding == 0 || padding > data.len() {
            return Err(anyhow!("Invalid padding: {}", padding));
        }
        let data_len = data.len() - padding;
        if data_len < 2 {
            return Err(anyhow!("Decrypted data too short for MAC"));
        }

        // 4. Extract MAC and data
        let plaintext_data = data[..data_len - 2].to_vec();
        let stored_mac = ((data[data_len - 2] as u16) << 8) | (data[data_len - 1] as u16);

        // 5. Verify MAC (MAC-then-Encrypt: verify MAC after decryption)
        let (calculated_mac, _) = self.mac_16(&plaintext_data, path_iv)?;
        if calculated_mac != stored_mac {
            return Err(anyhow!(
                "MAC mismatch in xattr data: expected {:04x}, got {:04x}",
                stored_mac,
                calculated_mac
            ));
        }

        Ok(plaintext_data)
    }

    /// Encrypts an xattr name using block encryption with MAC-then-Encrypt.
    /// Format: [name] [MAC(2 bytes)] [padding] -> encrypted
    pub fn encrypt_xattr_name(&self, name: &[u8], path_iv: u64) -> Result<Vec<u8>> {
        const NAME_IV_OFFSET: u64 = 0x2000000000000000u64;
        self.encrypt_xattr_data(name, path_iv, NAME_IV_OFFSET)
    }

    /// Decrypts an xattr name using block encryption with MAC-then-Encrypt.
    pub fn decrypt_xattr_name(&self, encrypted_name: &[u8], path_iv: u64) -> Result<Vec<u8>> {
        const NAME_IV_OFFSET: u64 = 0x2000000000000000u64;
        self.decrypt_xattr_data(encrypted_name, path_iv, NAME_IV_OFFSET)
    }

    /// Encrypts an xattr value using block encryption with MAC-then-Encrypt.
    pub fn encrypt_xattr_value(&self, value: &[u8], path_iv: u64) -> Result<Vec<u8>> {
        const VALUE_IV_OFFSET: u64 = 0x1000000000000000u64;
        self.encrypt_xattr_data(value, path_iv, VALUE_IV_OFFSET)
    }

    /// Decrypts an xattr value using block encryption with MAC-then-Encrypt.
    pub fn decrypt_xattr_value(&self, encrypted_value: &[u8], path_iv: u64) -> Result<Vec<u8>> {
        const VALUE_IV_OFFSET: u64 = 0x1000000000000000u64;
        self.decrypt_xattr_data(encrypted_value, path_iv, VALUE_IV_OFFSET)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Interface;
    use crate::constants::{
        DEFAULT_ARGON2_MEMORY_COST, DEFAULT_ARGON2_PARALLELISM, DEFAULT_ARGON2_TIME_COST,
    };

    /// Shared cipher configuration for all encryption mode tests
    struct CipherTestConfig {
        name: &'static str,
        key_size: i32,
        block_size: usize, // Block size in bytes
        iv_size: usize,    // IV size in bytes
    }

    /// Returns all supported cipher configurations for testing
    fn all_cipher_configs() -> Vec<CipherTestConfig> {
        vec![
            CipherTestConfig {
                name: "ssl/aes",
                key_size: 128,
                block_size: 16, // AES block size
                iv_size: 16,
            },
            CipherTestConfig {
                name: "ssl/aes",
                key_size: 192,
                block_size: 16,
                iv_size: 16,
            },
            CipherTestConfig {
                name: "ssl/aes",
                key_size: 256,
                block_size: 16,
                iv_size: 16,
            },
            CipherTestConfig {
                name: "ssl/blowfish",
                key_size: 160,
                block_size: 8, // Blowfish block size
                iv_size: 8,
            },
        ]
    }

    #[test]
    fn test_legacy_iv() {
        // Mock interface with version 2 (legacy)
        let iface = Interface {
            name: "ssl/aes".to_string(),
            major: 2,
            minor: 0,
            age: 0,
        };
        let cipher = SslCipher::new(&iface, 192).unwrap();

        let seed: u64 = 1;
        let master_iv = vec![0u8; 16]; // 16 bytes of zeros

        let iv = cipher.calculate_iv(seed, &[], &master_iv).unwrap();

        // var1 = 0x060a4011
        // var2 = 0xBD2FA279

        let var1: u32 = 0x060a4011;
        let var2: u32 = 0xBD2FA279;

        // Byte 0: master[0] ^ (var1 >> 24) = 0 ^ 0x06 = 0x06
        // Byte 1: master[1] ^ (var2 >> 16) = 0 ^ 0xBD2F => 0x2F

        assert_eq!(iv[0], ((var1 >> 24) & 0xff) as u8); // 0x06
        assert_eq!(iv[1], ((var2 >> 16) & 0xff) as u8); // 0x2F
    }

    #[test]
    fn test_all_block_encryption_modes() {
        // Test all supported block encryption modes (CBC mode)
        // Block ciphers require data to be a multiple of the block size

        let configs = all_cipher_configs();

        for config in configs {
            let iface = Interface {
                name: config.name.to_string(),
                major: 3,
                minor: 0,
                age: 0,
            };

            let mut cipher = match SslCipher::new(&iface, config.key_size) {
                Ok(c) => c,
                Err(e) => {
                    eprintln!(
                        "Skipping {} {}: {}. This may be due to OpenSSL 3.0+ requiring legacy algorithms.",
                        config.name, config.key_size, e
                    );
                    continue;
                }
            };

            // Generate test key and IV
            let key_len = (config.key_size / 8) as usize;
            let key: Vec<u8> = (0..key_len).map(|i| (i as u8).wrapping_mul(0x11)).collect();
            let iv: Vec<u8> = (0..config.iv_size)
                .map(|i| (i as u8).wrapping_mul(0x22))
                .collect();
            cipher.set_key(&key, &iv);

            // Test with single block
            let mut single_block = vec![0u8; config.block_size];
            for (i, item) in single_block.iter_mut().enumerate() {
                *item = (i as u8).wrapping_mul(0x33);
            }
            let original_single = single_block.clone();
            let iv64 = 0x1234567890abcdef;

            match cipher.block_encode(&mut single_block, iv64, &key, &iv) {
                Ok(_) => {
                    assert_ne!(
                        single_block, original_single,
                        "{} {}: Encrypted single block should differ from plaintext",
                        config.name, config.key_size
                    );

                    match cipher.legacy_block_decode(&mut single_block, iv64, &key, &iv) {
                        Ok(_) => {
                            assert_eq!(
                                single_block, original_single,
                                "{} {}: Decrypted single block should match original",
                                config.name, config.key_size
                            );
                        }
                        Err(e) => {
                            panic!(
                                "{} {}: Block decryption failed: {}",
                                config.name, config.key_size, e
                            );
                        }
                    }
                }
                Err(e) => {
                    eprintln!(
                        "Skipping {} {} block test: {}. OpenSSL 3.0+ may require legacy algorithms.",
                        config.name, config.key_size, e
                    );
                    continue;
                }
            }

            // Test with multiple blocks (3 blocks)
            let multi_block_size = config.block_size * 3;
            let mut multi_block = vec![0u8; multi_block_size];
            for (i, item) in multi_block.iter_mut().enumerate() {
                *item = (i as u8).wrapping_mul(0x44);
            }
            let original_multi = multi_block.clone();

            cipher
                .block_encode(&mut multi_block, iv64, &key, &iv)
                .unwrap_or_else(|_| {
                    panic!(
                        "{} {}: Multi-block encryption failed",
                        config.name, config.key_size
                    )
                });
            assert_ne!(
                multi_block, original_multi,
                "{} {}: Encrypted multi-block should differ from plaintext",
                config.name, config.key_size
            );

            cipher
                .legacy_block_decode(&mut multi_block, iv64, &key, &iv)
                .unwrap_or_else(|_| {
                    panic!(
                        "{} {}: Multi-block decryption failed",
                        config.name, config.key_size
                    )
                });
            assert_eq!(
                multi_block, original_multi,
                "{} {}: Decrypted multi-block should match original",
                config.name, config.key_size
            );

            println!(
                "✓ {} {} block encryption mode: round-trip test passed",
                config.name, config.key_size
            );
        }
    }

    #[test]
    fn test_all_stream_encryption_modes() {
        // Test all supported stream encryption modes (CFB mode)
        // Stream ciphers can handle data of any size

        let configs = all_cipher_configs();

        for config in configs {
            let iface = Interface {
                name: config.name.to_string(),
                major: 3,
                minor: 0,
                age: 0,
            };

            let mut cipher = match SslCipher::new(&iface, config.key_size) {
                Ok(c) => c,
                Err(e) => {
                    eprintln!(
                        "Skipping {} {}: {}. This may be due to OpenSSL 3.0+ requiring legacy algorithms.",
                        config.name, config.key_size, e
                    );
                    continue;
                }
            };

            // Generate test key and IV
            let key_len = (config.key_size / 8) as usize;
            let key: Vec<u8> = (0..key_len).map(|i| (i as u8).wrapping_mul(0x55)).collect();
            let iv: Vec<u8> = (0..config.iv_size)
                .map(|i| (i as u8).wrapping_mul(0x66))
                .collect();
            cipher.set_key(&key, &iv);

            let iv64 = 0xabcdef1234567890;

            // Test with small data (less than block size)
            let mut small_data = b"Hello!".to_vec();
            let original_small = small_data.clone();

            match cipher.stream_encode(&mut small_data, iv64, &key, &iv) {
                Ok(_) => {
                    assert_ne!(
                        small_data, original_small,
                        "{} {}: Encrypted small data should differ from plaintext",
                        config.name, config.key_size
                    );

                    match cipher.legacy_stream_decode(&mut small_data, iv64, &key, &iv) {
                        Ok(_) => {
                            assert_eq!(
                                small_data, original_small,
                                "{} {}: Decrypted small data should match original",
                                config.name, config.key_size
                            );
                        }
                        Err(e) => {
                            panic!(
                                "{} {}: Stream decryption failed for small data: {}",
                                config.name, config.key_size, e
                            );
                        }
                    }
                }
                Err(e) => {
                    eprintln!(
                        "Skipping {} {} stream test: {}. OpenSSL 3.0+ may require legacy algorithms.",
                        config.name, config.key_size, e
                    );
                    continue;
                }
            }

            // Test with medium data (multiple blocks)
            let medium_data_size = config.block_size * 3;
            let mut medium_data = vec![0u8; medium_data_size];
            for (i, item) in medium_data.iter_mut().enumerate() {
                *item = (i as u8).wrapping_mul(0x77);
            }
            let original_medium = medium_data.clone();

            cipher
                .stream_encode(&mut medium_data, iv64, &key, &iv)
                .unwrap_or_else(|_| {
                    panic!(
                        "{} {}: Medium data stream encryption failed",
                        config.name, config.key_size
                    )
                });
            assert_ne!(
                medium_data, original_medium,
                "{} {}: Encrypted medium data should differ from plaintext",
                config.name, config.key_size
            );

            cipher
                .legacy_stream_decode(&mut medium_data, iv64, &key, &iv)
                .unwrap_or_else(|_| {
                    panic!(
                        "{} {}: Medium data stream decryption failed",
                        config.name, config.key_size
                    )
                });
            assert_eq!(
                medium_data, original_medium,
                "{} {}: Decrypted medium data should match original",
                config.name, config.key_size
            );

            // Test with large data (many blocks)
            let large_data_size = config.block_size * 16;
            let mut large_data = vec![0u8; large_data_size];
            for (i, item) in large_data.iter_mut().enumerate() {
                *item = (i as u8).wrapping_mul(0x88);
            }
            let original_large = large_data.clone();

            cipher
                .stream_encode(&mut large_data, iv64, &key, &iv)
                .unwrap_or_else(|_| {
                    panic!(
                        "{} {}: Large data stream encryption failed",
                        config.name, config.key_size
                    )
                });
            assert_ne!(
                large_data, original_large,
                "{} {}: Encrypted large data should differ from plaintext",
                config.name, config.key_size
            );

            cipher
                .legacy_stream_decode(&mut large_data, iv64, &key, &iv)
                .unwrap_or_else(|_| {
                    panic!(
                        "{} {}: Large data stream decryption failed",
                        config.name, config.key_size
                    )
                });
            assert_eq!(
                large_data, original_large,
                "{} {}: Decrypted large data should match original",
                config.name, config.key_size
            );

            // Test with odd-sized data (not aligned to block boundary)
            let odd_data = b"This is a test message with odd length!".to_vec();
            let mut odd_data_enc = odd_data.clone();
            let original_odd = odd_data.clone();

            cipher
                .stream_encode(&mut odd_data_enc, iv64, &key, &iv)
                .unwrap_or_else(|_| {
                    panic!(
                        "{} {}: Odd-sized data stream encryption failed",
                        config.name, config.key_size
                    )
                });
            assert_ne!(
                odd_data_enc, original_odd,
                "{} {}: Encrypted odd-sized data should differ from plaintext",
                config.name, config.key_size
            );

            cipher
                .legacy_stream_decode(&mut odd_data_enc, iv64, &key, &iv)
                .unwrap_or_else(|_| {
                    panic!(
                        "{} {}: Odd-sized data stream decryption failed",
                        config.name, config.key_size
                    )
                });
            assert_eq!(
                odd_data_enc, original_odd,
                "{} {}: Decrypted odd-sized data should match original",
                config.name, config.key_size
            );

            println!(
                "✓ {} {} stream encryption mode: round-trip test passed",
                config.name, config.key_size
            );
        }
    }

    #[test]
    fn test_xattr_encryption_decryption() {
        let configs = all_cipher_configs();

        for config in configs {
            // Skip blowfish for xattr tests as it may have compatibility issues with block encryption
            if config.name == "ssl/blowfish" {
                eprintln!(
                    "Skipping {} {} xattr tests due to compatibility issues",
                    config.name, config.key_size
                );
                continue;
            }

            let iface = Interface {
                name: config.name.to_string(),
                major: 3,
                minor: 0,
                age: 0,
            };

            let mut cipher = match SslCipher::new(&iface, config.key_size) {
                Ok(c) => c,
                Err(e) => {
                    eprintln!(
                        "Skipping {} {}: {}. This may be due to OpenSSL 3.0+ requiring legacy algorithms.",
                        config.name, config.key_size, e
                    );
                    continue;
                }
            };

            // Generate test key and IV
            let key_len = (config.key_size / 8) as usize;
            let key: Vec<u8> = (0..key_len).map(|i| (i as u8).wrapping_mul(0x11)).collect();
            let iv: Vec<u8> = (0..config.iv_size)
                .map(|i| (i as u8).wrapping_mul(0x22))
                .collect();
            cipher.set_key(&key, &iv);

            let path_iv = 0x1234567890abcdefu64;

            // Test xattr name encryption/decryption
            let test_names = vec![
                b"user.foo".to_vec(),
                b"user.bar".to_vec(),
                b"security.selinux".to_vec(),
                b"trusted.baz".to_vec(),
                b"a".to_vec(), // Short name
                b"very_long_attribute_name_that_exceeds_normal_length".to_vec(), // Long name
            ];

            for name in &test_names {
                let encrypted = cipher
                    .encrypt_xattr_name(name, path_iv)
                    .unwrap_or_else(|_| {
                        panic!(
                            "{} {}: xattr name encryption failed for {:?}",
                            config.name, config.key_size, name
                        )
                    });

                // Verify encrypted data is different from plaintext
                assert_ne!(
                    encrypted, *name,
                    "{} {}: Encrypted xattr name should differ from plaintext",
                    config.name, config.key_size
                );

                // Verify encrypted data is block-aligned
                assert_eq!(
                    encrypted.len() % config.block_size,
                    0,
                    "{} {}: Encrypted xattr name should be block-aligned",
                    config.name,
                    config.key_size
                );

                let decrypted = cipher
                    .decrypt_xattr_name(&encrypted, path_iv)
                    .unwrap_or_else(|_| {
                        panic!(
                            "{} {}: xattr name decryption failed for {:?}",
                            config.name, config.key_size, name
                        )
                    });

                assert_eq!(
                    decrypted, *name,
                    "{} {}: Decrypted xattr name should match original",
                    config.name, config.key_size
                );
            }

            // Test xattr value encryption/decryption
            let test_values = vec![
                b"hello world".to_vec(),
                b"".to_vec(),                  // Empty value
                b"a".to_vec(),                 // Single byte
                vec![0u8; 100],                // Multiple blocks
                vec![0xFFu8; 50],              // All 0xFF
                (0..255).collect::<Vec<u8>>(), // All byte values
            ];

            for value in &test_values {
                let encrypted = cipher
                    .encrypt_xattr_value(value, path_iv)
                    .unwrap_or_else(|_| {
                        panic!(
                            "{} {}: xattr value encryption failed for value of length {}",
                            config.name,
                            config.key_size,
                            value.len()
                        )
                    });

                // Verify encrypted data is different from plaintext (unless empty)
                if !value.is_empty() {
                    assert_ne!(
                        encrypted, *value,
                        "{} {}: Encrypted xattr value should differ from plaintext",
                        config.name, config.key_size
                    );
                }

                // Verify encrypted data is block-aligned
                assert_eq!(
                    encrypted.len() % config.block_size,
                    0,
                    "{} {}: Encrypted xattr value should be block-aligned",
                    config.name,
                    config.key_size
                );

                let decrypted = cipher
                    .decrypt_xattr_value(&encrypted, path_iv)
                    .unwrap_or_else(|_| {
                        panic!(
                            "{} {}: xattr value decryption failed for value of length {}",
                            config.name,
                            config.key_size,
                            value.len()
                        )
                    });

                assert_eq!(
                    decrypted, *value,
                    "{} {}: Decrypted xattr value should match original",
                    config.name, config.key_size
                );
            }

            // Test that name and value encryption use different IVs
            let test_data = b"test_data".to_vec();
            let encrypted_name = cipher
                .encrypt_xattr_name(&test_data, path_iv)
                .expect("name encryption failed");
            let encrypted_value = cipher
                .encrypt_xattr_value(&test_data, path_iv)
                .expect("value encryption failed");

            assert_ne!(
                encrypted_name, encrypted_value,
                "{} {}: Name and value encryption should produce different ciphertext",
                config.name, config.key_size
            );

            // Test MAC verification failure (tampered data)
            let mut tampered = encrypted_name.clone();
            tampered[0] ^= 0xFF; // Flip some bits
            assert!(
                cipher.decrypt_xattr_name(&tampered, path_iv).is_err(),
                "{} {}: Decryption should fail with tampered data",
                config.name,
                config.key_size
            );

            println!(
                "✓ {} {} xattr encryption/decryption: all tests passed",
                config.name, config.key_size
            );
        }
    }

    #[test]
    fn test_argon2id_key_derivation() {
        // Test basic Argon2id key derivation
        let password = "test_password";
        let salt = b"test_salt_123456";
        let key_len = 32;

        let key1 = SslCipher::derive_key_argon2id(
            password,
            salt,
            DEFAULT_ARGON2_MEMORY_COST,
            DEFAULT_ARGON2_TIME_COST,
            DEFAULT_ARGON2_PARALLELISM,
            key_len,
        )
        .expect("Argon2id derivation failed");

        assert_eq!(
            key1.len(),
            key_len,
            "Key length should match requested length"
        );

        // Derive with same parameters - should get same key
        let key2 = SslCipher::derive_key_argon2id(
            password,
            salt,
            DEFAULT_ARGON2_MEMORY_COST,
            DEFAULT_ARGON2_TIME_COST,
            DEFAULT_ARGON2_PARALLELISM,
            key_len,
        )
        .expect("Argon2id derivation failed");

        assert_eq!(key1, key2, "Same inputs should produce same key");

        // Different password should produce different key
        let key3 = SslCipher::derive_key_argon2id(
            "different_password",
            salt,
            DEFAULT_ARGON2_MEMORY_COST,
            DEFAULT_ARGON2_TIME_COST,
            DEFAULT_ARGON2_PARALLELISM,
            key_len,
        )
        .expect("Argon2id derivation failed");

        assert_ne!(
            key1, key3,
            "Different password should produce different key"
        );

        // Different salt should produce different key
        let key4 = SslCipher::derive_key_argon2id(
            password,
            b"different_salt__",
            DEFAULT_ARGON2_MEMORY_COST,
            DEFAULT_ARGON2_TIME_COST,
            DEFAULT_ARGON2_PARALLELISM,
            key_len,
        )
        .expect("Argon2id derivation failed");

        assert_ne!(key1, key4, "Different salt should produce different key");
    }

    #[test]
    fn test_argon2id_different_parameters() {
        let password = "test_password";
        let salt = b"test_salt_123456";
        let key_len = 32;

        // Base key with default parameters
        let key1 = SslCipher::derive_key_argon2id(
            password,
            salt,
            DEFAULT_ARGON2_MEMORY_COST,
            DEFAULT_ARGON2_TIME_COST,
            DEFAULT_ARGON2_PARALLELISM,
            key_len,
        )
        .expect("Argon2id derivation failed");

        // Different memory cost
        let key2 = SslCipher::derive_key_argon2id(
            password,
            salt,
            DEFAULT_ARGON2_MEMORY_COST * 2,
            DEFAULT_ARGON2_TIME_COST,
            DEFAULT_ARGON2_PARALLELISM,
            key_len,
        )
        .expect("Argon2id derivation failed");

        assert_ne!(
            key1, key2,
            "Different memory cost should produce different key"
        );

        // Different time cost
        let key3 = SslCipher::derive_key_argon2id(
            password,
            salt,
            DEFAULT_ARGON2_MEMORY_COST,
            DEFAULT_ARGON2_TIME_COST + 1,
            DEFAULT_ARGON2_PARALLELISM,
            key_len,
        )
        .expect("Argon2id derivation failed");

        assert_ne!(
            key1, key3,
            "Different time cost should produce different key"
        );

        // Different parallelism
        let key4 = SslCipher::derive_key_argon2id(
            password,
            salt,
            DEFAULT_ARGON2_MEMORY_COST,
            DEFAULT_ARGON2_TIME_COST,
            DEFAULT_ARGON2_PARALLELISM * 2,
            key_len,
        )
        .expect("Argon2id derivation failed");

        assert_ne!(
            key1, key4,
            "Different parallelism should produce different key"
        );
    }

    #[test]
    fn test_argon2id_various_key_lengths() {
        let password = "test_password";
        let salt = b"test_salt_123456";

        // Test various key lengths
        for key_len in [16, 24, 32, 48, 64] {
            let key = SslCipher::derive_key_argon2id(
                password,
                salt,
                DEFAULT_ARGON2_MEMORY_COST,
                DEFAULT_ARGON2_TIME_COST,
                DEFAULT_ARGON2_PARALLELISM,
                key_len,
            )
            .expect("Argon2id derivation failed");

            assert_eq!(
                key.len(),
                key_len,
                "Key length should match requested length"
            );
        }
    }

    #[test]
    fn test_phase0_pbkdf2_sha1_known_vector() {
        let password = "phase0-password";
        let salt = b"phase0-salt";
        let iterations = 12345;
        let key_len = 32;

        let derived =
            SslCipher::derive_key(password, salt, iterations, key_len).expect("PBKDF2 failed");

        let expected = [
            0x58, 0x2e, 0x2d, 0xf2, 0x0b, 0x8e, 0xee, 0x96, 0x5b, 0x27, 0xcb, 0xeb, 0x7c, 0x20,
            0xf4, 0xee, 0xd6, 0x93, 0x6c, 0xfb, 0x00, 0xed, 0xb8, 0x40, 0x32, 0xd2, 0xaf, 0x76,
            0x00, 0x3f, 0x21, 0x2d,
        ];

        assert_eq!(
            derived, expected,
            "PBKDF2-SHA1 output must remain stable for migration compatibility"
        );
    }

    #[test]
    fn test_phase0_mac64_no_iv_known_vector() {
        let key = b"phase0-mac-key";
        let data = b"phase0-mac-data";

        let mac = SslCipher::mac_64_no_iv_with_key(data, key).expect("mac_64_no_iv failed");

        // Invariant: this value depends on XOR folding of HMAC-SHA1 bytes 0..19
        // excluding the last digest byte, interpreted as a big-endian u64.
        let expected: u64 = 0x26d56564aa8adc97;
        assert_eq!(
            mac, expected,
            "MAC folding/endian behavior must remain unchanged"
        );
    }

    #[test]
    fn test_phase0_calculate_iv_uses_little_endian_seed() {
        let iface = Interface {
            name: "ssl/aes".to_string(),
            major: 3,
            minor: 0,
            age: 0,
        };
        let cipher = SslCipher::new(&iface, 256).expect("cipher init failed");

        let key = b"phase0-iv-key";
        let iv: Vec<u8> = (0u8..16u8).collect();
        let seed = 0x0123456789abcdefu64;

        let calculated = cipher
            .calculate_iv(seed, key, &iv)
            .expect("calculate_iv failed");

        let expected = [
            0x63, 0x6e, 0x50, 0x1d, 0x3b, 0xa1, 0xdf, 0xaa, 0x2c, 0x35, 0x26, 0x80, 0x14, 0x1b,
            0x8a, 0x21,
        ];
        let known_big_endian_seed = [
            0x87, 0xa9, 0x94, 0x3d, 0x39, 0x30, 0xc9, 0x09, 0xb2, 0x7c, 0xf2, 0x34, 0x01, 0x73,
            0x85, 0x1e,
        ];

        assert_eq!(
            calculated, expected,
            "IV derivation must use little-endian seed bytes"
        );
        assert_ne!(
            calculated, known_big_endian_seed,
            "Guardrail: changing to big-endian seed would break compatibility"
        );
    }

    #[test]
    fn test_phase0_key_wrap_known_vector_and_unwrap() {
        let iface = Interface {
            name: "ssl/aes".to_string(),
            major: 3,
            minor: 0,
            age: 0,
        };

        let cipher = SslCipher::new(&iface, 256).expect("cipher init failed");

        let user_key = [0x11u8; 32];
        let user_iv = [0x22u8; 16];
        let volume_key = [0x33u8; 48];

        let wrapped = cipher
            .encrypt_key(&volume_key, &user_key, &user_iv)
            .expect("encrypt_key failed");
        let unwrapped = cipher
            .decrypt_key(&wrapped, &user_key, &user_iv)
            .expect("decrypt_key failed");

        let expected_wrapped = [
            0x51, 0xd3, 0x9e, 0x05, 0x18, 0x27, 0x73, 0x54, 0xd7, 0xd8, 0x3e, 0xde, 0xe7, 0xed,
            0xc1, 0xab, 0x35, 0xed, 0x82, 0xf9, 0xeb, 0xe7, 0x98, 0xc6, 0x1a, 0x2a, 0xef, 0xd2,
            0x86, 0xba, 0xea, 0x89, 0x9f, 0x84, 0xb6, 0xc6, 0x7a, 0x77, 0xe3, 0xed, 0xc4, 0x5a,
            0x86, 0x39, 0x7f, 0xed, 0x8d, 0x76, 0xc7, 0xce, 0xd0, 0x15,
        ];

        assert_eq!(
            wrapped, expected_wrapped,
            "Key wrap output must remain stable for compatibility"
        );
        assert_eq!(unwrapped, volume_key);
    }

    #[test]
    fn test_phase0_filename_header_block_known_vectors() {
        let iface = Interface {
            name: "ssl/aes".to_string(),
            major: 3,
            minor: 0,
            age: 0,
        };

        let mut cipher = SslCipher::new(&iface, 256).expect("cipher init failed");

        let fs_key = [0x44u8; 32];
        let fs_iv = [0x55u8; 16];
        cipher.set_key(&fs_key, &fs_iv);

        let (encoded_name, name_iv_out) = cipher
            .encrypt_filename(b"phase0-name.txt", 0x0102030405060708u64)
            .expect("encrypt_filename failed");

        assert_eq!(
            encoded_name, "jXPDn,UNesj7jaXJf3CI3Z6",
            "Filename encoding must remain stable"
        );
        assert_eq!(
            name_iv_out, 0xc9c55c89023378c7u64,
            "Filename-derived next IV must remain stable"
        );

        let header = cipher
            .encrypt_header_with_iv(0x0f1e2d3c4b5a6978u64, 0x8877665544332211u64)
            .expect("encrypt_header_with_iv failed");
        assert_eq!(
            header,
            [0x68, 0xd9, 0xed, 0x17, 0x09, 0x3d, 0x81, 0xc1],
            "Header encryption with fixed IV must remain stable"
        );

        let mut full_block: Vec<u8> = (0u8..16u8).collect();
        cipher
            .encrypt_block_inplace(&mut full_block, 7, 0x1020304050607080u64, 16)
            .expect("encrypt full block failed");
        assert_eq!(
            full_block,
            [
                0xbb, 0xf9, 0x45, 0xd9, 0x40, 0x80, 0x05, 0x86, 0x7d, 0xdb, 0x2d, 0x64, 0x3c, 0x30,
                0xc9, 0x4d,
            ],
            "Full block encryption vector must remain stable"
        );

        let mut partial_block = b"phase0-partial".to_vec();
        cipher
            .encrypt_block_inplace(&mut partial_block, 7, 0x1020304050607080u64, 16)
            .expect("encrypt partial block failed");
        assert_eq!(
            partial_block,
            [
                0x68, 0x2b, 0x49, 0xcd, 0xce, 0xff, 0x7a, 0xf3, 0x12, 0x47, 0xe6, 0x5e, 0xc6, 0x1e,
            ],
            "Partial block encryption vector must remain stable"
        );
    }

    fn golden_hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{:02x}", x)).collect::<Vec<_>>().join("")
    }

    /// Frozen byte-exact output of every cipher primitive, per algorithm.
    struct GoldenVec {
        name: &'static str,
        key_size: i32,
        iv_size: usize,
        block_size: usize,
        block: &'static str,
        stream: &'static str,
        mac64: u64,
        mac16: u16,
        keywrap: &'static str,
        xattr: &'static str,
        header: &'static str,
        fn_stream: (&'static str, u64),
        fn_block: (&'static str, u64),
        gcmsiv: Option<(&'static str, &'static str)>, // (ciphertext, tag)
    }

    fn golden_vectors() -> Vec<GoldenVec> {
        vec![
            GoldenVec {
                name: "ssl/aes",
                key_size: 128,
                iv_size: 16,
                block_size: 16,
                block: "0e545ea9c5f15747250c75a0a169c027",
                stream: "5a8f519fa366a80a594b72384e1debee1889",
                mac64: 0x796fc611527fdeaf,
                mac16: 0x33ae,
                keywrap: "c2286e01741c8cc81730ea6869f71ee480c6d77df66d034835b6c6dee4bc1b271c407ffc",
                xattr: "bfacbc2fbfe49729dddf7a43620139d8db4cd712abd03940952dba6e1b65d2d3",
                header: "4b9eaf9496f34c31",
                fn_stream: ("HAhBXFgO-ttY6OnNGRepms6", 0xbd5ab40ab477aef4),
                fn_block: ("hl5JQgej,9kYgcxDF-ryZnBB", 0xaa6decc3b62a9df8),
                gcmsiv: Some((
                    "1af8c75974ad000eb7679f77a8599e94",
                    "65e513a57d02052e82ea589dcd13868a",
                )),
            },
            GoldenVec {
                name: "ssl/aes",
                key_size: 192,
                iv_size: 16,
                block_size: 16,
                block: "52894d269c184fe83816505ac6e79e97",
                stream: "2346481a59b94e8acb717d549faf900085b7",
                mac64: 0xb228259970c60a7c,
                mac16: 0xed0b,
                keywrap: "0c8b757d9ab9679685154aadd0f1da5e7a2b5eb6bb4c908a42342c70d915f50c3a6fb879cc2113b078c1eec7",
                xattr: "2c4810bee007af17a2261109bc6481f36f30dcb29a106a48291ffdf690ef41d8",
                header: "ecd9b775cfd269d8",
                fn_stream: ("kRzTZOUeeJtHMznFUHGThW1", 0xece7a75c8478bf34),
                fn_block: ("TWSVKM1vp3P-qffW,wFogCPa", 0x7b222820ddbf1155),
                gcmsiv: None,
            },
            GoldenVec {
                name: "ssl/aes",
                key_size: 256,
                iv_size: 16,
                block_size: 16,
                block: "596ded9194e8f9e54996471f24e83f71",
                stream: "0f72e309389272d7c4ed063f989707ed0840",
                mac64: 0xe96fedfbe9d01e9f,
                mac16: 0xf3db,
                keywrap: "640f3df0c1a3658e6b653621d11f81c0a9dcefe650e64f1d7bb97e00e6005753b5609f28eb72335bb10189908f2293a8f55d1a4a",
                xattr: "d06d8f524e0ba5073ff7675db613e16c4b0b469d29c4e927d289a80faebe8d2d",
                header: "8847ba99c1fe4af3",
                fn_stream: ("bSruiYfN2XN87rWyPct5h1,", 0x4b48afaedea29d33),
                fn_block: ("rjQCKbBNIDTsT3q,ljeJVmlQ", 0xddc790c64921f3eb),
                gcmsiv: Some((
                    "581bbefb557f3fa29ae07d6c72d521cf",
                    "b56459a4a675b3cbd9d77a3774af1910",
                )),
            },
            GoldenVec {
                name: "ssl/blowfish",
                key_size: 160,
                iv_size: 8,
                block_size: 8,
                block: "205718e3a4d25e38",
                stream: "adc95d0c19c3a33a5ec86b2b23b5f7b44ce0",
                mac64: 0x5897b7c2a87f5a2e,
                mac16: 0x1d04,
                keywrap: "b1219e3c4344164bf27eb88cc24bebdc7ab882cf2c1bd11d10d436c751338710",
                xattr: "98eb9f01fe46fb1abef281a3eaed759a274cc3f1ced3a1f3",
                header: "97e2b8026b49bc4a",
                fn_stream: ("tZdEVGDXFgxrv0ROywh15p6", 0xe812fa99a6abcdb9),
                fn_block: ("A3YjeNjXU6FDf2nXGrpLh,-I", 0x905537a2c0502be6),
                gcmsiv: None,
            },
        ]
    }

    /// Byte-exact regression oracle for every cipher primitive across all
    /// supported algorithms. These vectors lock the on-disk format: any drift
    /// during the Cipher-trait refactor must fail HERE rather than silently
    /// corrupt existing volumes. Vectors were generated from the in-tree
    /// implementation (see `golden_capture` harness in git history to
    /// regenerate if the format is ever intentionally changed).
    #[test]
    fn golden_cipher_vectors() {
        for v in golden_vectors() {
            let iface = Interface {
                name: v.name.to_string(),
                major: 3,
                minor: 0,
                age: 0,
            };
            let mut cipher = SslCipher::new(&iface, v.key_size).expect("new");
            let key_len = (v.key_size / 8) as usize;
            let key: Vec<u8> = (0..key_len).map(|i| (i as u8).wrapping_mul(0x11)).collect();
            let iv: Vec<u8> = (0..v.iv_size).map(|i| (i as u8).wrapping_mul(0x22)).collect();
            cipher.set_key(&key, &iv);
            let tag = format!("{}-{}", v.name, v.key_size);

            let mut blk: Vec<u8> = (0..v.block_size)
                .map(|i| (i as u8).wrapping_mul(0x33))
                .collect();
            cipher
                .block_encode(&mut blk, 0x1234567890abcdef, &key, &iv)
                .expect("block_encode");
            assert_eq!(golden_hex(&blk), v.block, "{}: block_encode drift", tag);

            let mut s = b"golden-stream-data".to_vec();
            cipher
                .stream_encode(&mut s, 0x1234567890abcdef, &key, &iv)
                .expect("stream_encode");
            assert_eq!(golden_hex(&s), v.stream, "{}: stream_encode drift", tag);

            let m64 = cipher
                .mac_64(b"golden-mac-data", 0x0102030405060708)
                .expect("mac64");
            assert_eq!(m64, v.mac64, "{}: mac_64 drift", tag);
            let (m16, _) = cipher
                .mac_16(b"golden-mac-data", 0x0102030405060708)
                .expect("mac16");
            assert_eq!(m16, v.mac16, "{}: mac_16 drift", tag);

            let vk: Vec<u8> = (0..key_len + v.iv_size)
                .map(|i| (i as u8).wrapping_mul(0x55))
                .collect();
            let ek = cipher.encrypt_key(&vk, &key, &iv).expect("encrypt_key");
            assert_eq!(golden_hex(&ek), v.keywrap, "{}: encrypt_key drift", tag);
            let unwrapped = cipher.decrypt_key(&ek, &key, &iv).expect("decrypt_key");
            assert_eq!(unwrapped, vk, "{}: key-wrap round-trip", tag);

            let xv = cipher
                .encrypt_xattr_value(b"golden-xattr-value", 0x1122334455667788)
                .expect("xattr");
            assert_eq!(golden_hex(&xv), v.xattr, "{}: encrypt_xattr_value drift", tag);

            let hdr = cipher
                .encrypt_header_with_iv(0x0f1e2d3c4b5a6978, 0x8877665544332211)
                .expect("header");
            assert_eq!(golden_hex(&hdr), v.header, "{}: encrypt_header_with_iv drift", tag);

            let (fn_s, fiv_s) = cipher
                .encrypt_filename(b"golden-name.txt", 0x0102030405060708)
                .expect("fn stream");
            assert_eq!(
                (fn_s.as_str(), fiv_s),
                v.fn_stream,
                "{}: filename stream-encoding drift",
                tag
            );

            let block_iface = Interface {
                name: "nameio/block".to_string(),
                major: 3,
                minor: 0,
                age: 0,
            };
            cipher.set_name_encoding(&block_iface);
            let (fn_b, fiv_b) = cipher
                .encrypt_filename(b"golden-name.txt", 0x0102030405060708)
                .expect("fn block");
            assert_eq!(
                (fn_b.as_str(), fiv_b),
                v.fn_block,
                "{}: filename block-encoding drift",
                tag
            );

            if let Some((exp_data, exp_tag)) = v.gcmsiv {
                let mut g: Vec<u8> = (0..v.block_size)
                    .map(|i| (i as u8).wrapping_mul(0x33))
                    .collect();
                let t = cipher
                    .encrypt_block_aes_gcm_siv_inplace(&mut g, 7, 0x1020304050607080)
                    .expect("gcmsiv");
                assert_eq!(golden_hex(&g), exp_data, "{}: gcm-siv ciphertext drift", tag);
                assert_eq!(golden_hex(&t), exp_tag, "{}: gcm-siv tag drift", tag);
            }
        }
    }
}
