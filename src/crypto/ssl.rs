use crate::config::Interface;
use anyhow::{Context, Result, anyhow};
use openssl::hash::MessageDigest;
use openssl::pkcs5::pbkdf2_hmac;
use openssl::rand::rand_bytes;
use openssl::symm::{Cipher as OpenSslCipher, Crypter, Mode};

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum NameEncoding {
    Stream,
    Block,
}

/// Main cryptographic wrapper for EncFS.
/// Handles key derivation, file content encryption (stream/block), and filename encryption.
pub struct SslCipher {
    pub iv_len: usize,
    cipher: OpenSslCipher,
    block_cipher: OpenSslCipher,
    key: Vec<u8>,
    iv: Vec<u8>,
    name_encoding: NameEncoding,
    iface: Interface,
}

impl SslCipher {
    pub fn new(iface: &Interface, key_size: i32) -> Result<Self> {
        let (cipher, block_cipher) = match (iface.name.as_str(), key_size) {
            ("ssl/aes", 128) => (
                OpenSslCipher::aes_128_cfb128(),
                OpenSslCipher::aes_128_cbc(),
            ),
            ("ssl/aes", 192) => (
                OpenSslCipher::aes_192_cfb128(),
                OpenSslCipher::aes_192_cbc(),
            ),
            ("ssl/aes", 256) => (
                OpenSslCipher::aes_256_cfb128(),
                OpenSslCipher::aes_256_cbc(),
            ),
            ("ssl/blowfish", _) => (OpenSslCipher::bf_cfb64(), OpenSslCipher::bf_cbc()),
            _ => return Err(anyhow!("Unsupported cipher: {} {}", iface.name, key_size)),
        };

        Ok(Self {
            iv_len: cipher.iv_len().unwrap_or(16),
            cipher,
            block_cipher,
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

    /// Derives the User Key from the password using PBKDF2-HMAC-SHA1.
    pub fn derive_key(
        password: &str,
        salt: &[u8],
        iterations: i32,
        key_len: usize,
    ) -> Result<Vec<u8>> {
        let mut key = vec![0u8; key_len];
        pbkdf2_hmac(
            password.as_bytes(),
            salt,
            iterations as usize,
            MessageDigest::sha1(),
            &mut key,
        )
        .context("PBKDF2 failed")?;
        Ok(key)
    }

    /// Legacy key derivation for EncFS cipher interface version 2.
    /// Uses BytesToKey algorithm with SHA1 and 16 rounds.
    pub fn derive_key_legacy(password: &str, key_len: usize, iv_len: usize) -> Result<Vec<u8>> {
        use openssl::hash::Hasher;

        // BytesToKey with SHA1, 16 rounds, no salt (matching SSL_Cipher.cpp line 452-454)
        let total_len = key_len + iv_len;
        let mut out = Vec::with_capacity(total_len);
        let mut digest = Vec::new();
        let pass_bytes = password.as_bytes();
        let sha1 = MessageDigest::sha1();

        while out.len() < total_len {
            let mut hasher = Hasher::new(sha1)?;
            if !digest.is_empty() {
                hasher.update(&digest)?;
            }
            hasher.update(pass_bytes)?;
            digest = hasher.finish()?.to_vec();

            // 16 additional rounds of hashing
            for _ in 1..16 {
                let mut hasher = Hasher::new(sha1)?;
                hasher.update(&digest)?;
                digest = hasher.finish()?.to_vec();
            }

            let to_copy = std::cmp::min(digest.len(), total_len - out.len());
            out.extend_from_slice(&digest[..to_copy]);
        }

        Ok(out)
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
        self.stream_decode(&mut data, checksum as u64, user_key, user_iv)?;

        // 3. Verify Checksum (MAC_32)
        let calculated_mac = Self::mac_32_with_key(&data, 0, user_key);

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
        self.stream_decode(&mut data, checksum as u64, user_key, user_iv)?;

        // 3. Verify Checksum (MAC_32) - legacy uses the user_key for HMAC
        let calculated_mac = Self::mac_32_with_key(&data, 0, user_key);

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
        let checksum = Self::mac_32_with_key(volume_key, 0, user_key);

        // 2. Encrypt using two-pass stream encoding (matching C++ streamEncode)
        let mut data = volume_key.to_vec();

        // Pass 1: shuffle, encrypt with iv64, flip, shuffle
        Self::shuffle_bytes(&mut data);
        let ivec1 = self.calculate_iv(checksum as u64, user_key, user_iv)?;
        let mut crypter1 = Crypter::new(self.cipher, Mode::Encrypt, user_key, Some(&ivec1))?;
        let mut out = vec![0u8; data.len() + self.cipher.block_size()];
        let count1 = crypter1.update(&data, &mut out)?;
        let rest1 = crypter1.finalize(&mut out[count1..])?;
        data.copy_from_slice(&out[..count1 + rest1]);
        Self::flip_bytes(&mut data);
        Self::shuffle_bytes(&mut data);

        // Pass 2: encrypt with iv64+1
        let ivec2 = self.calculate_iv(checksum as u64 + 1, user_key, user_iv)?;
        let mut crypter2 = Crypter::new(self.cipher, Mode::Encrypt, user_key, Some(&ivec2))?;
        let count2 = crypter2.update(&data, &mut out)?;
        let rest2 = crypter2.finalize(&mut out[count2..])?;
        data.copy_from_slice(&out[..count2 + rest2]);

        // 3. Prepend checksum (4 bytes, Big Endian)
        let mut result = Vec::with_capacity(4 + data.len());
        result.extend_from_slice(&checksum.to_be_bytes());
        result.extend_from_slice(&data);

        Ok(result)
    }

    // ... (stream_decode, calculate_iv, etc.)

    pub fn mac_16(&self, data: &[u8], iv: u64) -> (u16, u64) {
        let mac64 = self.mac_64(data, iv);
        let mac32 = ((mac64 >> 32) as u32) ^ (mac64 as u32);
        let mac16 = ((mac32 >> 16) as u16) ^ (mac32 as u16);
        (mac16, mac64)
    }

    pub fn mac_64_with_key(data: &[u8], iv: u64, key: &[u8]) -> u64 {
        if key.is_empty() {
            return 0;
        }

        let hmac_key = match openssl::pkey::PKey::hmac(key) {
            Ok(k) => k,
            Err(_) => return 0,
        };

        let mut signer = match openssl::sign::Signer::new(MessageDigest::sha1(), &hmac_key) {
            Ok(s) => s,
            Err(_) => return 0,
        };

        let _ = signer.update(data);
        let _ = signer.update(&iv.to_le_bytes());

        let hmac = match signer.sign_to_vec() {
            Ok(h) => h,
            Err(_) => return 0,
        };

        // EncFS XORs only mdLen - 1 bytes (skips last byte)!
        let mut h = [0u8; 8];
        for (i, &b) in hmac.iter().take(hmac.len() - 1).enumerate() {
            h[i % 8] ^= b;
        }

        // C++ constructs u64 Big Endian: value = (value << 8) | h[i]
        u64::from_be_bytes(h)
    }

    /// EncFS MAC_64 without chained IV.
    ///
    /// This matches the legacy C++ implementation when `chainedIV == nullptr`:
    /// HMAC-SHA1(key, data), XOR-reduce all but the last digest byte into 8 bytes,
    /// then interpret those 8 bytes as a big-endian `u64`.
    pub fn mac_64_no_iv_with_key(data: &[u8], key: &[u8]) -> u64 {
        if key.is_empty() {
            return 0;
        }

        let hmac_key = match openssl::pkey::PKey::hmac(key) {
            Ok(k) => k,
            Err(_) => return 0,
        };

        let mut signer = match openssl::sign::Signer::new(MessageDigest::sha1(), &hmac_key) {
            Ok(s) => s,
            Err(_) => return 0,
        };

        let _ = signer.update(data);

        let hmac = match signer.sign_to_vec() {
            Ok(h) => h,
            Err(_) => return 0,
        };

        // EncFS XORs only mdLen - 1 bytes (skips last byte)!
        let mut h = [0u8; 8];
        for (i, &b) in hmac.iter().take(hmac.len().saturating_sub(1)).enumerate() {
            h[i % 8] ^= b;
        }

        u64::from_be_bytes(h)
    }

    pub fn mac_64_no_iv(&self, data: &[u8]) -> u64 {
        Self::mac_64_no_iv_with_key(data, &self.key)
    }

    pub fn mac_32_with_key(data: &[u8], _iv: u64, key: &[u8]) -> u32 {
        // For key verification, EncFS does NOT include IV in HMAC.
        // So we need a version of mac_64 that doesn't include IV.

        if key.is_empty() {
            return 0;
        }

        let hmac_key = match openssl::pkey::PKey::hmac(key) {
            Ok(k) => k,
            Err(_) => return 0,
        };

        let mut signer = match openssl::sign::Signer::new(MessageDigest::sha1(), &hmac_key) {
            Ok(s) => s,
            Err(_) => return 0,
        };

        let _ = signer.update(data);
        // NO IV update here for key verification!

        let hmac = match signer.sign_to_vec() {
            Ok(h) => h,
            Err(_) => return 0,
        };

        // EncFS XORs only mdLen - 1 bytes (skips last byte)!
        let mut h = [0u8; 8];
        for (i, &b) in hmac.iter().take(hmac.len() - 1).enumerate() {
            h[i % 8] ^= b;
        }

        // C++ constructs u64 Big Endian: value = (value << 8) | h[i]
        let mac64 = u64::from_be_bytes(h);
        ((mac64 >> 32) as u32) ^ (mac64 as u32)
    }

    pub fn mac_64(&self, data: &[u8], iv: u64) -> u64 {
        Self::mac_64_with_key(data, iv, &self.key)
    }
    /// Standard stream decoding for EncFS.
    ///
    /// EncFS uses a unique "shuffle/flip" algorithm on top of the cipher
    /// to diffuse changes. It performs two passes of encryption/decryption
    /// with different IVs (derived from the block IV).
    pub fn stream_decode(&self, data: &mut [u8], iv64: u64, key: &[u8], iv: &[u8]) -> Result<()> {
        // EncFS does TWO passes of decryption:
        // Pass 1: setIVec(iv64 + 1), decrypt, unshuffle, flip
        // Pass 2: setIVec(iv64), decrypt, unshuffle

        // Pass 1
        let ivec1 = self.calculate_iv(iv64 + 1, key, iv)?;
        let mut crypter1 = Crypter::new(self.cipher, Mode::Decrypt, key, Some(&ivec1))?;

        let mut out = vec![0u8; data.len() + self.cipher.block_size()];
        let count = crypter1.update(data, &mut out)?;
        let rest = crypter1.finalize(&mut out[count..])?;
        data.copy_from_slice(&out[..count + rest]);

        Self::unshuffle_bytes(data);
        Self::flip_bytes(data);

        // Pass 2
        let ivec2 = self.calculate_iv(iv64, key, iv)?;
        let mut crypter2 = Crypter::new(self.cipher, Mode::Decrypt, key, Some(&ivec2))?;

        let count = crypter2.update(data, &mut out)?;
        let rest = crypter2.finalize(&mut out[count..])?;
        data.copy_from_slice(&out[..count + rest]);

        Self::unshuffle_bytes(data);
        Ok(())
    }

    fn calculate_iv(&self, seed: u64, key: &[u8], iv: &[u8]) -> Result<Vec<u8>> {
        if self.iface.major >= 3 {
            // HMAC(key, iv || seed)
            let hmac_key = openssl::pkey::PKey::hmac(key)?;
            let mut signer = openssl::sign::Signer::new(MessageDigest::sha1(), &hmac_key)?;

            signer.update(iv)?;
            signer.update(&seed.to_le_bytes())?; // EncFS uses little endian for seed in HMAC

            let hmac = signer.sign_to_vec()?;

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

        self.stream_decode(&mut name_data, name_iv, &self.key, &self.iv)?;

        // 4. Verify Checksum
        let (calculated_mac, new_iv) = self.mac_16(&name_data, iv);
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
        let bs = self.block_cipher.block_size();

        if block_data.len() < bs || block_data.len() % bs != 0 {
            return Err(anyhow!("Block data length invalid"));
        }

        // IV for name decryption is checksum ^ directory_iv
        let name_iv = (checksum as u64) ^ iv;
        self.block_decode(&mut block_data, name_iv, &self.key, &self.iv)?;

        // 4. Verify MAC (over decrypted data INCLUDING padding)
        // Fix Padding Oracle: Verify MAC *before* checking padding.

        let (calculated_mac, new_iv) = self.mac_16(&block_data, iv);
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

    fn encrypt_filename_stream(&self, plaintext_name: &[u8], iv: u64) -> Result<(String, u64)> {
        // 1. Calculate Checksum
        let (checksum, new_iv) = self.mac_16(plaintext_name, iv);

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
        let bs = self.block_cipher.block_size();

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
        let (checksum, new_iv) = self.mac_16(&data[2..], iv);

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
        let mut crypter = Crypter::new(self.cipher, Mode::Encrypt, key, Some(&ivec))?;

        let mut out = vec![0u8; data.len() + self.cipher.block_size()];
        let count = crypter.update(data, &mut out)?;
        let rest = crypter.finalize(&mut out[count..])?;
        data.copy_from_slice(&out[..count + rest]);

        // Pass 2: Flip -> Shuffle -> Encrypt(IV+1)
        Self::flip_bytes(data);
        Self::shuffle_bytes(data);

        let ivec2 = self.calculate_iv(iv64 + 1, key, iv)?;
        let mut crypter2 = Crypter::new(self.cipher, Mode::Encrypt, key, Some(&ivec2))?;

        let mut out2 = vec![0u8; data.len() + self.cipher.block_size()];
        let count2 = crypter2.update(data, &mut out2)?;
        let rest2 = crypter2.finalize(&mut out2[count2..])?;
        data.copy_from_slice(&out2[..count2 + rest2]);

        Ok(())
    }

    pub fn block_encode(&self, data: &mut [u8], iv64: u64, key: &[u8], iv: &[u8]) -> Result<()> {
        let ivec = self.calculate_iv(iv64, key, iv)?;

        let mut crypter = Crypter::new(self.block_cipher, Mode::Encrypt, key, Some(&ivec))?;

        crypter.pad(false);

        let mut out = vec![0u8; data.len() + self.block_cipher.block_size()];
        let count = crypter.update(data, &mut out)?;
        let rest = crypter.finalize(&mut out[count..])?;

        data.copy_from_slice(&out[..count + rest]);
        Ok(())
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
        self.stream_decode(header, external_iv, &self.key, &self.iv)?;

        let mut file_iv = 0u64;
        for &b in header.iter() {
            file_iv = (file_iv << 8) | (b as u64);
        }

        Ok(file_iv)
    }

    pub fn encrypt_header(&self, external_iv: u64) -> Result<(Vec<u8>, u64)> {
        // Generate random 64-bit file IV
        let mut file_iv_bytes = [0u8; 8];
        rand_bytes(&mut file_iv_bytes).context("Failed to generate random IV")?;

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

    pub fn decrypt_block_inplace(
        &self,
        data: &mut [u8],
        block_num: u64,
        file_iv: u64,
        block_size: u64,
    ) -> Result<()> {
        let iv64 = block_num ^ file_iv;

        if data.len() as u64 == block_size {
            // Full block - use block cipher (CBC)
            self.block_decode(data, iv64, &self.key, &self.iv)
        } else {
            // Partial block - use stream cipher (CFB)
            self.stream_decode(data, iv64, &self.key, &self.iv)
        }
    }
    pub fn block_decode(&self, data: &mut [u8], iv64: u64, key: &[u8], iv: &[u8]) -> Result<()> {
        let ivec = self.calculate_iv(iv64, key, iv)?;

        let mut crypter = Crypter::new(self.block_cipher, Mode::Decrypt, key, Some(&ivec))?;

        crypter.pad(false);

        let mut out = vec![0u8; data.len() + self.block_cipher.block_size()];
        let count = crypter.update(data, &mut out)?;
        let rest = crypter.finalize(&mut out[count..])?;

        data.copy_from_slice(&out[..count + rest]);
        Ok(())
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Interface;

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
}
