use crate::config::ConfigType;
use crate::crypto::ssl::SslCipher;
use std::io;

/// Fixed tag length for the V7 AES-GCM-SIV per-block format.
pub const AES_GCM_SIV_BLOCK_TAG_BYTES: u64 = 16;
/// Maximum legacy EncFS `blockMACBytes` value.
pub const LEGACY_MAX_BLOCK_MAC_BYTES: u64 = 8;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum BlockMode {
    #[default]
    Legacy,
    AesGcmSiv,
}

impl BlockMode {
    pub fn from_config(config_type: ConfigType, block_mac_bytes: u64) -> Self {
        if config_type == ConfigType::V7 && block_mac_bytes == AES_GCM_SIV_BLOCK_TAG_BYTES {
            Self::AesGcmSiv
        } else {
            Self::Legacy
        }
    }

    pub fn overhead_bytes(self, configured_block_mac_bytes: u64) -> u64 {
        match self {
            Self::Legacy => configured_block_mac_bytes,
            Self::AesGcmSiv => AES_GCM_SIV_BLOCK_TAG_BYTES,
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct BlockLayout {
    mode: BlockMode,
    block_size: u64,
    overhead_bytes: u64,
}

impl BlockLayout {
    pub fn new(
        mode: BlockMode,
        block_size: u64,
        configured_block_mac_bytes: u64,
    ) -> io::Result<Self> {
        let overhead_bytes = mode.overhead_bytes(configured_block_mac_bytes);
        if block_size <= overhead_bytes {
            return Err(io::Error::other(format!(
                "Invalid config: block_size ({block_size}) must be > block overhead ({overhead_bytes})"
            )));
        }
        Ok(Self {
            mode,
            block_size,
            overhead_bytes,
        })
    }

    pub fn mode(self) -> BlockMode {
        self.mode
    }

    pub fn block_size(self) -> u64 {
        self.block_size
    }

    pub fn overhead_bytes(self) -> u64 {
        self.overhead_bytes
    }

    pub fn data_size_per_block(self) -> u64 {
        self.block_size - self.overhead_bytes
    }

    pub fn logical_size_from_physical(self, physical_size: u64, header_size: u64) -> u64 {
        if physical_size < header_size {
            return 0;
        }

        let data_size = physical_size - header_size;
        if self.overhead_bytes == 0 {
            return data_size;
        }

        let full_blocks = data_size / self.block_size;
        let usage_in_full = full_blocks * self.data_size_per_block();

        let remainder = data_size % self.block_size;
        let usage_in_partial = remainder.saturating_sub(self.overhead_bytes);

        usage_in_full + usage_in_partial
    }

    pub fn physical_size_from_logical(self, logical_size: u64, header_size: u64) -> u64 {
        if logical_size == 0 {
            return header_size;
        }

        if self.overhead_bytes == 0 {
            return header_size + logical_size;
        }

        let data_block_size = self.data_size_per_block();
        let full_blocks = logical_size / data_block_size;
        let remainder = logical_size % data_block_size;

        let mut physical_size = header_size + full_blocks * self.block_size;
        if remainder > 0 {
            physical_size += remainder + self.overhead_bytes;
        }

        physical_size
    }
}

/// Encapsulates on-disk block metadata handling (legacy MAC prefix vs AEAD tag)
/// and per-block encryption/decryption.
pub struct BlockCodec<'a> {
    cipher: &'a SslCipher,
    layout: BlockLayout,
    ignore_legacy_mac_mismatch: bool,
}

impl<'a> BlockCodec<'a> {
    pub fn new(
        cipher: &'a SslCipher,
        layout: BlockLayout,
        ignore_legacy_mac_mismatch: bool,
    ) -> Self {
        Self {
            cipher,
            layout,
            ignore_legacy_mac_mismatch,
        }
    }

    pub fn decrypt_block(
        &self,
        block_num: u64,
        file_iv: u64,
        block_data: &mut [u8],
    ) -> io::Result<Vec<u8>> {
        match self.layout.mode() {
            BlockMode::Legacy => self.decrypt_legacy_block(block_num, file_iv, block_data),
            BlockMode::AesGcmSiv => self.decrypt_aes_gcm_siv_block(block_num, file_iv, block_data),
        }
    }

    pub fn encrypt_block(
        &self,
        block_num: u64,
        file_iv: u64,
        plaintext: &[u8],
    ) -> io::Result<Vec<u8>> {
        match self.layout.mode() {
            BlockMode::Legacy => self.encrypt_legacy_block(block_num, file_iv, plaintext),
            BlockMode::AesGcmSiv => self.encrypt_aes_gcm_siv_block(block_num, file_iv, plaintext),
        }
    }

    fn decrypt_legacy_block(
        &self,
        block_num: u64,
        file_iv: u64,
        block_data: &mut [u8],
    ) -> io::Result<Vec<u8>> {
        self.cipher
            .legacy_decrypt_block_inplace(block_data, block_num, file_iv, self.layout.block_size())
            .map_err(io::Error::other)?;

        let mac_len = self.layout.overhead_bytes() as usize;
        if mac_len == 0 {
            return Ok(block_data.to_owned());
        }

        if block_data.len() < mac_len {
            return Err(io::Error::other(format!(
                "Truncated block {block_num}: missing MAC bytes"
            )));
        }

        let stored_mac = &block_data[..mac_len];
        let plaintext = &block_data[mac_len..];

        let computed = self
            .cipher
            .mac_64_no_iv(plaintext)
            .map_err(io::Error::other)?;
        let mut tmp = computed;
        let mut fail: u8 = 0;
        for &stored in stored_mac {
            let expected = (tmp & 0xff) as u8;
            fail |= expected ^ stored;
            tmp >>= 8;
        }
        if fail != 0 && !self.ignore_legacy_mac_mismatch {
            return Err(io::Error::other(format!(
                "MAC mismatch in block {block_num}"
            )));
        }

        Ok(plaintext.to_vec())
    }

    fn decrypt_aes_gcm_siv_block(
        &self,
        block_num: u64,
        file_iv: u64,
        block_data: &mut [u8],
    ) -> io::Result<Vec<u8>> {
        let tag_len = AES_GCM_SIV_BLOCK_TAG_BYTES as usize;
        if block_data.len() < tag_len {
            return Err(io::Error::other(format!(
                "Truncated block {block_num}: missing AEAD tag"
            )));
        }

        let (tag, ciphertext) = block_data.split_at(tag_len);
        let mut plaintext = ciphertext.to_vec();
        self.cipher
            .decrypt_block_aes_gcm_siv_inplace(&mut plaintext, tag, block_num, file_iv)
            .map_err(io::Error::other)?;
        Ok(plaintext)
    }

    fn encrypt_legacy_block(
        &self,
        block_num: u64,
        file_iv: u64,
        plaintext: &[u8],
    ) -> io::Result<Vec<u8>> {
        let mac_len = self.layout.overhead_bytes() as usize;
        let mut block = Vec::with_capacity(mac_len + plaintext.len());
        block.resize(mac_len, 0);
        block.extend_from_slice(plaintext);

        if mac_len > 0 {
            let mac = self
                .cipher
                .mac_64_no_iv(plaintext)
                .map_err(io::Error::other)?;
            let mut tmp = mac;
            for byte in block.iter_mut().take(mac_len) {
                *byte = (tmp & 0xff) as u8;
                tmp >>= 8;
            }
        }

        self.cipher
            .encrypt_block_inplace(&mut block, block_num, file_iv, self.layout.block_size())
            .map_err(io::Error::other)?;

        Ok(block)
    }

    fn encrypt_aes_gcm_siv_block(
        &self,
        block_num: u64,
        file_iv: u64,
        plaintext: &[u8],
    ) -> io::Result<Vec<u8>> {
        // Allocate the output buffer with space for the tag and the ciphertext.
        let tag_len = AES_GCM_SIV_BLOCK_TAG_BYTES as usize;
        let mut out = vec![0u8; tag_len + plaintext.len()];
        out[tag_len..].copy_from_slice(plaintext);

        let tag = self
            .cipher
            .encrypt_block_aes_gcm_siv_inplace(&mut out[tag_len..], block_num, file_iv)
            .map_err(io::Error::other)?;

        out[..tag_len].copy_from_slice(&tag);
        Ok(out)
    }
}
