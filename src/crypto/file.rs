use crate::crypto::block::{BlockCodec, BlockLayout, BlockMode};
use crate::crypto::ssl::SslCipher;
use std::io;
use std::os::unix::fs::FileExt;

pub trait ReadAt {
    fn read_at(&self, buf: &mut [u8], offset: u64) -> io::Result<usize>;
}

impl<T: FileExt> ReadAt for T {
    fn read_at(&self, buf: &mut [u8], offset: u64) -> io::Result<usize> {
        FileExt::read_at(self, buf, offset)
    }
}

pub trait WriteAt {
    fn write_at(&self, buf: &[u8], offset: u64) -> io::Result<usize>;
}

impl<T: FileExt> WriteAt for T {
    fn write_at(&self, buf: &[u8], offset: u64) -> io::Result<usize> {
        FileExt::write_at(self, buf, offset)
    }
}

/// Trait for querying file length.
/// Needed to detect writes past EOF that would create sparse holes.
pub trait FileLen {
    fn file_len(&self) -> io::Result<u64>;
}

impl FileLen for std::fs::File {
    fn file_len(&self) -> io::Result<u64> {
        self.metadata().map(|m| m.len())
    }
}

/// Decodes encrypted files.
///
/// Handles block-by-block decryption and verification for both legacy EncFS
/// block-MAC format and V7 AES-GCM-SIV block format.
pub struct FileDecoder<'a, F: ReadAt> {
    cipher: &'a SslCipher,
    file: &'a F,
    file_iv: u64,
    header_size: u64,
    block_size: u64, // On-disk block size from config (e.g., 1024)
    block_mac_bytes: u64,
    block_mode: BlockMode,
    ignore_mac_mismatch: bool,
}

impl<'a, F: ReadAt> FileDecoder<'a, F> {
    pub fn new(
        cipher: &'a SslCipher,
        file: &'a F,
        file_iv: u64,
        header_size: u64,
        block_size: u64,
        block_mac_bytes: u64,
        ignore_mac_mismatch: bool,
    ) -> Self {
        Self::new_with_mode(
            cipher,
            file,
            file_iv,
            header_size,
            block_size,
            block_mac_bytes,
            BlockMode::Legacy,
            ignore_mac_mismatch,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn new_with_mode(
        cipher: &'a SslCipher,
        file: &'a F,
        file_iv: u64,
        header_size: u64,
        block_size: u64,
        block_mac_bytes: u64,
        block_mode: BlockMode,
        ignore_mac_mismatch: bool,
    ) -> Self {
        Self {
            cipher,
            file,
            file_iv,
            header_size,
            block_size,
            block_mac_bytes,
            block_mode,
            ignore_mac_mismatch,
        }
    }

    /// Calculates the logical file size (plain text size) from the physical
    /// on-disk size.
    ///
    /// EncFS adds a header (8 bytes) and potentially MAC bytes to every block.
    /// This function reverses that logic to determine how many actual data bytes
    /// are in the file.
    pub fn calculate_logical_size(
        physical_size: u64,
        header_size: u64,
        block_size: u64,
        block_mac_bytes: u64,
    ) -> u64 {
        Self::calculate_logical_size_with_mode(
            physical_size,
            header_size,
            block_size,
            block_mac_bytes,
            BlockMode::Legacy,
        )
    }

    pub fn calculate_logical_size_with_mode(
        physical_size: u64,
        header_size: u64,
        block_size: u64,
        block_mac_bytes: u64,
        block_mode: BlockMode,
    ) -> u64 {
        match BlockLayout::new(block_mode, block_size, block_mac_bytes) {
            Ok(layout) => layout.logical_size_from_physical(physical_size, header_size),
            Err(_) => 0,
        }
    }

    /// Reads and decrypts data from the encrypted file at the specified logical offset.
    ///
    /// This method manages:
    /// 1. Mapping logical offset/size to physical blocks
    /// 2. Reading full blocks from disk (alignment is required for conversion)
    /// 3. Decrypting blocks (handling full vs partial blocks)
    /// 4. Stripping MAC bytes if present
    /// 5. Copying the requested slice of decrypted data to the buffer
    pub fn read_at(&self, buf: &mut [u8], offset: u64) -> io::Result<usize> {
        let layout = BlockLayout::new(self.block_mode, self.block_size, self.block_mac_bytes)?;
        let codec = BlockCodec::new(self.cipher, layout, self.ignore_mac_mismatch);
        let size = buf.len() as u64;
        let mut bytes_remaining = size;
        let mut total_read = 0;
        let mut current_offset = offset;

        let data_block_size = layout.data_size_per_block();

        let block_size_usize = usize::try_from(layout.block_size())
            .map_err(|_| io::Error::other("block_size too large"))?;

        let mut block_data = vec![0u8; block_size_usize];

        while bytes_remaining > 0 {
            // Calculate which data block we need
            let block_num = current_offset / data_block_size;
            let block_offset = current_offset % data_block_size;
            let bytes_to_read_in_block =
                std::cmp::min(bytes_remaining, data_block_size - block_offset);

            // Read full on-disk block (MAC + encrypted data = block_size bytes)
            let read_offset = self.header_size + block_num * layout.block_size();

            // Ensure buffer is sized correctly for max possible read
            block_data.resize(block_size_usize, 0);

            match self.file.read_at(&mut block_data, read_offset) {
                Ok(bytes_read) => {
                    if bytes_read == 0 {
                        break; // EOF
                    }
                    block_data.truncate(bytes_read);

                    let plaintext =
                        codec.decrypt_block(block_num, self.file_iv, &mut block_data)?;

                    // Copy requested part
                    let start = block_offset as usize;
                    let end =
                        std::cmp::min(start + bytes_to_read_in_block as usize, plaintext.len());

                    if start < plaintext.len() {
                        let dest_start = total_read;
                        let dest_end = total_read + (end - start);
                        buf[dest_start..dest_end].copy_from_slice(&plaintext[start..end]);

                        let copied = end - start;
                        total_read += copied;
                        current_offset += copied as u64;
                        bytes_remaining -= copied as u64;
                    } else {
                        break; // EOF reached within block
                    }
                }
                Err(e) => return Err(e),
            }
        }

        Ok(total_read)
    }
}

/// Encodes encrypted files (writes).
pub struct FileEncoder<'a, F: ReadAt + WriteAt + FileLen> {
    cipher: &'a SslCipher,
    file: &'a F,
    file_iv: u64,
    header_size: u64,
    block_size: u64,
    block_mac_bytes: u64,
    block_mode: BlockMode,
}

impl<'a, F: ReadAt + WriteAt + FileLen> FileEncoder<'a, F> {
    pub fn new(
        cipher: &'a SslCipher,
        file: &'a F,
        file_iv: u64,
        header_size: u64,
        block_size: u64,
        block_mac_bytes: u64,
    ) -> Self {
        Self::new_with_mode(
            cipher,
            file,
            file_iv,
            header_size,
            block_size,
            block_mac_bytes,
            BlockMode::Legacy,
        )
    }

    pub fn new_with_mode(
        cipher: &'a SslCipher,
        file: &'a F,
        file_iv: u64,
        header_size: u64,
        block_size: u64,
        block_mac_bytes: u64,
        block_mode: BlockMode,
    ) -> Self {
        Self {
            cipher,
            file,
            file_iv,
            header_size,
            block_size,
            block_mac_bytes,
            block_mode,
        }
    }

    pub fn calculate_physical_size(
        logical_size: u64,
        header_size: u64,
        block_size: u64,
        block_mac_bytes: u64,
    ) -> u64 {
        Self::calculate_physical_size_with_mode(
            logical_size,
            header_size,
            block_size,
            block_mac_bytes,
            BlockMode::Legacy,
        )
    }

    pub fn calculate_physical_size_with_mode(
        logical_size: u64,
        header_size: u64,
        block_size: u64,
        block_mac_bytes: u64,
        block_mode: BlockMode,
    ) -> u64 {
        match BlockLayout::new(block_mode, block_size, block_mac_bytes) {
            Ok(layout) => layout.physical_size_from_logical(logical_size, header_size),
            Err(_) => header_size,
        }
    }

    pub fn write_at(&self, buf: &[u8], offset: u64) -> io::Result<usize> {
        let layout = BlockLayout::new(self.block_mode, self.block_size, self.block_mac_bytes)?;
        let data_block_size = layout.data_size_per_block();
        let physical_block_size = layout.block_size();
        let physical_block_size_usize = usize::try_from(physical_block_size)
            .map_err(|_| io::Error::other("block_size too large"))?;

        // Detect and fill gaps to prevent sparse files.
        // Sparse files cause MAC verification failures because reading a block
        // that partially spans a hole returns zeros that weren't properly encrypted.
        let physical_size = self.file.file_len()?;
        let current_logical_size = FileDecoder::<F>::calculate_logical_size_with_mode(
            physical_size,
            self.header_size,
            self.block_size,
            self.block_mac_bytes,
            self.block_mode,
        );

        if offset > current_logical_size {
            // Fill the gap with encrypted zeros
            const CHUNK_SIZE: u64 = crate::constants::FILE_BUFFER_SIZE as u64;
            let gap_size = offset - current_logical_size;
            let mut remaining_gap = gap_size;
            let zeros = vec![0u8; std::cmp::min(remaining_gap, CHUNK_SIZE) as usize];
            let mut gap_offset = current_logical_size;

            while remaining_gap > 0 {
                let write_len = std::cmp::min(remaining_gap, CHUNK_SIZE);
                // Recursively call write_at to fill the gap with properly encrypted zeros
                self.write_at_internal(
                    &zeros[..write_len as usize],
                    gap_offset,
                    layout,
                    data_block_size,
                    physical_block_size,
                    physical_block_size_usize,
                )?;
                remaining_gap -= write_len;
                gap_offset += write_len;
            }
        }

        // Now write the actual data
        self.write_at_internal(
            buf,
            offset,
            layout,
            data_block_size,
            physical_block_size,
            physical_block_size_usize,
        )
    }

    fn write_at_internal(
        &self,
        buf: &[u8],
        offset: u64,
        layout: BlockLayout,
        data_block_size: u64,
        physical_block_size: u64,
        physical_block_size_usize: usize,
    ) -> io::Result<usize> {
        let codec = BlockCodec::new(self.cipher, layout, false);
        let size = buf.len() as u64;
        let mut bytes_remaining = size;
        let mut total_written = 0;
        let mut current_offset = offset;

        let mut on_disk_block = Vec::with_capacity(physical_block_size_usize);

        while bytes_remaining > 0 {
            let block_num = current_offset / data_block_size;
            let block_offset = current_offset % data_block_size;
            let bytes_to_write_in_block =
                std::cmp::min(bytes_remaining, data_block_size - block_offset);

            let read_offset = self.header_size + block_num * physical_block_size;
            let mut plaintext_block = Vec::new();

            // RMW: Enable read if we are not overwriting the entire data portion of the block
            let is_full_write = block_offset == 0 && bytes_to_write_in_block == data_block_size;
            if !is_full_write {
                on_disk_block.resize(physical_block_size_usize, 0);
                match self.file.read_at(&mut on_disk_block, read_offset) {
                    Ok(n) => {
                        if n > 0 {
                            let existing_payload_len =
                                n.saturating_sub(layout.overhead_bytes() as usize);
                            if block_offset == 0
                                && (bytes_to_write_in_block as usize) >= existing_payload_len
                            {
                                // Entire currently stored payload will be overwritten; no need to
                                // decrypt potentially truncated/corrupt bytes for read-modify-write.
                                plaintext_block.clear();
                            } else {
                                on_disk_block.truncate(n);
                                plaintext_block = codec
                                    .decrypt_block(block_num, self.file_iv, &mut on_disk_block)
                                    .map_err(|e| {
                                        io::Error::other(format!(
                                            "Decrypt failed during RMW: {}",
                                            e
                                        ))
                                    })?;
                            }
                        }
                    }
                    Err(e) => return Err(e),
                }
            }

            // Extend buffer if necessary to cover the new write range
            let required_len = (block_offset + bytes_to_write_in_block) as usize;
            if plaintext_block.len() < required_len {
                plaintext_block.resize(required_len, 0);
            }

            // Copy new data
            let src_start = total_written;
            let src_end = src_start + bytes_to_write_in_block as usize;
            let dst_start = block_offset as usize;
            let dst_end = dst_start + bytes_to_write_in_block as usize;

            plaintext_block[dst_start..dst_end].copy_from_slice(&buf[src_start..src_end]);
            let encrypted_block = codec.encrypt_block(block_num, self.file_iv, &plaintext_block)?;

            // Write
            self.file.write_at(&encrypted_block, read_offset)?;

            let written = bytes_to_write_in_block;
            total_written += written as usize;
            current_offset += written;
            bytes_remaining -= written;
        }

        Ok(total_written)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    #[derive(Clone)]
    struct MockFile {
        data: Arc<Mutex<Vec<u8>>>,
    }

    impl MockFile {
        fn new(initial_data: Vec<u8>) -> Self {
            Self {
                data: Arc::new(Mutex::new(initial_data)),
            }
        }

        fn get_data(&self) -> Vec<u8> {
            self.data.lock().unwrap().clone()
        }
    }

    impl ReadAt for MockFile {
        fn read_at(&self, buf: &mut [u8], offset: u64) -> io::Result<usize> {
            let data = self.data.lock().unwrap();
            let offset = offset as usize;
            if offset >= data.len() {
                return Ok(0);
            }
            let len = std::cmp::min(buf.len(), data.len() - offset);
            buf[..len].copy_from_slice(&data[offset..offset + len]);
            Ok(len)
        }
    }

    impl WriteAt for MockFile {
        fn write_at(&self, buf: &[u8], offset: u64) -> io::Result<usize> {
            let mut data = self.data.lock().unwrap();
            let offset = offset as usize;
            let end = offset + buf.len();
            if end > data.len() {
                data.resize(end, 0);
            }
            data[offset..end].copy_from_slice(buf);
            Ok(buf.len())
        }
    }

    impl FileLen for MockFile {
        fn file_len(&self) -> io::Result<u64> {
            Ok(self.data.lock().unwrap().len() as u64)
        }
    }

    #[test]
    fn test_calculate_logical_size() {
        // No MAC
        assert_eq!(
            FileDecoder::<MockFile>::calculate_logical_size(108, 8, 100, 0),
            100
        );
        assert_eq!(
            FileDecoder::<MockFile>::calculate_logical_size(8, 8, 100, 0),
            0
        );
        assert_eq!(
            FileDecoder::<MockFile>::calculate_logical_size(4, 8, 100, 0),
            0
        );

        // With MAC (8 bytes per 64 byte *on-disk* block)
        let block_size = 64; // physical
        let block_mac_bytes = 8;
        let header_size = 8;
        // Plaintext per full block = 56

        // 1 full block
        // Physical: 8 (header) + 64 (block) = 72
        // Logical: 56
        assert_eq!(
            FileDecoder::<MockFile>::calculate_logical_size(
                72,
                header_size,
                block_size,
                block_mac_bytes
            ),
            56
        );

        // 1.5 blocks
        // Physical: 8 + 64 + (8 MAC + 28 data) = 8 + 64 + 36 = 108
        // Logical: 56 + 28 = 84
        assert_eq!(
            FileDecoder::<MockFile>::calculate_logical_size(
                108,
                header_size,
                block_size,
                block_mac_bytes
            ),
            84
        );

        // Just header + tiny bit (MAC only)
        // Physical: 8 + 4 (MAC part of first block)
        // Logical: 0 (since it's all MAC)
        assert_eq!(
            FileDecoder::<MockFile>::calculate_logical_size(
                12,
                header_size,
                block_size,
                block_mac_bytes
            ),
            0
        );

        // --- AES-GCM-SIV Mode ---
        let siv_mac_bytes = crate::crypto::block::AES_GCM_SIV_BLOCK_TAG_BYTES; // 16 bytes
        let siv_mode = BlockMode::AesGcmSiv;
        // Plaintext per full block = 64 - 16 = 48

        // 1 full block
        // Physical: 8 (header) + 64 (block) = 72
        // Logical: 48
        assert_eq!(
            FileDecoder::<MockFile>::calculate_logical_size_with_mode(
                72,
                header_size,
                block_size,
                siv_mac_bytes,
                siv_mode
            ),
            48
        );

        // 1.5 blocks
        // Physical: 8 + 64 + (16 MAC + 24 data) = 8 + 64 + 40 = 112
        // Logical: 48 + 24 = 72
        assert_eq!(
            FileDecoder::<MockFile>::calculate_logical_size_with_mode(
                112,
                header_size,
                block_size,
                siv_mac_bytes,
                siv_mode
            ),
            72
        );
    }

    #[test]
    fn test_calculate_physical_size() {
        let header_size = 8;
        let block_size = 64;

        // No MAC
        assert_eq!(
            FileEncoder::<MockFile>::calculate_physical_size(100, 8, 100, 0),
            108
        );
        assert_eq!(
            FileEncoder::<MockFile>::calculate_physical_size(0, 8, 100, 0),
            8
        );

        // With MAC (8 bytes)
        let block_mac_bytes = 8;
        // data_block_size = 56

        // 0 bytes -> just header
        assert_eq!(
            FileEncoder::<MockFile>::calculate_physical_size(
                0,
                header_size,
                block_size,
                block_mac_bytes
            ),
            8
        );

        // 56 bytes (1 full block) -> header + 64
        assert_eq!(
            FileEncoder::<MockFile>::calculate_physical_size(
                56,
                header_size,
                block_size,
                block_mac_bytes
            ),
            72
        );

        // 57 bytes (1 full + 1 partial) -> header + 64 + (8 MAC + 1 byte) = 72 + 9 = 81
        assert_eq!(
            FileEncoder::<MockFile>::calculate_physical_size(
                57,
                header_size,
                block_size,
                block_mac_bytes
            ),
            81
        );

        // --- AES-GCM-SIV Mode ---
        let siv_mac_bytes = crate::crypto::block::AES_GCM_SIV_BLOCK_TAG_BYTES; // 16 bytes
        let siv_mode = BlockMode::AesGcmSiv;
        // data_block_size = 48

        // 48 bytes (1 full block) -> header + 64
        assert_eq!(
            FileEncoder::<MockFile>::calculate_physical_size_with_mode(
                48,
                header_size,
                block_size,
                siv_mac_bytes,
                siv_mode
            ),
            72
        );

        // 49 bytes (1 full + 1 partial) -> header + 64 + (16 MAC + 1 byte) = 72 + 17 = 89
        assert_eq!(
            FileEncoder::<MockFile>::calculate_physical_size_with_mode(
                49,
                header_size,
                block_size,
                siv_mac_bytes,
                siv_mode
            ),
            89
        );
    }

    fn create_cipher() -> SslCipher {
        // Use a simple cipher for testing
        let iface = crate::config::Interface {
            name: "ssl/aes".to_string(),
            major: 3,
            minor: 0,
            age: 0,
        };
        // 128-bit key
        SslCipher::new(&iface, 128).expect("Failed to create cipher")
    }

    #[test]
    fn test_read_write_roundtrip_no_mac() {
        let mut cipher = create_cipher();
        // Setup key
        let key = vec![0u8; 16];
        let iv = vec![0u8; 16]; // IV length depends on cipher, AES usually 16?
        // SslCipher handles IV length internally, we just pass slice.
        // Actually SslCipher wrapper expects key/IV set via set_key
        cipher.set_key(&key, &iv);

        let file_iv = 123456789;
        let header_size = 8;
        let block_size = 64;
        let block_mac_bytes = 0;

        let mock_file = MockFile::new(vec![0u8; header_size as usize]); // Start with just header space

        let encoder = FileEncoder::new(
            &cipher,
            &mock_file,
            file_iv,
            header_size,
            block_size,
            block_mac_bytes,
        );

        let data = b"Hello, World! This is a test of the EncFS file encryption system.";
        let written = encoder.write_at(data, 0).expect("Write failed");
        assert_eq!(written, data.len());

        // Verify physical size
        // Length 65. Block size 64.
        // 1 full block (64) + 1 partial block (1)
        // Physical size: 8 + 64 + 1 = 73
        assert_eq!(mock_file.get_data().len(), 73);

        let decoder = FileDecoder::new(
            &cipher,
            &mock_file,
            file_iv,
            header_size,
            block_size,
            block_mac_bytes,
            false,
        );

        let mut buf = vec![0u8; data.len()];
        let read = decoder.read_at(&mut buf, 0).expect("Read failed");
        assert_eq!(read, data.len());
        assert_eq!(&buf, data);
    }

    #[test]
    fn test_read_write_roundtrip_with_mac() {
        let mut cipher = create_cipher();
        let key = vec![0u8; 16]; // AES-128 needs 16 bytes
        // But let's provide enough bytes.
        let iv = vec![0u8; 32];
        cipher.set_key(&key, &iv);

        let file_iv = 987654321;
        let header_size = 8;
        let block_size = 64;
        let block_mac_bytes = 8; // Enable MAC

        let mock_file = MockFile::new(vec![0u8; header_size as usize]);

        let encoder = FileEncoder::new(
            &cipher,
            &mock_file,
            file_iv,
            header_size,
            block_size,
            block_mac_bytes,
        );

        // Data: "A" * 100.
        // data_block_size = 64 - 8 = 56.
        // 100 bytes = 1 full block (56) + 1 partial block (44).
        let data = vec![b'A'; 100];
        encoder.write_at(&data, 0).expect("Write failed");

        // Verify physical size
        // Header: 8
        // Block 0: 64 (8 MAC + 56 Data)
        // Block 1: 8 MAC + 44 Data = 52
        // Total: 8 + 64 + 52 = 124
        assert_eq!(mock_file.get_data().len(), 124);

        let decoder = FileDecoder::new(
            &cipher,
            &mock_file,
            file_iv,
            header_size,
            block_size,
            block_mac_bytes,
            false,
        );

        let mut buf = vec![0u8; 100];
        let read = decoder.read_at(&mut buf, 0).expect("Read failed");
        assert_eq!(read, 100);
        assert_eq!(buf, data);
    }

    #[test]
    fn test_mac_verification_failure() {
        let mut cipher = create_cipher();
        let key = vec![0u8; 16];
        let iv = vec![0u8; 32];
        cipher.set_key(&key, &iv);

        let file_iv = 11111;
        let header_size = 8;
        let block_size = 64;
        let block_mac_bytes = 8;

        let mock_file = MockFile::new(vec![0u8; header_size as usize]);
        let encoder = FileEncoder::new(
            &cipher,
            &mock_file,
            file_iv,
            header_size,
            block_size,
            block_mac_bytes,
        );
        let data = b"Sensitive Data";
        encoder.write_at(data, 0).expect("Write failed");

        // Tamper with the data (flip a bit in the encrypted content)
        // Header is 8 bytes. MAC is 8 bytes. Data follows.
        // Let's modify byte at offset 8 + 8 = 16 (first byte of encrypted data)
        {
            let mut file_data = mock_file.data.lock().unwrap();
            file_data[16] ^= 0x01;
        }

        let decoder = FileDecoder::new(
            &cipher,
            &mock_file,
            file_iv,
            header_size,
            block_size,
            block_mac_bytes,
            false,
        );
        let mut buf = vec![0u8; data.len()];
        let err = decoder.read_at(&mut buf, 0).expect_err("Should fail MAC");
        assert!(err.to_string().contains("MAC mismatch"));
    }

    #[test]
    fn test_read_write_roundtrip_with_aes_gcm_siv_mode() {
        let mut cipher = create_cipher();
        let key = vec![0u8; 16];
        let iv = vec![0u8; 16];
        cipher.set_key(&key, &iv);

        let file_iv = 33333;
        let header_size = 8;
        let block_size = 64;
        let block_mac_bytes = crate::crypto::block::AES_GCM_SIV_BLOCK_TAG_BYTES;

        let mock_file = MockFile::new(vec![0u8; header_size as usize]);
        let encoder = FileEncoder::new_with_mode(
            &cipher,
            &mock_file,
            file_iv,
            header_size,
            block_size,
            block_mac_bytes,
            BlockMode::AesGcmSiv,
        );

        let data = vec![b'Z'; 100];
        encoder.write_at(&data, 0).expect("Write failed");

        assert_eq!(
            mock_file.get_data().len() as u64,
            FileEncoder::<MockFile>::calculate_physical_size_with_mode(
                data.len() as u64,
                header_size,
                block_size,
                block_mac_bytes,
                BlockMode::AesGcmSiv
            )
        );

        let decoder = FileDecoder::new_with_mode(
            &cipher,
            &mock_file,
            file_iv,
            header_size,
            block_size,
            block_mac_bytes,
            BlockMode::AesGcmSiv,
            false,
        );

        let mut buf = vec![0u8; data.len()];
        let read = decoder.read_at(&mut buf, 0).expect("Read failed");
        assert_eq!(read, data.len());
        assert_eq!(buf, data);
    }

    #[test]
    fn test_aes_gcm_siv_tag_verification_failure() {
        let mut cipher = create_cipher();
        let key = vec![0u8; 16];
        let iv = vec![0u8; 16];
        cipher.set_key(&key, &iv);

        let file_iv = 44444;
        let header_size = 8;
        let block_size = 64;
        let block_mac_bytes = crate::crypto::block::AES_GCM_SIV_BLOCK_TAG_BYTES;

        let mock_file = MockFile::new(vec![0u8; header_size as usize]);
        let encoder = FileEncoder::new_with_mode(
            &cipher,
            &mock_file,
            file_iv,
            header_size,
            block_size,
            block_mac_bytes,
            BlockMode::AesGcmSiv,
        );
        let data = b"Authenticated block payload";
        encoder.write_at(data, 0).expect("Write failed");

        // Tamper with first tag byte after file header.
        {
            let mut file_data = mock_file.data.lock().unwrap();
            file_data[header_size as usize] ^= 0x01;
        }

        let decoder = FileDecoder::new_with_mode(
            &cipher,
            &mock_file,
            file_iv,
            header_size,
            block_size,
            block_mac_bytes,
            BlockMode::AesGcmSiv,
            false,
        );
        let mut buf = vec![0u8; data.len()];
        let err = decoder
            .read_at(&mut buf, 0)
            .expect_err("Should fail AEAD verification");
        assert!(err.to_string().contains("tag verification failed"));
    }

    #[test]
    fn test_read_modify_write() {
        let mut cipher = create_cipher();
        let key = vec![0u8; 16];
        let iv = vec![0u8; 32];
        cipher.set_key(&key, &iv);

        let file_iv = 22222;
        let header_size = 8;
        let block_size = 64;
        let block_mac_bytes = 8;

        let mock_file = MockFile::new(vec![0u8; header_size as usize]);
        let encoder = FileEncoder::new(
            &cipher,
            &mock_file,
            file_iv,
            header_size,
            block_size,
            block_mac_bytes,
        );

        // Write initial data: "AAAA..." (56 bytes - full block)
        let initial_data = vec![b'A'; 56];
        encoder.write_at(&initial_data, 0).expect("Write init");

        // Modify middle: write "BBB" at offset 10
        let overwrite = b"BBB";
        encoder.write_at(overwrite, 10).expect("Write overwrite");

        // Read back
        let decoder = FileDecoder::new(
            &cipher,
            &mock_file,
            file_iv,
            header_size,
            block_size,
            block_mac_bytes,
            false,
        );
        let mut buf = vec![0u8; 56];
        decoder.read_at(&mut buf, 0).expect("Read back");

        let mut expected = initial_data.clone();
        expected[10..13].copy_from_slice(overwrite);

        assert_eq!(buf, expected);
    }

    #[test]
    fn test_read_modify_write_with_aes_gcm_siv_mode() {
        let mut cipher = create_cipher();
        let key = vec![0u8; 16];
        let iv = vec![0u8; 16];
        cipher.set_key(&key, &iv);

        let file_iv = 55555;
        let header_size = 8;
        let block_size = 64;
        let block_mac_bytes = crate::crypto::block::AES_GCM_SIV_BLOCK_TAG_BYTES; // 16

        let mock_file = MockFile::new(vec![0u8; header_size as usize]);
        let encoder = FileEncoder::new_with_mode(
            &cipher,
            &mock_file,
            file_iv,
            header_size,
            block_size,
            block_mac_bytes,
            BlockMode::AesGcmSiv,
        );

        // Write initial data: "ABCD..." (48 bytes - exactly one full AES-GCM-SIV plaintext block, 64 - 16)
        let initial_data = vec![b'A'; 48];
        encoder.write_at(&initial_data, 0).expect("Write init");

        // Modify middle: write "XYZ" at offset 15, which forces a RMW of the first AES-GCM-SIV block
        let overwrite = b"XYZ";
        encoder.write_at(overwrite, 15).expect("Write overwrite");

        // Read back
        let decoder = FileDecoder::new_with_mode(
            &cipher,
            &mock_file,
            file_iv,
            header_size,
            block_size,
            block_mac_bytes,
            BlockMode::AesGcmSiv,
            false,
        );
        let mut buf = vec![0u8; 48];
        decoder.read_at(&mut buf, 0).expect("Read back");

        let mut expected = initial_data.clone();
        expected[15..18].copy_from_slice(overwrite);

        assert_eq!(buf, expected);
    }

    #[test]
    fn test_large_gap_write() {
        let mut cipher = create_cipher();
        let key = vec![0u8; 16];
        let iv = vec![0u8; 32];
        cipher.set_key(&key, &iv);

        let file_iv = 123;
        let header_size = 8;
        let block_size = 64;
        let block_mac_bytes = 8;

        let mock_file = MockFile::new(vec![0u8; header_size as usize]);
        let encoder = FileEncoder::new(
            &cipher,
            &mock_file,
            file_iv,
            header_size,
            block_size,
            block_mac_bytes,
        );

        // Initial write at offset 0
        encoder.write_at(b"Start", 0).expect("Write failed");

        // Write at large offset (1MB gap).
        // 1MB is large enough to trigger the loop with 128KB chunks.
        let large_offset = 1024 * 1024 + 5; // 1MB + 5
        encoder
            .write_at(b"End", large_offset)
            .expect("Gap write failed");

        // Verify content size
        // Logical size = large_offset + 3 ("End")
        // let expected_logical = large_offset + 3;

        let decoder = FileDecoder::new(
            &cipher,
            &mock_file,
            file_iv,
            header_size,
            block_size,
            block_mac_bytes,
            false,
        );

        // Read back the "End"
        let mut buf = vec![0u8; 3];
        decoder
            .read_at(&mut buf, large_offset)
            .expect("Read failed");
        assert_eq!(&buf, b"End");

        // Verify gap is zeros at a few points
        let mut zero_buf = vec![0u8; 100];
        // Check near start of gap
        decoder.read_at(&mut zero_buf, 100).expect("Read gap start");
        assert_eq!(zero_buf, vec![0u8; 100]);

        // Check near end of gap
        decoder
            .read_at(&mut zero_buf, large_offset - 100)
            .expect("Read gap end");
        assert_eq!(zero_buf, vec![0u8; 100]);
    }
}
