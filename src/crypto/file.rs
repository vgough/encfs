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
/// Handles block-by-block decryption and MAC verification.
/// EncFS uses a fixed block size (typically 1024 bytes) on disk, which includes
/// encryption overhead (MAC).
pub struct FileDecoder<'a, F: ReadAt> {
    cipher: &'a SslCipher,
    file: &'a F,
    file_iv: u64,
    header_size: u64,
    block_size: u64,      // On-disk block size from config (e.g., 1024)
    block_mac_bytes: u64, // MAC bytes per block (e.g., 8)
}

impl<'a, F: ReadAt> FileDecoder<'a, F> {
    pub fn new(
        cipher: &'a SslCipher,
        file: &'a F,
        file_iv: u64,
        header_size: u64,
        block_size: u64,
        block_mac_bytes: u64,
    ) -> Self {
        Self {
            cipher,
            file,
            file_iv,
            header_size,
            block_size,
            block_mac_bytes,
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
        if physical_size < header_size {
            return 0;
        }

        let data_size = physical_size - header_size;

        if block_mac_bytes > 0 {
            // EncFS stores MAC bytes at the start of each on-disk block.
            // In this implementation, `block_size` is the *on-disk* block size,
            // and the plaintext payload per full block is `block_size - block_mac_bytes`.
            if block_size <= block_mac_bytes {
                return 0;
            }
            let physical_block_size = block_size;
            let data_block_size = block_size - block_mac_bytes;

            let full_blocks = data_size / physical_block_size;
            let usage_in_full = full_blocks * data_block_size;

            let remainder = data_size % physical_block_size;
            let usage_in_partial = remainder.saturating_sub(block_mac_bytes);

            return usage_in_full + usage_in_partial;
        }

        data_size
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
        let size = buf.len() as u64;
        let mut bytes_remaining = size;
        let mut total_read = 0;
        let mut current_offset = offset;

        // Data block size is the actual user data per block (block_size - MAC overhead)
        if self.block_size <= self.block_mac_bytes {
            return Err(io::Error::other(
                "Invalid config: block_size must be > block_mac_bytes",
            ));
        }
        let data_block_size = self.block_size - self.block_mac_bytes;

        let block_size_usize = usize::try_from(self.block_size)
            .map_err(|_| io::Error::other("block_size too large"))?;
        let mac_len_usize = usize::try_from(self.block_mac_bytes)
            .map_err(|_| io::Error::other("block_mac_bytes too large"))?;
        if mac_len_usize > 8 {
            return Err(io::Error::other(
                "Invalid config: block_mac_bytes must be <= 8",
            ));
        }

        while bytes_remaining > 0 {
            // Calculate which data block we need
            let block_num = current_offset / data_block_size;
            let block_offset = current_offset % data_block_size;
            let bytes_to_read_in_block =
                std::cmp::min(bytes_remaining, data_block_size - block_offset);

            // Read full on-disk block (MAC + encrypted data = block_size bytes)
            let read_offset = self.header_size + block_num * self.block_size;
            let mut block_data = vec![0u8; block_size_usize];

            match self.file.read_at(&mut block_data, read_offset) {
                Ok(bytes_read) => {
                    if bytes_read == 0 {
                        break; // EOF
                    }
                    block_data.truncate(bytes_read);

                    // EncFS decrypts the entire block (MAC + data), then strips MAC
                    if let Err(e) = self.cipher.decrypt_block_inplace(
                        &mut block_data,
                        block_num,
                        self.file_iv,
                        self.block_size, // Full block size for crypto
                    ) {
                        return Err(io::Error::other(format!(
                            "Failed to decrypt block {}: {}",
                            block_num, e
                        )));
                    }

                    // AFTER decryption, verify and strip MAC from start.
                    let plaintext: &[u8] = if self.block_mac_bytes > 0 {
                        if block_data.len() < mac_len_usize {
                            return Err(io::Error::other(format!(
                                "Truncated block {}: missing MAC bytes",
                                block_num
                            )));
                        }
                        let stored_mac = &block_data[..mac_len_usize];
                        let data = &block_data[mac_len_usize..];

                        // EncFS stores MAC bytes as the least-significant bytes of the u64,
                        // written in little-endian order (byte 0 = mac & 0xff).
                        let computed = self.cipher.mac_64_no_iv(data);
                        let mut tmp = computed;
                        let mut fail: u8 = 0;
                        for &stored in stored_mac.iter() {
                            let expected = (tmp & 0xff) as u8;
                            fail |= expected ^ stored;
                            tmp >>= 8;
                        }
                        if fail != 0 {
                            return Err(io::Error::other(format!(
                                "MAC mismatch in block {}",
                                block_num
                            )));
                        }
                        data
                    } else {
                        &block_data
                    };

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
        Self {
            cipher,
            file,
            file_iv,
            header_size,
            block_size,
            block_mac_bytes,
        }
    }

    pub fn calculate_physical_size(
        logical_size: u64,
        header_size: u64,
        block_size: u64,
        block_mac_bytes: u64,
    ) -> u64 {
        if logical_size == 0 {
            return header_size;
        }

        if block_mac_bytes == 0 {
            return header_size + logical_size;
        }
        if block_size <= block_mac_bytes {
            return header_size;
        }
        let data_block_size = block_size - block_mac_bytes;
        let full_blocks = logical_size / data_block_size;
        let remainder = logical_size % data_block_size;

        let mut physical_size = header_size + full_blocks * block_size;
        if remainder > 0 {
            physical_size += remainder + block_mac_bytes;
        }
        physical_size
    }

    pub fn write_at(&self, buf: &[u8], offset: u64) -> io::Result<usize> {
        if self.block_size <= self.block_mac_bytes {
            return Err(io::Error::other(
                "Invalid config: block_size must be > block_mac_bytes",
            ));
        }
        let physical_block_size = self.block_size;
        let data_block_size = self.block_size - self.block_mac_bytes;

        let physical_block_size_usize = usize::try_from(physical_block_size)
            .map_err(|_| io::Error::other("block_size too large"))?;
        let mac_len_usize = usize::try_from(self.block_mac_bytes)
            .map_err(|_| io::Error::other("block_mac_bytes too large"))?;
        if mac_len_usize > 8 {
            return Err(io::Error::other(
                "Invalid config: block_mac_bytes must be <= 8",
            ));
        }

        // Detect and fill gaps to prevent sparse files.
        // Sparse files cause MAC verification failures because reading a block
        // that partially spans a hole returns zeros that weren't properly encrypted.
        let physical_size = self.file.file_len()?;
        let current_logical_size = FileDecoder::<F>::calculate_logical_size(
            physical_size,
            self.header_size,
            self.block_size,
            self.block_mac_bytes,
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
                    data_block_size,
                    physical_block_size,
                    physical_block_size_usize,
                    mac_len_usize,
                )?;
                remaining_gap -= write_len;
                gap_offset += write_len;
            }
        }

        // Now write the actual data
        self.write_at_internal(
            buf,
            offset,
            data_block_size,
            physical_block_size,
            physical_block_size_usize,
            mac_len_usize,
        )
    }

    fn write_at_internal(
        &self,
        buf: &[u8],
        offset: u64,
        data_block_size: u64,
        physical_block_size: u64,
        physical_block_size_usize: usize,
        mac_len_usize: usize,
    ) -> io::Result<usize> {
        let size = buf.len() as u64;
        let mut bytes_remaining = size;
        let mut total_written = 0;
        let mut current_offset = offset;

        while bytes_remaining > 0 {
            let block_num = current_offset / data_block_size;
            let block_offset = current_offset % data_block_size;
            let bytes_to_write_in_block =
                std::cmp::min(bytes_remaining, data_block_size - block_offset);

            let read_offset = self.header_size + block_num * physical_block_size;
            let mut block_data = vec![0u8; physical_block_size_usize];

            // RMW: Enable read if we are not overwriting the entire data portion of the block
            let is_full_write = block_offset == 0 && bytes_to_write_in_block == data_block_size;

            let mut buffer = if !is_full_write {
                match self.file.read_at(&mut block_data, read_offset) {
                    Ok(n) => {
                        if n > 0 {
                            // Check if this write will overwrite the entire data we just read.
                            // We read 'n' bytes. This includes MAC overhead.
                            // The amount of plaintext data in this block is 'n - mac_len'.
                            // If we are writing at offset 0, and writing >= that amount, we don't need to decrypt.
                            let current_payload_len = if self.block_mac_bytes > 0 {
                                n.saturating_sub(mac_len_usize)
                            } else {
                                n
                            };

                            if block_offset == 0
                                && (bytes_to_write_in_block as usize) >= current_payload_len
                            {
                                // Optimization: We are overwriting the entire existing content.
                                // No need to decrypt the old content.
                                Vec::new()
                            } else {
                                block_data.truncate(n);
                                if self
                                    .cipher
                                    .decrypt_block_inplace(
                                        &mut block_data,
                                        block_num,
                                        self.file_iv,
                                        physical_block_size,
                                    )
                                    .is_err()
                                {
                                    // Decrypt failed. Could be new block/garbage.
                                    // Treat as empty/zeros to overwrite?
                                    // If we fail to decrypt, we corrupt the block if we write back garbage + new data?
                                    // Better to error out.
                                    return Err(io::Error::other("Decrypt failed during RMW"));
                                }
                                if self.block_mac_bytes > 0
                                    && (block_data.len() as u64) >= self.block_mac_bytes
                                {
                                    block_data.drain(0..self.block_mac_bytes as usize);
                                }
                                block_data
                            }
                        } else {
                            Vec::new()
                        }
                    }
                    Err(e) => return Err(e),
                }
            } else {
                Vec::new()
            };

            // Extend buffer to cover the write range
            let required_len = usize::try_from(block_offset + bytes_to_write_in_block)
                .map_err(|_| io::Error::other("write range too large"))?;
            if buffer.len() < required_len {
                buffer.resize(required_len, 0);
            }

            // Copy new data
            let src_start = total_written;
            let src_end = src_start + bytes_to_write_in_block as usize;
            let dst_start = block_offset as usize;
            let dst_end = dst_start + bytes_to_write_in_block as usize;

            buffer[dst_start..dst_end].copy_from_slice(&buf[src_start..src_end]);

            // Add MAC
            if self.block_mac_bytes > 0 {
                // EncFS computes MAC_64 over the plaintext data (and optional rand bytes),
                // without a chained IV, then stores the least-significant bytes first.
                let mac = self.cipher.mac_64_no_iv(&buffer);
                let mut new_buf = Vec::with_capacity(mac_len_usize + buffer.len());
                let mut tmp = mac;
                for _ in 0..mac_len_usize {
                    new_buf.push((tmp & 0xff) as u8);
                    tmp >>= 8;
                }
                new_buf.extend_from_slice(&buffer);
                buffer = new_buf;
            }

            // Encrypt
            self.cipher
                .encrypt_block_inplace(&mut buffer, block_num, self.file_iv, physical_block_size)
                .map_err(io::Error::other)?;

            // Write
            self.file.write_at(&buffer, read_offset)?;

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
        );
        let mut buf = vec![0u8; data.len()];
        let err = decoder.read_at(&mut buf, 0).expect_err("Should fail MAC");
        assert!(err.to_string().contains("MAC mismatch"));
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
        );
        let mut buf = vec![0u8; 56];
        decoder.read_at(&mut buf, 0).expect("Read back");

        let mut expected = initial_data.clone();
        expected[10..13].copy_from_slice(overwrite);

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
