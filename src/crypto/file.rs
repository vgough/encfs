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
    allow_holes: bool,
}

impl<'a, F: ReadAt> FileDecoder<'a, F> {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        cipher: &'a SslCipher,
        file: &'a F,
        file_iv: u64,
        header_size: u64,
        block_size: u64,
        block_mac_bytes: u64,
        ignore_mac_mismatch: bool,
        allow_holes: bool,
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
            allow_holes,
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
        allow_holes: bool,
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
            allow_holes,
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
        let codec = BlockCodec::new(
            self.cipher,
            layout,
            self.ignore_mac_mismatch,
            self.allow_holes,
        );
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
    allow_holes: bool,
}

impl<'a, F: ReadAt + WriteAt + FileLen> FileEncoder<'a, F> {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        cipher: &'a SslCipher,
        file: &'a F,
        file_iv: u64,
        header_size: u64,
        block_size: u64,
        block_mac_bytes: u64,
        allow_holes: bool,
    ) -> Self {
        Self::new_with_mode(
            cipher,
            file,
            file_iv,
            header_size,
            block_size,
            block_mac_bytes,
            BlockMode::Legacy,
            allow_holes,
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
        allow_holes: bool,
    ) -> Self {
        Self {
            cipher,
            file,
            file_iv,
            header_size,
            block_size,
            block_mac_bytes,
            block_mode,
            allow_holes,
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

        let physical_size = self.file.file_len()?;
        let current_logical_size = FileDecoder::<F>::calculate_logical_size_with_mode(
            physical_size,
            self.header_size,
            self.block_size,
            self.block_mac_bytes,
            self.block_mode,
        );

        if offset > current_logical_size {
            let zeros = vec![0u8; data_block_size as usize];
            let mut gap_offset = current_logical_size;
            while gap_offset < offset {
                let block_offset = gap_offset % data_block_size;
                let bytes_in_block =
                    std::cmp::min(offset - gap_offset, data_block_size - block_offset);
                self.write_at_internal(
                    &zeros[..bytes_in_block as usize],
                    gap_offset,
                    layout,
                    data_block_size,
                    physical_block_size,
                    physical_block_size_usize,
                )?;
                gap_offset += bytes_in_block;
            }
        }

        let mut total_written = 0;
        let mut current_offset = offset;
        let mut bytes_remaining = buf.len() as u64;

        while bytes_remaining > 0 {
            let block_offset = current_offset % data_block_size;
            let bytes_in_block =
                std::cmp::min(bytes_remaining, data_block_size - block_offset);

            self.write_at_internal(
                &buf[total_written..total_written + bytes_in_block as usize],
                current_offset,
                layout,
                data_block_size,
                physical_block_size,
                physical_block_size_usize,
            )?;

            total_written += bytes_in_block as usize;
            current_offset += bytes_in_block;
            bytes_remaining -= bytes_in_block;
        }

        Ok(total_written)
    }

    /// Writes a single block's worth of data at the given logical offset.
    /// The caller must ensure `buf` fits within one block boundary.
    fn write_at_internal(
        &self,
        buf: &[u8],
        offset: u64,
        layout: BlockLayout,
        data_block_size: u64,
        physical_block_size: u64,
        physical_block_size_usize: usize,
    ) -> io::Result<usize> {
        let codec = BlockCodec::new(self.cipher, layout, false, self.allow_holes);

        let block_num = offset / data_block_size;
        let block_offset = offset % data_block_size;
        let bytes_to_write = buf.len() as u64;

        let disk_offset = self.header_size + block_num * physical_block_size;
        let mut plaintext_block = Vec::new();

        let is_full_write = block_offset == 0 && bytes_to_write == data_block_size;
        if !is_full_write {
            let mut on_disk_block = vec![0u8; physical_block_size_usize];
            match self.file.read_at(&mut on_disk_block, disk_offset) {
                Ok(n) => {
                    if n > 0 {
                        let existing_payload_len =
                            n.saturating_sub(layout.overhead_bytes() as usize);
                        if block_offset == 0
                            && (bytes_to_write as usize) >= existing_payload_len
                        {
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

        let required_len = (block_offset + bytes_to_write) as usize;
        if plaintext_block.len() < required_len {
            plaintext_block.resize(required_len, 0);
        }

        let dst_start = block_offset as usize;
        let dst_end = dst_start + buf.len();
        plaintext_block[dst_start..dst_end].copy_from_slice(buf);

        let encrypted_block = codec.encrypt_block(block_num, self.file_iv, &plaintext_block)?;
        self.file.write_at(&encrypted_block, disk_offset)?;

        Ok(buf.len())
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
            false,
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
            false,
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
            false,
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
            false,
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
            false,
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
            false,
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
            false,
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
            false,
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

    #[test]
    fn test_allow_holes_zero_block_passthrough_no_mac() {
        let mut cipher = create_cipher();
        let key = vec![0u8; 16];
        let iv = vec![0u8; 32];
        cipher.set_key(&key, &iv);

        let file_iv = 987654;
        let header_size = 8;
        let block_size = 64;
        let block_mac_bytes = 0; // No MACs (standard mode)

        // Create a file with a sparse hole (all zeros in a block)
        let mock_file = MockFile::new(vec![0u8; header_size as usize + block_size as usize]);

        // Decoder WITHOUT allow_holes - should try to decrypt zeros as ciphertext
        let decoder_no_holes = FileDecoder::new(
            &cipher,
            &mock_file,
            file_iv,
            header_size,
            block_size,
            block_mac_bytes,
            false,
            false, // allow_holes = false
        );

        let mut buf_no_holes = vec![0u8; block_size as usize];
        let read = decoder_no_holes
            .read_at(&mut buf_no_holes, 0)
            .expect("Read should succeed");
        assert_eq!(read, block_size as usize);
        // Without allow_holes, decrypting zeros produces non-zero garbage
        assert_ne!(buf_no_holes, vec![0u8; block_size as usize]);

        // Decoder WITH allow_holes - should return zeros as plaintext
        let decoder_with_holes = FileDecoder::new(
            &cipher,
            &mock_file,
            file_iv,
            header_size,
            block_size,
            block_mac_bytes,
            false,
            true, // allow_holes = true
        );

        let mut buf_with_holes = vec![0u8; block_size as usize];
        let read = decoder_with_holes
            .read_at(&mut buf_with_holes, 0)
            .expect("Read should succeed");
        assert_eq!(read, block_size as usize);
        // With allow_holes, reading zeros returns zeros
        assert_eq!(buf_with_holes, vec![0u8; block_size as usize]);
    }

    #[test]
    fn test_allow_holes_sparse_file_extension() {
        let mut cipher = create_cipher();
        let key = vec![0u8; 16];
        let iv = vec![0u8; 32];
        cipher.set_key(&key, &iv);

        let file_iv = 555555;
        let header_size = 8;
        let block_size = 64;
        let block_mac_bytes = 0;

        // Test WITH allow_holes - should allow sparse gaps
        let mock_file_sparse = MockFile::new(vec![0u8; header_size as usize]);
        let encoder_sparse = FileEncoder::new(
            &cipher,
            &mock_file_sparse,
            file_iv,
            header_size,
            block_size,
            block_mac_bytes,
            true, // allow_holes = true
        );

        // Write initial data
        encoder_sparse.write_at(b"START", 0).expect("Write failed");

        // Write at offset with a gap (should NOT fill gap with encrypted zeros)
        let offset_with_gap = 200;
        encoder_sparse
            .write_at(b"END", offset_with_gap)
            .expect("Write at gap");

        // Verify both can read back correctly
        let decoder_sparse = FileDecoder::new(
            &cipher,
            &mock_file_sparse,
            file_iv,
            header_size,
            block_size,
            block_mac_bytes,
            false,
            true,
        );

        let mut buf = vec![0u8; 3];
        decoder_sparse
            .read_at(&mut buf, offset_with_gap)
            .expect("Read");
        assert_eq!(&buf, b"END");

        // Verify gap reads as zeros
        let mut gap_buf = vec![0u8; 10];
        decoder_sparse.read_at(&mut gap_buf, 100).expect("Read gap");
        assert_eq!(gap_buf, vec![0u8; 10]);

        // Test WITHOUT allow_holes - should fill gap
        let mock_file_dense = MockFile::new(vec![0u8; header_size as usize]);
        let encoder_dense = FileEncoder::new(
            &cipher,
            &mock_file_dense,
            file_iv,
            header_size,
            block_size,
            block_mac_bytes,
            false, // allow_holes = false
        );

        encoder_dense.write_at(b"START", 0).expect("Write failed");
        encoder_dense
            .write_at(b"END", offset_with_gap)
            .expect("Write at gap");

        let decoder_dense = FileDecoder::new(
            &cipher,
            &mock_file_dense,
            file_iv,
            header_size,
            block_size,
            block_mac_bytes,
            false,
            false,
        );

        let mut buf2 = vec![0u8; 3];
        decoder_dense
            .read_at(&mut buf2, offset_with_gap)
            .expect("Read");
        assert_eq!(&buf2, b"END");

        // Verify gap was filled with encrypted zeros (reads back as zeros but different on disk)
        let mut gap_buf2 = vec![0u8; 10];
        decoder_dense.read_at(&mut gap_buf2, 100).expect("Read gap");
        assert_eq!(gap_buf2, vec![0u8; 10]);
    }

    #[test]
    fn test_allow_holes_zero_block_passthrough_with_mac() {
        let mut cipher = create_cipher();
        let key = vec![0u8; 16];
        let iv = vec![0u8; 32];
        cipher.set_key(&key, &iv);

        let file_iv = 987654;
        let header_size: u64 = 8;
        let block_size: u64 = 64;
        let block_mac_bytes: u64 = 8;
        let data_block_size = (block_size - block_mac_bytes) as usize; // 56

        // One full physical block of zeros after the header.
        let mock_file = MockFile::new(vec![0u8; header_size as usize + block_size as usize]);

        let decoder = FileDecoder::new(
            &cipher,
            &mock_file,
            file_iv,
            header_size,
            block_size,
            block_mac_bytes,
            false,
            true, // allow_holes = true
        );

        let mut buf = vec![0xFFu8; data_block_size];
        let read = decoder.read_at(&mut buf, 0).expect("Read should succeed");
        assert_eq!(read, data_block_size);
        assert_eq!(buf, vec![0u8; data_block_size]);
    }

    #[test]
    fn test_allow_holes_sparse_file_extension_with_mac() {
        let mut cipher = create_cipher();
        let key = vec![0u8; 16];
        let iv = vec![0u8; 32];
        cipher.set_key(&key, &iv);

        let file_iv = 555555;
        let header_size: u64 = 8;
        let block_size: u64 = 64;
        let block_mac_bytes: u64 = 8;
        let data_block_size = block_size - block_mac_bytes; // 56

        let mock_file = MockFile::new(vec![0u8; header_size as usize]);
        let encoder = FileEncoder::new(
            &cipher,
            &mock_file,
            file_iv,
            header_size,
            block_size,
            block_mac_bytes,
            true, // allow_holes = true
        );

        // Write a full data block so block 0 occupies exactly block_size bytes
        // on disk, avoiding a partial block bleeding into the gap region.
        let payload1 = vec![0xAB; data_block_size as usize];
        encoder.write_at(&payload1, 0).expect("Write 1 failed");

        // Write past a multi-block gap.  Blocks 1 and 2 are untouched (sparse
        // holes of zeros).  Block 3 gets the second payload.
        let offset2 = data_block_size * 3; // 168
        let payload2 = b"WORLD";
        encoder.write_at(payload2, offset2).expect("Write 2 failed");

        let decoder = FileDecoder::new(
            &cipher,
            &mock_file,
            file_iv,
            header_size,
            block_size,
            block_mac_bytes,
            false,
            true, // allow_holes = true
        );

        // Verify first payload
        let mut buf1 = vec![0u8; payload1.len()];
        decoder.read_at(&mut buf1, 0).expect("Read payload1");
        assert_eq!(buf1, payload1);

        // Verify hole blocks are zeros
        let hole_len = (offset2 - data_block_size) as usize; // blocks 1-2
        let mut hole_buf = vec![0xFFu8; hole_len];
        let n = decoder
            .read_at(&mut hole_buf, data_block_size)
            .expect("Read hole");
        assert_eq!(n, hole_len);
        assert!(
            hole_buf.iter().all(|&b| b == 0),
            "Hole region should be all zeros"
        );

        // Verify second payload
        let mut buf2 = vec![0u8; payload2.len()];
        decoder.read_at(&mut buf2, offset2).expect("Read payload2");
        assert_eq!(&buf2, payload2);
    }
}
