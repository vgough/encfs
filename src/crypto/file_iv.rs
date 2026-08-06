//! `FileIv`: the per-file IV value used to build AES-GCM-SIV nonces/AAD and the
//! on-disk file header, in either its legacy 64-bit or wide 96-bit form.
//!
//! An internal `u128` is a convenient representation, but it is not itself the
//! wire format — every conversion in and out is checked so a value at or above
//! `2^96` can never be constructed or silently truncated.

use anyhow::{Result, anyhow};

/// A file IV constrained to the range `0..2^96`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct FileIv(u128);

impl FileIv {
    /// Largest value a `FileIv` may hold: `2^96 - 1`.
    pub const MAX: u128 = (1u128 << 96) - 1;

    /// Wraps a legacy 64-bit (narrow or headerless) file IV. Always in range.
    pub fn from_u64(value: u64) -> Self {
        Self(value as u128)
    }

    /// Constructs a wide file IV from its 12-byte big-endian header/wire form.
    pub fn from_wide_be_bytes(bytes: [u8; 12]) -> Self {
        let mut full = [0u8; 16];
        full[4..].copy_from_slice(&bytes);
        Self(u128::from_be_bytes(full))
    }

    /// Constructs a `FileIv` from an unconstrained `u128`, rejecting values at
    /// or above `2^96`.
    pub fn try_from_u128(value: u128) -> Result<Self> {
        if value > Self::MAX {
            return Err(anyhow!(
                "file IV {} exceeds the 96-bit maximum ({})",
                value,
                Self::MAX
            ));
        }
        Ok(Self(value))
    }

    /// The underlying value as an unconstrained `u128`, guaranteed `<= MAX`.
    pub fn as_u128(self) -> u128 {
        self.0
    }

    /// Returns the value as exactly 12 big-endian bytes (the wide header /
    /// wire form).
    pub fn to_wide_be_bytes(self) -> [u8; 12] {
        let full = self.0.to_be_bytes();
        full[4..16].try_into().expect("slice is exactly 12 bytes")
    }

    /// Returns the value as a `u64`, rejecting it if any of the upper 32 bits
    /// of the 96-bit range (i.e. bits 64..96) are set. Never truncates.
    pub fn try_to_u64(self) -> Result<u64> {
        if self.0 >> 64 != 0 {
            return Err(anyhow!(
                "file IV {} does not fit in the legacy 64-bit representation",
                self.0
            ));
        }
        Ok(self.0 as u64)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn narrow_roundtrip() {
        let iv = FileIv::from_u64(0x0123_4567_89ab_cdef);
        assert_eq!(iv.as_u128(), 0x0123_4567_89ab_cdef);
        assert_eq!(iv.try_to_u64().unwrap(), 0x0123_4567_89ab_cdef);
    }

    #[test]
    fn wide_roundtrip() {
        let bytes: [u8; 12] = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];
        let iv = FileIv::from_wide_be_bytes(bytes);
        assert_eq!(iv.to_wide_be_bytes(), bytes);
    }

    #[test]
    fn accepts_maximum_96_bit_value() {
        let iv = FileIv::try_from_u128(FileIv::MAX).expect("max value must be accepted");
        assert_eq!(iv.as_u128(), FileIv::MAX);
        assert_eq!(iv.to_wide_be_bytes(), [0xffu8; 12]);
    }

    #[test]
    fn rejects_values_above_96_bits() {
        assert!(FileIv::try_from_u128(FileIv::MAX + 1).is_err());
        assert!(FileIv::try_from_u128(u128::MAX).is_err());
    }

    #[test]
    fn try_to_u64_rejects_wide_only_values() {
        // Bit 64 set: outside the legacy 64-bit range but still a valid FileIv.
        let iv = FileIv::try_from_u128(1u128 << 64).unwrap();
        assert!(iv.try_to_u64().is_err());

        // Exactly at the u64 boundary: the largest value that still fits.
        let iv = FileIv::try_from_u128(u64::MAX as u128).unwrap();
        assert_eq!(iv.try_to_u64().unwrap(), u64::MAX);
    }

    #[test]
    fn wide_be_bytes_high_nibble_is_zero_for_narrow_values() {
        let iv = FileIv::from_u64(u64::MAX);
        let bytes = iv.to_wide_be_bytes();
        assert_eq!(&bytes[..4], &[0u8; 4]);
        assert_eq!(&bytes[4..], &u64::MAX.to_be_bytes());
    }
}
