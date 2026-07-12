use std::mem;
use std::sync::OnceLock;

use bincode::config::{
    AllowTrailing, FixintEncoding, LittleEndian, WithOtherEndian, WithOtherIntEncoding,
    WithOtherTrailing,
};
use bincode::{DefaultOptions, Options};
use nix::sys::stat::mode_t;

use crate::FileType;

/// Cached bincode configuration type for better performance.
/// Avoids creating new configuration objects on every call.
type BincodeConfigType = WithOtherIntEncoding<
    WithOtherTrailing<WithOtherEndian<DefaultOptions, LittleEndian>, AllowTrailing>,
    FixintEncoding,
>;

static BINCODE_CONFIG: OnceLock<BincodeConfigType> = OnceLock::new();

pub trait Apply: Sized {
    fn apply<F>(mut self, f: F) -> Self
    where
        F: FnOnce(&mut Self),
    {
        f(&mut self);
        self
    }
}

impl<T> Apply for T {}

#[inline]
pub fn get_first_null_position(data: impl AsRef<[u8]>) -> Option<usize> {
    data.as_ref().iter().position(|char| *char == 0)
}

// Some platforms like Linux x86_64 have mode_t = u32, and lint warns of a trivial_numeric_casts.
// But others like macOS x86_64 have mode_t = u16, requiring a typecast. So, just silence lint.
#[cfg(target_os = "linux")]
#[allow(trivial_numeric_casts)]
/// returns the mode for a given file kind and permission
pub const fn mode_from_kind_and_perm(kind: FileType, perm: u16) -> u32 {
    kind.const_into_mode_t() | perm as mode_t
}

// Some platforms like Linux x86_64 have mode_t = u32, and lint warns of a trivial_numeric_casts.
// But others like macOS x86_64 have mode_t = u16, requiring a typecast. So, just silence lint.
#[cfg(all(
    not(target_os = "linux"),
    any(target_os = "freebsd", target_os = "macos")
))]
#[allow(trivial_numeric_casts)]
/// returns the mode for a given file kind and permission
pub const fn mode_from_kind_and_perm(kind: FileType, perm: u16) -> u32 {
    (kind.const_into_mode_t() | perm as mode_t) as u32
}

/// returns the permission for a given file kind and mode
#[allow(clippy::unnecessary_cast)] // Not unnecessary on all platforms.
pub const fn perm_from_mode_and_kind(kind: FileType, mode: mode_t) -> u16 {
    (mode ^ kind.const_into_mode_t()) as u16
}

#[inline]
pub const fn get_padding_size(dir_entry_size: usize) -> usize {
    // 64bit align
    let entry_size = (dir_entry_size + mem::size_of::<u64>() - 1) & !(mem::size_of::<u64>() - 1);

    entry_size - dir_entry_size
}

/// Returns a cached bincode configuration for FUSE ABI serialization.
/// Uses LazyLock to avoid creating new configuration objects on every call.
#[inline]
pub fn get_bincode_config() -> &'static BincodeConfigType {
    BINCODE_CONFIG.get_or_init(|| {
        DefaultOptions::new()
            .with_little_endian()
            .allow_trailing_bytes()
            .with_fixint_encoding()
    })
}
