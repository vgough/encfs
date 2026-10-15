//! On-disk naming for encfs's encrypted extended attributes.
//!
//! Each attribute is stored under [`PREFIX`] followed by the base64 of its
//! encrypted name. [`PREFIX`] carries the `user.` namespace; that is part of
//! the stored name on Linux and macOS, but on FreeBSD the `extattr_*`
//! syscalls pass it out-of-band and the backing file records only
//! `encfs.<b64>`. The standard base64 alphabet includes `/`, which FreeBSD
//! will not accept in an extended-attribute name: `setextattr(8)` fails with
//! `EINVAL` on a name containing one, while the same name spelled with `+`
//! or `=` is stored without complaint. Two of the six distinct names the
//! xattr tests here produce contain a `/`, so a third of attributes could
//! not be stored on FreeBSD at all.
//!
//! Names therefore use the URL-safe alphabet, which spells the two
//! disputed characters `-` and `_`.
//!
//! The encrypted names on an inode are keyed by an IV derived from
//! [`IV_SEED_LEN`] random bytes stored on the same inode under
//! [`IV_SEED_NAME`] (see `Cipher::xattr_iv`), so they move with the inode
//! through renames and are shared by its hard links. `~` is in neither base64
//! alphabet, so the seed's name never collides with an encrypted one.
//!
//! Only this port is affected. The C++ encfs passed attribute names through
//! to the backing file unchanged; encrypting and encoding them arrived with
//! the Rust port. Filenames are unrelated -- they use the cipher's own
//! alphabet, not this one.

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use std::ffi::CStr;

/// Prefix encfs uses for a stored (encrypted) attribute name.
pub const PREFIX: &str = "user.encfs.";

/// The on-disk name for an encrypted attribute name.
pub fn encode(encrypted_name: &[u8]) -> String {
    format!("{}{}", PREFIX, URL_SAFE_NO_PAD.encode(encrypted_name))
}

/// Decode the base64 part of a stored name.
pub fn decode(encoded: &str) -> Option<Vec<u8>> {
    URL_SAFE_NO_PAD.decode(encoded).ok()
}

/// On-disk name of the random seed an inode's encrypted attribute IV is
/// derived from. Never listed through the mount.
pub const IV_SEED_NAME: &str = "user.encfs.~iv";

/// [`IV_SEED_NAME`] as a C string, for the xattr syscalls.
pub const IV_SEED_CNAME: &CStr = c"user.encfs.~iv";

/// Exact size of the seed stored under [`IV_SEED_NAME`].
pub const IV_SEED_LEN: usize = 16;

/// Whether `name` (an on-disk attribute name) is an encrypted attribute,
/// which excludes the seed.
pub fn is_encrypted_name(name: &[u8]) -> bool {
    name.starts_with(PREFIX.as_bytes()) && name != IV_SEED_NAME.as_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Encodes to `///8` under the standard alphabet and `___8` under the
    /// URL-safe one.
    const DISPUTED: &[u8] = &[0xFF, 0xFF, 0xFC];

    #[test]
    fn names_avoid_the_character_freebsd_rejects() {
        let name = encode(DISPUTED);
        assert!(!name.contains('/'), "{}", name);
        let encoded = name.strip_prefix(PREFIX).expect("prefix");
        assert_eq!(decode(encoded).expect("decodes"), DISPUTED);
    }

    #[test]
    fn rejects_what_is_not_base64() {
        assert!(decode("not base64!").is_none());
    }

    #[test]
    fn the_seed_names_agree() {
        assert_eq!(IV_SEED_CNAME.to_str().unwrap(), IV_SEED_NAME);
    }

    #[test]
    fn the_seed_is_not_an_encrypted_name() {
        let seed = IV_SEED_NAME.strip_prefix(PREFIX).expect("prefix");
        assert!(decode(seed).is_none());
        assert!(!is_encrypted_name(IV_SEED_NAME.as_bytes()));
        assert!(is_encrypted_name(encode(DISPUTED).as_bytes()));
        assert!(!is_encrypted_name(b"user.other"));
    }
}
