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
//! New names therefore use the URL-safe alphabet, which spells the two
//! disputed characters `-` and `_`. Reading accepts either. The alphabets
//! differ only in those four characters, so a string that decodes under both
//! contains none of them and yields the same bytes either way: trying one and
//! then the other cannot return the wrong plaintext. [`encode_legacy`]
//! reproduces the older spelling so a lookup can fall back to it.
//!
//! Only this port is affected. The C++ encfs passed attribute names through
//! to the backing file unchanged; encrypting and encoding them arrived with
//! the Rust port. Filenames are unrelated -- they use the cipher's own
//! alphabet, not this one.

use base64::Engine;
use base64::engine::general_purpose::{STANDARD_NO_PAD, URL_SAFE_NO_PAD};

/// Prefix encfs uses for a stored (encrypted) attribute name.
pub const PREFIX: &str = "user.encfs.";

/// The on-disk name for an encrypted attribute name.
pub fn encode(encrypted_name: &[u8]) -> String {
    format!("{}{}", PREFIX, URL_SAFE_NO_PAD.encode(encrypted_name))
}

/// The on-disk name a build from before the alphabet change would have
/// written. Identical to [`encode`] whenever the encoding happens to use none
/// of the characters the two alphabets disagree on.
pub fn encode_legacy(encrypted_name: &[u8]) -> String {
    format!("{}{}", PREFIX, STANDARD_NO_PAD.encode(encrypted_name))
}

/// Decode the base64 part of a stored name, accepting either alphabet.
pub fn decode(encoded: &str) -> Option<Vec<u8>> {
    URL_SAFE_NO_PAD
        .decode(encoded)
        .or_else(|_| STANDARD_NO_PAD.decode(encoded))
        .ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Encodes to `///8` under the standard alphabet and `___8` under the
    /// URL-safe one, so it exercises exactly the disagreement.
    const DISPUTED: &[u8] = &[0xFF, 0xFF, 0xFC];

    #[test]
    fn new_names_avoid_the_character_freebsd_rejects() {
        let name = encode(DISPUTED);
        assert!(!name.contains('/'), "{}", name);
        // and the old spelling really did contain it, or this proves nothing
        assert!(encode_legacy(DISPUTED).contains('/'));
    }

    #[test]
    fn both_spellings_decode_to_the_same_bytes() {
        for name in [encode(DISPUTED), encode_legacy(DISPUTED)] {
            let encoded = name.strip_prefix(PREFIX).expect("prefix");
            assert_eq!(decode(encoded).expect("decodes"), DISPUTED, "{}", name);
        }
    }

    #[test]
    fn the_spellings_coincide_when_nothing_is_disputed() {
        assert_eq!(encode(b"encfs"), encode_legacy(b"encfs"));
    }

    #[test]
    fn rejects_what_is_not_base64() {
        assert!(decode("not base64!").is_none());
    }
}
