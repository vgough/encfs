//! Encoding of symlink targets on disk.
//!
//! Legacy (V4-V6) volumes store targets the way C++ EncFS does
//! (`DirNode::relativeCipherPath` / `DirNode::plainPath`):
//! - a relative target is encoded component by component like a path, with
//!   the IV starting at 0 and chained across the target's own components when
//!   `chained_name_iv` is set; `/` separators, `.` and `..` are kept as-is;
//! - an absolute target is stored as `+` followed by the rest of the path
//!   encoded as a single name with no IV.
//!
//! V7 volumes encrypt the whole target as one name under the symlink's own
//! path IV.

use crate::config::EncfsConfig;
use crate::crypto::cipher::Cipher;
use anyhow::{Result, anyhow};

/// Marks an absolute target in the legacy on-disk form.
const ABSOLUTE_MARK: u8 = b'+';

/// Encrypts a plaintext symlink `target` for a link whose path IV is `link_iv`.
pub fn encrypt(
    cipher: &dyn Cipher,
    config: &EncfsConfig,
    target: &[u8],
    link_iv: u64,
) -> Result<Vec<u8>> {
    if !config.uses_legacy_symlink_targets() {
        return Ok(cipher.encrypt_filename(target, link_iv)?.0.into_bytes());
    }
    if let Some(rest) = target.strip_prefix(b"/") {
        let mut out = vec![ABSOLUTE_MARK];
        out.extend_from_slice(cipher.encrypt_filename_no_iv(rest)?.as_bytes());
        return Ok(out);
    }
    recode(target, config.chained_name_iv, |name, iv| {
        let (encoded, next_iv) = cipher.encrypt_filename(name, iv)?;
        Ok((encoded.into_bytes(), next_iv))
    })
}

/// Decrypts an on-disk symlink target for a link whose path IV is `link_iv`.
pub fn decrypt(
    cipher: &dyn Cipher,
    config: &EncfsConfig,
    stored: &[u8],
    link_iv: u64,
) -> Result<Vec<u8>> {
    let as_str = |b: &[u8]| -> Result<String> {
        String::from_utf8(b.to_vec()).map_err(|_| anyhow!("symlink target is not valid UTF-8"))
    };
    if !config.uses_legacy_symlink_targets() {
        return Ok(cipher.decrypt_filename(&as_str(stored)?, link_iv)?.0);
    }
    if let Some(rest) = stored.strip_prefix(&[ABSOLUTE_MARK]) {
        let mut out = vec![b'/'];
        out.extend_from_slice(&cipher.decrypt_filename_no_iv(&as_str(rest)?)?);
        return Ok(out);
    }
    recode(stored, config.chained_name_iv, |name, iv| {
        cipher.decrypt_filename(&as_str(name)?, iv)
    })
}

/// Applies `code` to each `/`-separated component of `path`, mirroring C++
/// `NameIO::recodePath`: separators (including repeated or trailing ones),
/// `.` and `..` pass through, and the IV chains from 0 when `chained`.
fn recode(
    path: &[u8],
    chained: bool,
    mut code: impl FnMut(&[u8], u64) -> Result<(Vec<u8>, u64)>,
) -> Result<Vec<u8>> {
    let mut out = Vec::with_capacity(path.len() * 2);
    let mut iv = 0u64;
    for (i, component) in path.split(|&b| b == b'/').enumerate() {
        if i > 0 {
            out.push(b'/');
        }
        if component.is_empty() || component == b"." || component == b".." {
            out.extend_from_slice(component);
            continue;
        }
        let (coded, next_iv) = code(component, iv)?;
        out.extend_from_slice(&coded);
        if chained {
            iv = next_iv;
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{ConfigType, Interface};
    use crate::crypto::ssl::SslCipher;

    fn setup(config_type: ConfigType, chained: bool) -> (Box<dyn Cipher>, EncfsConfig) {
        let iface = Interface {
            name: "ssl/aes".to_string(),
            major: 3,
            minor: 0,
            age: 0,
        };
        let mut cipher = SslCipher::new(&iface, 192).expect("cipher");
        cipher.set_key(&[1u8; 24], &[2u8; 16]);
        cipher.set_name_mac_includes_iv(chained || config_type == ConfigType::V7);
        let mut config = EncfsConfig::test_default();
        config.config_type = config_type;
        config.chained_name_iv = chained;
        (Box::new(cipher), config)
    }

    fn enc(cipher: &dyn Cipher, name: &str, iv: u64) -> (String, u64) {
        cipher
            .encrypt_filename(name.as_bytes(), iv)
            .expect("encrypt")
    }

    #[test]
    fn legacy_relative_target_matches_cpp_encode_path() {
        let (cipher, config) = setup(ConfigType::V6, true);
        let link_iv = 0x1234_5678_9abc_def0;

        let stored = encrypt(cipher.as_ref(), &config, b"foo", link_iv).unwrap();
        assert_eq!(stored, enc(cipher.as_ref(), "foo", 0).0.into_bytes());

        // Components chain from IV 0; ".", ".." and separators pass through.
        let stored = encrypt(cipher.as_ref(), &config, b"../dir/./foo/", link_iv).unwrap();
        let (dir, dir_iv) = enc(cipher.as_ref(), "dir", 0);
        let (foo, _) = enc(cipher.as_ref(), "foo", dir_iv);
        assert_eq!(
            String::from_utf8(stored.clone()).unwrap(),
            format!("../{dir}/./{foo}/")
        );

        // The target doesn't depend on the link's path IV.
        assert_eq!(
            decrypt(cipher.as_ref(), &config, &stored, 0).unwrap(),
            b"../dir/./foo/"
        );
        assert!(!config.symlink_target_depends_on_path());
    }

    #[test]
    fn legacy_absolute_target_uses_plus_and_no_iv() {
        let (cipher, config) = setup(ConfigType::V6, true);
        let stored = encrypt(cipher.as_ref(), &config, b"/usr/bin/env", 99).unwrap();
        let expected = format!(
            "+{}",
            cipher.encrypt_filename_no_iv(b"usr/bin/env").unwrap()
        );
        assert_eq!(String::from_utf8(stored.clone()).unwrap(), expected);
        // On a chained volume the no-IV name differs from the IV-0 name.
        assert_ne!(expected[1..], enc(cipher.as_ref(), "usr/bin/env", 0).0);
        assert_eq!(
            decrypt(cipher.as_ref(), &config, &stored, 7).unwrap(),
            b"/usr/bin/env"
        );
    }

    #[test]
    fn legacy_unchained_target_does_not_chain() {
        let (cipher, config) = setup(ConfigType::V6, false);
        let stored = encrypt(cipher.as_ref(), &config, b"a/b", 0).unwrap();
        let (a, _) = enc(cipher.as_ref(), "a", 0);
        let (b, _) = enc(cipher.as_ref(), "b", 0);
        assert_eq!(
            String::from_utf8(stored.clone()).unwrap(),
            format!("{a}/{b}")
        );
        assert_eq!(
            decrypt(cipher.as_ref(), &config, &stored, 0).unwrap(),
            b"a/b"
        );
    }

    #[test]
    fn v7_target_is_one_name_under_link_iv() {
        let (cipher, config) = setup(ConfigType::V7, true);
        let stored = encrypt(cipher.as_ref(), &config, b"/abs/dir/foo", 42).unwrap();
        assert_eq!(
            stored,
            enc(cipher.as_ref(), "/abs/dir/foo", 42).0.into_bytes()
        );
        assert_eq!(
            decrypt(cipher.as_ref(), &config, &stored, 42).unwrap(),
            b"/abs/dir/foo"
        );
        assert!(config.symlink_target_depends_on_path());
    }
}
