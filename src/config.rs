use anyhow::{Context, Result};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use log::debug;
use serde::Deserialize;
use std::fs::File;
use std::io::{Read, Write};
use std::path::Path;

/// Config format version
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ConfigType {
    #[default]
    None,
    Prehistoric, // V1, V2 - not supported
    V3,          // .encfs3 - not supported
    V4,          // .encfs4 - legacy binary format
    V5,          // .encfs5 - binary format
    V6,          // .encfs6.xml - XML format
}

#[derive(Debug, Deserialize)]
pub struct BoostSerialization {
    pub cfg: EncfsConfig,
}

#[derive(Debug, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct EncfsConfig {
    /// Config format type (not serialized, set during load)
    #[serde(skip, default)]
    pub config_type: ConfigType,

    #[allow(dead_code)]
    pub creator: String,
    #[allow(dead_code)]
    pub version: i32, // Was sub_version

    #[serde(rename = "cipherAlg")]
    pub cipher_iface: Interface,

    #[serde(rename = "nameAlg")]
    pub name_iface: Interface,

    pub key_size: i32,
    pub block_size: i32,

    #[serde(rename = "encodedKeyData", with = "base64_serde")]
    pub key_data: Vec<u8>,

    #[serde(rename = "saltData", with = "base64_serde")]
    pub salt: Vec<u8>,

    #[serde(rename = "kdfIterations")]
    pub kdf_iterations: i32,

    #[serde(rename = "desiredKDFDuration")]
    #[allow(dead_code)]
    pub desired_kdf_duration: i64,

    #[serde(rename = "plainData", default)]
    #[allow(dead_code)]
    pub plain_data: bool,

    #[serde(rename = "blockMACBytes", default)]
    pub block_mac_bytes: i32,

    #[serde(rename = "blockMACRandBytes", default)]
    #[allow(dead_code)]
    pub block_mac_rand_bytes: i32,

    #[serde(rename = "uniqueIV", default)]
    #[allow(dead_code)]
    pub unique_iv: bool,

    #[serde(rename = "externalIVChaining", default)]
    pub external_iv_chaining: bool,

    #[serde(rename = "chainedNameIV", default)]
    pub chained_name_iv: bool,

    #[serde(rename = "allowHoles", default)]
    #[allow(dead_code)]
    pub allow_holes: bool,
}

#[derive(Debug, Deserialize, Default, Clone, PartialEq)]
pub struct Interface {
    pub name: String,
    #[allow(dead_code)]
    pub major: i32,
    #[allow(dead_code)]
    pub minor: i32,
    #[allow(dead_code)]
    #[serde(skip, default)]
    pub age: i32,
}

impl Interface {
    pub fn from_config_var(var: &mut crate::config_binary::ConfigVar) -> Result<Self> {
        let name = var.read_string()?;
        let major = var.read_int()?;
        let minor = var.read_int()?;
        let age = var.read_int()?;
        Ok(Self {
            name,
            major,
            minor,
            age,
        })
    }
}

mod base64_serde {
    use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
    use serde::{Deserialize, Deserializer};

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        // Remove newlines and whitespace if present
        let s = s.replace(['\n', '\r', ' ', '\t'], "");
        BASE64.decode(s).map_err(serde::de::Error::custom)
    }
}

impl EncfsConfig {
    pub fn load(path: &Path) -> Result<Self> {
        let mut file = File::open(path).context("Failed to open config file")?;
        let mut content_bytes = Vec::new();
        file.read_to_end(&mut content_bytes)
            .context("Failed to read config file")?;

        // Determine config type from filename
        let filename = path.file_name().and_then(|s| s.to_str()).unwrap_or("");

        // Check for V3 (not supported)
        if filename == ".encfs3" {
            return Err(anyhow::anyhow!(
                "Version 3 configuration files are not supported. \
                 This is a very old EncFS format."
            ));
        }

        // Try load as XML first (current format - V6)
        // Requires valid UTF-8.
        if let Ok(content_str) = std::str::from_utf8(&content_bytes) {
            match quick_xml::de::from_str::<BoostSerialization>(content_str) {
                Ok(wrapper) => {
                    let mut cfg = wrapper.cfg;
                    cfg.config_type = ConfigType::V6;
                    cfg.validate()?;
                    return Ok(cfg);
                }
                Err(e) => {
                    // Helpful for debugging why XML load failed, but avoid printing from a library.
                    debug!("Failed to parse XML config: {e}");
                }
            }
        }

        // Check for V4 format (.encfs4)
        if filename == ".encfs4" {
            return Self::load_v4(&content_bytes);
        }

        // Fallback to V5 binary config
        Self::load_v5(&content_bytes)
    }

    pub(crate) fn validate(&self) -> Result<()> {
        // Basic sanity checks to avoid negative sizes turning into huge `u64` via casts.
        if self.plain_data {
            return Err(anyhow::anyhow!(
                "plainData=1 is not supported by this implementation"
            ));
        }
        if !self.unique_iv && self.config_type != ConfigType::V4 {
            return Err(anyhow::anyhow!(
                "uniqueIV=0 is not supported by this implementation"
            ));
        }
        if self.key_size <= 0 || self.key_size % 8 != 0 {
            return Err(anyhow::anyhow!(
                "Invalid keySize {} (must be positive and a multiple of 8)",
                self.key_size
            ));
        }
        if self.block_size <= 0 {
            return Err(anyhow::anyhow!(
                "Invalid blockSize {} (must be positive)",
                self.block_size
            ));
        }
        if self.block_mac_bytes < 0 || self.block_mac_bytes > 8 {
            return Err(anyhow::anyhow!(
                "Invalid blockMACBytes {} (must be in 0..=8)",
                self.block_mac_bytes
            ));
        }
        if self.block_mac_rand_bytes < 0 {
            return Err(anyhow::anyhow!(
                "Invalid blockMACRandBytes {} (must be >= 0)",
                self.block_mac_rand_bytes
            ));
        }
        if self.block_mac_rand_bytes != 0 {
            return Err(anyhow::anyhow!(
                "blockMACRandBytes={} is not supported yet",
                self.block_mac_rand_bytes
            ));
        }
        if self.block_mac_bytes + self.block_mac_rand_bytes >= self.block_size {
            return Err(anyhow::anyhow!(
                "Invalid block header sizes: blockSize={} blockMACBytes={} blockMACRandBytes={}",
                self.block_size,
                self.block_mac_bytes,
                self.block_mac_rand_bytes
            ));
        }
        if self.kdf_iterations < 0 {
            return Err(anyhow::anyhow!(
                "Invalid kdfIterations {} (must be >= 0)",
                self.kdf_iterations
            ));
        }
        Ok(())
    }

    /// Load V4 format config (.encfs4)
    /// V4 is an older binary format with minimal fields and hardcoded defaults
    fn load_v4(data: &[u8]) -> Result<Self> {
        let reader = crate::config_binary::ConfigReader::new(data)?;

        // V4 has: cipher, keySize, blockSize, keyData
        // All other values use defaults
        let mut cipher_iface = Interface::default();
        if let Some(mut var) = reader.get("cipher") {
            cipher_iface = Interface::from_config_var(&mut var)?;
        }

        let key_size = reader
            .get("keySize")
            .ok_or_else(|| anyhow::anyhow!("Missing keySize"))?
            .read_int()?;

        let block_size = reader
            .get("blockSize")
            .ok_or_else(|| anyhow::anyhow!("Missing blockSize"))?
            .read_int()?;

        let key_data = reader
            .get("keyData")
            .ok_or_else(|| anyhow::anyhow!("Missing keyData"))?
            .read_u8_vector()?;

        // V4 defaults - stream name encoding
        let name_iface = Interface {
            name: "nameio/stream".to_string(),
            major: 1,
            minor: 0,
            age: 0,
        };

        let cfg = EncfsConfig {
            config_type: ConfigType::V4,
            creator: "EncFS 1.0.x".to_string(),
            version: 0, // V4 didn't have subVersion
            cipher_iface,
            name_iface,
            key_size,
            block_size,
            key_data,
            salt: vec![],      // V4 didn't have salt
            kdf_iterations: 0, // V4 didn't have PBKDF2 iterations
            desired_kdf_duration: 0,
            plain_data: false,
            block_mac_bytes: 0,
            block_mac_rand_bytes: 0,
            unique_iv: false,
            external_iv_chaining: false,
            chained_name_iv: false,
            allow_holes: false,
        };
        cfg.validate()?;
        Ok(cfg)
    }

    /// Load V5 format config (.encfs5)
    fn load_v5(data: &[u8]) -> Result<Self> {
        let reader = crate::config_binary::ConfigReader::new(data)?;

        let sub_version = reader
            .get("subVersion")
            .ok_or_else(|| anyhow::anyhow!("Missing subVersion"))?
            .read_int_default(0);

        if sub_version < 20040813 {
            return Err(anyhow::anyhow!("Unsupported old version: {}", sub_version));
        }

        let creator = reader
            .get("creator")
            .ok_or_else(|| anyhow::anyhow!("Missing creator"))?
            .read_string()?;

        let mut cipher_iface = Interface::default();
        if let Some(mut var) = reader.get("cipher") {
            cipher_iface = Interface::from_config_var(&mut var)?;
        }

        let mut name_iface = Interface::default();
        if let Some(mut var) = reader.get("naming") {
            name_iface = Interface::from_config_var(&mut var)?;
        }

        let key_size = reader
            .get("keySize")
            .ok_or_else(|| anyhow::anyhow!("Missing keySize"))?
            .read_int()?;

        let block_size = reader
            .get("blockSize")
            .ok_or_else(|| anyhow::anyhow!("Missing blockSize"))?
            .read_int()?;

        let key_data = reader
            .get("keyData")
            .ok_or_else(|| anyhow::anyhow!("Missing keyData"))?
            .read_u8_vector()?;

        let unique_iv = reader
            .get("uniqueIV")
            .map(|mut v| v.read_bool(false))
            .unwrap_or(false);
        let chained_name_iv = reader
            .get("chainedIV")
            .map(|mut v| v.read_bool(false))
            .unwrap_or(false);
        let external_iv_chaining = reader
            .get("externalIV")
            .map(|mut v| v.read_bool(false))
            .unwrap_or(false);
        let block_mac_bytes = reader
            .get("blockMACBytes")
            .map(|mut v| v.read_int_default(0))
            .unwrap_or(0);
        let block_mac_rand_bytes = reader
            .get("blockMACRandBytes")
            .map(|mut v| v.read_int_default(0))
            .unwrap_or(0);

        let cfg = EncfsConfig {
            config_type: ConfigType::V5,
            creator,
            version: sub_version,
            cipher_iface,
            name_iface,
            key_size,
            block_size,
            key_data,
            salt: vec![],      // V5 didn't have salt
            kdf_iterations: 0, // V5 didn't have PBKDF2 iterations
            desired_kdf_duration: 0,
            plain_data: false,
            block_mac_bytes,
            block_mac_rand_bytes,
            unique_iv,
            external_iv_chaining,
            chained_name_iv,
            allow_holes: false,
        };
        cfg.validate()?;
        Ok(cfg)
    }

    pub fn get_cipher(&self, password: &str) -> Result<crate::crypto::ssl::SslCipher> {
        use crate::crypto::ssl::SslCipher;

        self.validate()?;
        let mut cipher = SslCipher::new(&self.cipher_iface, self.key_size)?;

        let key_len = usize::try_from(self.key_size / 8)
            .map_err(|_| anyhow::anyhow!("Unsupported key size {}", self.key_size))?;
        let iv_len = cipher.iv_len();
        let user_key_len = key_len + iv_len;

        let user_key_blob = if self.kdf_iterations > 0 {
            SslCipher::derive_key(password, &self.salt, self.kdf_iterations, user_key_len)?
        } else {
            SslCipher::derive_key_legacy(password, key_len, iv_len)?
        };

        // Split user_key_blob into key and IV
        let user_key = &user_key_blob[..key_len];
        let user_iv = &user_key_blob[key_len..];

        // Decrypt volume key
        let volume_key_blob = if self.kdf_iterations > 0 {
            cipher.decrypt_key(&self.key_data, user_key, user_iv)?
        } else {
            cipher.decrypt_key_legacy(&self.key_data, user_key, user_iv)?
        };

        if volume_key_blob.len() < key_len + iv_len {
            return Err(anyhow::anyhow!("Decrypted key blob too short"));
        }

        let volume_key = &volume_key_blob[..key_len];
        let volume_iv = &volume_key_blob[key_len..key_len + iv_len];

        cipher.set_key(volume_key, volume_iv);
        cipher.set_name_encoding(&self.name_iface);

        Ok(cipher)
    }
}

impl EncfsConfig {
    /// Saves the configuration to a file.
    /// Supports both XML (V6) and binary (V5) formats based on file extension.
    pub fn save(&self, path: &Path) -> Result<()> {
        if self.config_type == ConfigType::V6
            && path.extension().and_then(|s| s.to_str()) == Some("xml")
        {
            self.save_xml(path)
        } else {
            // For V5 or other binary formats, we don't support saving yet.
            // We return an error rather than silently saving to a different file (e.g. .encfs6.xml)
            // which would break tools expecting the config at the provided path.
            Err(anyhow::anyhow!(
                "Binary config format (V5) save not yet implemented"
            ))
        }
    }

    /// Saves the configuration file as XML, emulating the Boost Serialization format
    /// used for V6 configs.
    fn save_xml(&self, path: &Path) -> Result<()> {
        let mut file = File::create(path).context("Failed to create config file")?;

        // Write XML header
        writeln!(file, "<?xml version=\"1.0\" encoding=\"UTF-8\"?>")?;
        writeln!(file, "<!DOCTYPE boost_serialization>")?;
        writeln!(
            file,
            "<boost_serialization signature=\"serialization::archive\" version=\"7\">"
        )?;
        writeln!(
            file,
            "    <cfg class_id=\"0\" tracking_level=\"0\" version=\"20\">"
        )?;

        // Write version
        writeln!(file, "        <version>{}</version>", self.version)?;

        // Write creator
        writeln!(file, "        <creator>{}</creator>", self.creator)?;

        // Write cipherAlg
        writeln!(
            file,
            "        <cipherAlg class_id=\"1\" tracking_level=\"0\" version=\"0\">"
        )?;
        writeln!(file, "            <name>{}</name>", self.cipher_iface.name)?;
        writeln!(
            file,
            "            <major>{}</major>",
            self.cipher_iface.major
        )?;
        writeln!(
            file,
            "            <minor>{}</minor>",
            self.cipher_iface.minor
        )?;
        writeln!(file, "        </cipherAlg>")?;

        // Write nameAlg
        writeln!(file, "        <nameAlg>")?;
        writeln!(file, "            <name>{}</name>", self.name_iface.name)?;
        writeln!(file, "            <major>{}</major>", self.name_iface.major)?;
        writeln!(file, "            <minor>{}</minor>", self.name_iface.minor)?;
        writeln!(file, "        </nameAlg>")?;

        // Write other fields
        writeln!(file, "        <keySize>{}</keySize>", self.key_size)?;
        writeln!(file, "        <blockSize>{}</blockSize>", self.block_size)?;
        writeln!(
            file,
            "        <plainData>{}</plainData>",
            if self.plain_data { 1 } else { 0 }
        )?;
        writeln!(
            file,
            "        <uniqueIV>{}</uniqueIV>",
            if self.unique_iv { 1 } else { 0 }
        )?;
        writeln!(
            file,
            "        <chainedNameIV>{}</chainedNameIV>",
            if self.chained_name_iv { 1 } else { 0 }
        )?;
        writeln!(
            file,
            "        <externalIVChaining>{}</externalIVChaining>",
            if self.external_iv_chaining { 1 } else { 0 }
        )?;
        writeln!(
            file,
            "        <blockMACBytes>{}</blockMACBytes>",
            self.block_mac_bytes
        )?;
        writeln!(
            file,
            "        <blockMACRandBytes>{}</blockMACRandBytes>",
            self.block_mac_rand_bytes
        )?;
        writeln!(
            file,
            "        <allowHoles>{}</allowHoles>",
            if self.allow_holes { 1 } else { 0 }
        )?;

        // Write encodedKeySize and encodedKeyData
        writeln!(
            file,
            "        <encodedKeySize>{}</encodedKeySize>",
            self.key_data.len()
        )?;
        writeln!(file, "        <encodedKeyData>")?;
        let key_data_b64 = BASE64.encode(&self.key_data);
        // Split into lines of reasonable length (76 chars is standard)
        for chunk in key_data_b64.as_bytes().chunks(76) {
            writeln!(file, "{}", String::from_utf8_lossy(chunk))?;
        }
        writeln!(file, "</encodedKeyData>")?;

        // Write saltLen and saltData
        writeln!(file, "        <saltLen>{}</saltLen>", self.salt.len())?;
        writeln!(file, "        <saltData>")?;
        let salt_b64 = BASE64.encode(&self.salt);
        for chunk in salt_b64.as_bytes().chunks(76) {
            writeln!(file, "{}", String::from_utf8_lossy(chunk))?;
        }
        writeln!(file, "</saltData>")?;

        // Write KDF fields
        writeln!(
            file,
            "        <kdfIterations>{}</kdfIterations>",
            self.kdf_iterations
        )?;
        writeln!(
            file,
            "        <desiredKDFDuration>{}</desiredKDFDuration>",
            self.desired_kdf_duration
        )?;

        // Close tags
        writeln!(file, "    </cfg>")?;
        writeln!(file, "</boost_serialization>")?;

        Ok(())
    }
}

impl crate::crypto::ssl::SslCipher {
    pub fn iv_len(&self) -> usize {
        self.iv_len
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn test_config_roundway() -> Result<()> {
        let fixture_path = Path::new("tests/fixtures/encfs6-std.xml");

        // 1. Load the existing fixture config
        // Note: We need to make sure we're running from the project root usually.
        // If not found, panic with a helpful message.
        if !fixture_path.exists() {
            panic!(
                "Fixture not found at {:?}. Current Dir: {:?}",
                fixture_path,
                std::env::current_dir().unwrap_or_default()
            );
        }
        let loaded_config = EncfsConfig::load(fixture_path)?;

        // Verify some fields to ensure it parsed correctly
        assert_eq!(loaded_config.creator, "EncFS 1.9.5");
        assert_eq!(loaded_config.cipher_iface.name, "ssl/aes");
        assert_eq!(loaded_config.key_size, 192);

        // 2. Save the config to a new temp file
        let dir = std::env::temp_dir();
        let saved_path = dir.join(format!("encfs_test_saved_{}.xml", std::process::id()));
        loaded_config.save(&saved_path)?;

        // 3. Load the saved config
        let reloaded_config = EncfsConfig::load(&saved_path)?;

        // 4. Compare
        assert_eq!(loaded_config, reloaded_config);

        // 5. Compare text content
        let original_text = fs::read_to_string(fixture_path)?;
        let saved_text = fs::read_to_string(&saved_path)?;
        assert_eq!(
            original_text, saved_text,
            "Saved XML text differs from original"
        );

        // Cleanup
        let _ = fs::remove_file(saved_path);

        Ok(())
    }
    fn create_test_config() -> EncfsConfig {
        EncfsConfig {
            config_type: ConfigType::V6,
            creator: "test".to_string(),
            version: 20100713,
            cipher_iface: Interface {
                name: "ssl/aes".to_string(),
                major: 3,
                minor: 0,
                age: 0,
            },
            name_iface: Interface::default(),
            key_size: 192,
            block_size: 1024,
            key_data: vec![],
            salt: vec![],
            kdf_iterations: 1,
            desired_kdf_duration: 0,
            plain_data: false,
            block_mac_bytes: 0,
            block_mac_rand_bytes: 0,
            unique_iv: true,
            external_iv_chaining: false,
            chained_name_iv: true,
            allow_holes: false,
        }
    }

    #[test]
    fn test_validate_invalid_key_size() {
        let mut config = create_test_config();
        config.key_size = 190; // Not multiple of 8

        assert!(config.validate().is_err());

        config.key_size = 0;
        assert!(config.validate().is_err());

        config.key_size = -8;
        assert!(config.validate().is_err());

        config.key_size = 192;
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_validate_invalid_block_size() {
        let mut config = create_test_config();
        config.block_size = 0;
        assert!(config.validate().is_err());

        config.block_size = -1024;
        assert!(config.validate().is_err());

        config.block_size = 1024;
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_validate_block_size_too_small_for_mac() {
        let mut config = create_test_config();
        config.block_size = 8;
        config.block_mac_bytes = 8;
        // block_size (8) <= block_mac_bytes (8) is invalid
        assert!(config.validate().is_err()); // "Invalid block header sizes"

        config.block_size = 9;
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_validate_unsupported_flags() {
        let mut config = create_test_config();
        config.plain_data = true;
        assert!(config.validate().is_err());

        config.plain_data = false;
        config.block_mac_rand_bytes = 4;
        assert!(config.validate().is_err());

        config.block_mac_rand_bytes = 0;
        assert!(config.validate().is_ok());
    }
}
