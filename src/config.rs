use anyhow::{Context, Result};
use log::debug;
use rust_i18n::t;
use serde::{Deserialize, Serialize};
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
    V7,          // .encfs7 / .encfs7.pb - protobuf format with AEAD key wrap
}

/// Key derivation function algorithm
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum KdfAlgorithm {
    #[default]
    Pbkdf2, // PBKDF2-HMAC-SHA1 (legacy default)
    Argon2id, // Argon2id (recommended for new configs)
}

/// V7 protobuf file magic header ("ENCFS7\\0").
const V7_MAGIC: &[u8; 7] = b"ENCFS7\0";

#[derive(Debug, Deserialize)]
pub struct BoostSerialization {
    pub cfg: EncfsConfig,
}

#[derive(Debug, Deserialize, PartialEq, Clone)]
#[serde(rename_all = "camelCase")]
pub struct EncfsConfig {
    /// Config format type (not serialized, set during load)
    #[serde(skip, default)]
    pub config_type: ConfigType,

    pub creator: String,
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
    pub desired_kdf_duration: i64,

    /// Key derivation function algorithm (defaults to PBKDF2 for backward compatibility)
    #[serde(rename = "kdfAlgorithm", default, with = "kdf_algorithm_serde")]
    pub kdf_algorithm: KdfAlgorithm,

    /// Argon2 memory cost in KiB (only used when kdf_algorithm is Argon2id)
    #[serde(rename = "argon2MemoryCost", default)]
    pub argon2_memory_cost: Option<u32>,

    /// Argon2 time cost (iterations, only used when kdf_algorithm is Argon2id)
    #[serde(rename = "argon2TimeCost", default)]
    pub argon2_time_cost: Option<u32>,

    /// Argon2 parallelism (threads, only used when kdf_algorithm is Argon2id)
    #[serde(rename = "argon2Parallelism", default)]
    pub argon2_parallelism: Option<u32>,

    #[serde(rename = "plainData", default)]
    pub plain_data: bool,

    #[serde(rename = "blockMACBytes", default)]
    pub block_mac_bytes: i32,

    #[serde(rename = "blockMACRandBytes", default)]
    pub block_mac_rand_bytes: i32,

    #[serde(rename = "uniqueIV", default)]
    pub unique_iv: bool,

    #[serde(rename = "externalIVChaining", default)]
    pub external_iv_chaining: bool,

    #[serde(rename = "chainedNameIV", default)]
    pub chained_name_iv: bool,

    #[serde(rename = "allowHoles", default)]
    pub allow_holes: bool,

    /// Config hash for V7 AEAD AAD (set on load, not serialized).
    #[serde(skip, default)]
    pub config_hash: Option<Vec<u8>>,
}

#[derive(Debug, Deserialize, Default, Clone, PartialEq)]
pub struct Interface {
    pub name: String,
    pub major: i32,
    pub minor: i32,
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
    use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
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

mod kdf_algorithm_serde {
    use super::KdfAlgorithm;
    use serde::{Deserialize, Deserializer};

    pub fn deserialize<'de, D>(deserializer: D) -> Result<KdfAlgorithm, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = Option::<String>::deserialize(deserializer)?;
        match s.as_deref() {
            None | Some("pbkdf2") => Ok(KdfAlgorithm::Pbkdf2),
            Some("argon2id") => Ok(KdfAlgorithm::Argon2id),
            Some(other) => Err(serde::de::Error::custom(format!(
                "Unknown KDF algorithm: {}",
                other
            ))),
        }
    }
}

impl EncfsConfig {
    /// Returns a new V7 config with standard settings (AES-256, stream naming, Argon2id).
    /// New V7 configs default to AES-GCM-SIV block mode (16-byte tag per block).
    /// Caller must set random salt and call set_v7_key before save.
    pub fn standard_v7() -> Self {
        Self {
            config_type: ConfigType::V7,
            creator: "encfs-rust".to_string(),
            version: crate::constants::DEFAULT_CONFIG_VERSION,
            cipher_iface: Interface {
                name: "ssl/aes".to_string(),
                major: 3,
                minor: 0,
                age: 0,
            },
            name_iface: Interface {
                name: "nameio/stream".to_string(),
                major: 2,
                minor: 0,
                age: 0,
            },
            key_size: 256,
            block_size: crate::constants::DEFAULT_BLOCK_SIZE,
            key_data: vec![],
            salt: vec![0u8; crate::constants::DEFAULT_SALT_SIZE],
            kdf_iterations: 0,
            desired_kdf_duration: 0,
            kdf_algorithm: KdfAlgorithm::Argon2id,
            argon2_memory_cost: Some(crate::constants::DEFAULT_ARGON2_MEMORY_COST),
            argon2_time_cost: Some(crate::constants::DEFAULT_ARGON2_TIME_COST),
            argon2_parallelism: Some(crate::constants::DEFAULT_ARGON2_PARALLELISM),
            plain_data: false,
            block_mac_bytes: crate::crypto::block::AES_GCM_SIV_BLOCK_TAG_BYTES as i32,
            block_mac_rand_bytes: 0,
            unique_iv: true,
            external_iv_chaining: false,
            chained_name_iv: true,
            allow_holes: false,
            config_hash: None,
        }
    }

    pub fn load(path: &Path) -> Result<Self> {
        let mut file = File::open(path).context("Failed to open config file")?;
        let mut content_bytes = Vec::new();
        file.read_to_end(&mut content_bytes)
            .context("Failed to read config file")?;

        // Check for V7 magic header regardless of filename
        if content_bytes.starts_with(V7_MAGIC) {
            return Self::load_v7(&content_bytes);
        }

        // Determine config type from filename
        let filename = path.file_name().and_then(|s| s.to_str()).unwrap_or("");

        // Check for V3 (not supported)
        if filename == ".encfs3" {
            return Err(anyhow::anyhow!(
                "{}",
                t!("lib.error_version3_not_supported")
            ));
        }

        // Check for V7 protobuf format (.encfs7, *.encfs7, or *.encfs7.pb)
        if filename == ".encfs7"
            || filename.ends_with(".encfs7.pb")
            || filename.ends_with(".encfs7")
        {
            return Self::load_v7(&content_bytes);
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
        let legacy_max = crate::crypto::block::LEGACY_MAX_BLOCK_MAC_BYTES as i32;
        let gcm_siv_tag = crate::crypto::block::AES_GCM_SIV_BLOCK_TAG_BYTES as i32;
        if self.block_mac_bytes < 0 {
            return Err(anyhow::anyhow!(
                "Invalid blockMACBytes {} (must be >= 0)",
                self.block_mac_bytes
            ));
        }
        if self.config_type == ConfigType::V7 {
            if self.block_mac_bytes > legacy_max && self.block_mac_bytes != gcm_siv_tag {
                return Err(anyhow::anyhow!(
                    "Invalid V7 blockMACBytes {} (must be in 0..={} for legacy mode, or {} for AES-GCM-SIV mode)",
                    self.block_mac_bytes,
                    legacy_max,
                    gcm_siv_tag
                ));
            }
        } else if self.block_mac_bytes > legacy_max {
            return Err(anyhow::anyhow!(
                "Invalid blockMACBytes {} (must be in 0..={})",
                self.block_mac_bytes,
                legacy_max
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
        let block_overhead = match self.block_mode() {
            crate::crypto::block::BlockMode::Legacy => self.block_mac_bytes,
            crate::crypto::block::BlockMode::AesGcmSiv => {
                if self.config_type != ConfigType::V7 {
                    return Err(anyhow::anyhow!(
                        "AES-GCM-SIV block mode is only supported in V7 configs"
                    ));
                }
                if self.cipher_iface.name != "ssl/aes" {
                    return Err(anyhow::anyhow!(
                        "V7 AES-GCM-SIV block mode requires ssl/aes cipher (got {})",
                        self.cipher_iface.name
                    ));
                }
                if self.key_size != 128 && self.key_size != 256 {
                    return Err(anyhow::anyhow!(
                        "V7 AES-GCM-SIV block mode requires keySize 128 or 256 (got {})",
                        self.key_size
                    ));
                }
                gcm_siv_tag
            }
        };
        if block_overhead + self.block_mac_rand_bytes >= self.block_size {
            return Err(anyhow::anyhow!(
                "Invalid block header sizes: blockSize={} blockMACBytes={} blockMACRandBytes={}",
                self.block_size,
                block_overhead,
                self.block_mac_rand_bytes
            ));
        }
        if self.kdf_iterations < 0 {
            return Err(anyhow::anyhow!(
                "Invalid kdfIterations {} (must be >= 0)",
                self.kdf_iterations
            ));
        }

        // Validate Argon2 parameters if using Argon2id
        if self.kdf_algorithm == KdfAlgorithm::Argon2id {
            if self.argon2_memory_cost.is_none()
                || self.argon2_time_cost.is_none()
                || self.argon2_parallelism.is_none()
            {
                return Err(anyhow::anyhow!(
                    "Argon2id algorithm requires argon2MemoryCost, argon2TimeCost, and argon2Parallelism to be set"
                ));
            }

            let memory_cost = self.argon2_memory_cost.unwrap();
            let time_cost = self.argon2_time_cost.unwrap();
            let parallelism = self.argon2_parallelism.unwrap();

            if memory_cost < 8 {
                return Err(anyhow::anyhow!(
                    "Invalid argon2MemoryCost {} (must be at least 8 KiB)",
                    memory_cost
                ));
            }
            if time_cost < 1 {
                return Err(anyhow::anyhow!(
                    "Invalid argon2TimeCost {} (must be at least 1)",
                    time_cost
                ));
            }
            if parallelism < 1 {
                return Err(anyhow::anyhow!(
                    "Invalid argon2Parallelism {} (must be at least 1)",
                    parallelism
                ));
            }
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
            kdf_algorithm: KdfAlgorithm::Pbkdf2, // V4 uses legacy KDF
            argon2_memory_cost: None,
            argon2_time_cost: None,
            argon2_parallelism: None,
            plain_data: false,
            block_mac_bytes: 0,
            block_mac_rand_bytes: 0,
            unique_iv: false,
            external_iv_chaining: false,
            chained_name_iv: false,
            allow_holes: false,
            config_hash: None,
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

        if sub_version < crate::constants::V5_MIN_SUBVERSION {
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
            kdf_algorithm: KdfAlgorithm::Pbkdf2, // V5 uses legacy KDF
            argon2_memory_cost: None,
            argon2_time_cost: None,
            argon2_parallelism: None,
            plain_data: false,
            block_mac_bytes,
            block_mac_rand_bytes,
            unique_iv,
            external_iv_chaining,
            chained_name_iv,
            allow_holes: false,
            config_hash: None,
        };
        cfg.validate()?;
        Ok(cfg)
    }

    /// Decode V7 protobuf bytes (with optional magic header) into raw Config.
    /// Used by load_v7 and by encfsctl info --raw.
    pub fn decode_v7_proto(data: &[u8]) -> Result<crate::config_proto::Config> {
        use crate::config_proto::Config;
        use prost::Message;

        let proto_bytes = if data.starts_with(V7_MAGIC) {
            &data[V7_MAGIC.len()..]
        } else {
            data
        };
        Config::decode(proto_bytes).context("Failed to decode V7 config")
    }

    /// Load raw V7 protobuf from a path (for encfsctl info --raw).
    pub fn load_v7_proto(path: &Path) -> Result<crate::config_proto::Config> {
        let data = std::fs::read(path).context("Failed to read config file")?;
        Self::decode_v7_proto(&data)
    }

    /// Load V7 protobuf format (.encfs7 or *.encfs7.pb)
    fn load_v7(data: &[u8]) -> Result<Self> {
        let proto = Self::decode_v7_proto(data)?;

        let argon2 = proto
            .argon2
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("V7 config requires Argon2 KDF"))?;
        let name_encoding = proto
            .name_encoding
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("V7 config requires name_encoding"))?;

        let computed_hash = Self::v7_config_hash_from_proto(&proto);
        if !proto.config_hash.is_empty() && proto.config_hash != computed_hash {
            anyhow::bail!("V7 config hash mismatch (tampered or corrupted)");
        }
        let config_hash = if proto.config_hash.is_empty() {
            computed_hash
        } else {
            proto.config_hash.clone()
        };

        let key_data = proto.encrypted_key;
        let (cipher_iface, key_size, block_size, block_mac_bytes, block_mac_rand_bytes, unique_iv) =
            match proto.cipher {
                None => {
                    anyhow::bail!("V7 config requires a cipher");
                }
                Some(crate::config_proto::config::Cipher::Legacy(ref cipher)) => {
                    // BlockCipherAlgorithm::Aes = 1, Blowfish = 2.
                    let cipher_iface = match cipher.algorithm {
                        1 => Interface {
                            name: "ssl/aes".to_string(),
                            major: 3,
                            minor: 0,
                            age: 0,
                        },
                        2 => Interface {
                            name: "ssl/blowfish".to_string(),
                            major: 0,
                            minor: 0,
                            age: 0,
                        },
                        _ => anyhow::bail!("V7: unsupported block cipher algorithm"),
                    };

                    // Backward compatibility: older V7 configs could encode AES-GCM-SIV via
                    // the legacy cipher message using the 16-byte per-block tag sentinel.
                    let inferred_aead_from_mac = cipher.block_mac_bytes
                        == crate::crypto::block::AES_GCM_SIV_BLOCK_TAG_BYTES as i32;
                    let block_mac_bytes = if inferred_aead_from_mac {
                        crate::crypto::block::AES_GCM_SIV_BLOCK_TAG_BYTES as i32
                    } else {
                        cipher.block_mac_bytes
                    };

                    (
                        cipher_iface,
                        cipher.key_size,
                        cipher.block_size,
                        block_mac_bytes,
                        cipher.block_mac_rand_bytes,
                        cipher.unique_iv,
                    )
                }
                Some(crate::config_proto::config::Cipher::GcmSiv(ref cipher)) => (
                    Interface {
                        name: "ssl/aes".to_string(),
                        major: 3,
                        minor: 0,
                        age: 0,
                    },
                    cipher.key_size,
                    cipher.block_size,
                    crate::crypto::block::AES_GCM_SIV_BLOCK_TAG_BYTES as i32,
                    0,
                    cipher.unique_iv,
                ),
            };

        // NameEncodingMode::Stream = 1, Block = 2
        let name_iface = match name_encoding.mode {
            1 => Interface {
                name: "nameio/stream".to_string(),
                major: 2,
                minor: 0,
                age: 0,
            },
            2 => Interface {
                name: "nameio/block".to_string(),
                major: 4,
                minor: 0,
                age: 0,
            },
            _ => Interface {
                name: "nameio/stream".to_string(),
                major: 2,
                minor: 0,
                age: 0,
            },
        };

        let allow_holes = proto
            .feature_flags
            .as_ref()
            .map(|f| f.allow_holes)
            .unwrap_or(false);

        let cfg = EncfsConfig {
            config_type: ConfigType::V7,
            creator: "encfs-rust".to_string(),
            version: crate::constants::DEFAULT_CONFIG_VERSION,
            cipher_iface,
            name_iface,
            key_size,
            block_size,
            key_data,
            salt: argon2.salt.clone(),
            kdf_iterations: 0,
            desired_kdf_duration: 0,
            kdf_algorithm: KdfAlgorithm::Argon2id,
            argon2_memory_cost: Some(argon2.memory_cost_kib),
            argon2_time_cost: Some(argon2.time_cost),
            argon2_parallelism: Some(argon2.parallelism),
            plain_data: false,
            block_mac_bytes,
            block_mac_rand_bytes,
            unique_iv,
            external_iv_chaining: name_encoding.external_iv_chaining,
            chained_name_iv: name_encoding.chained_name_iv,
            allow_holes,
            config_hash: Some(config_hash),
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

        // V7: AEAD decrypt with config hash as AAD
        if self.config_type == ConfigType::V7 {
            let aad = self
                .config_hash
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("V7 config missing config_hash"))?;
            let user_key = SslCipher::derive_key_argon2id(
                password,
                &self.salt,
                self.argon2_memory_cost
                    .unwrap_or(crate::constants::DEFAULT_ARGON2_MEMORY_COST),
                self.argon2_time_cost
                    .unwrap_or(crate::constants::DEFAULT_ARGON2_TIME_COST),
                self.argon2_parallelism
                    .unwrap_or(crate::constants::DEFAULT_ARGON2_PARALLELISM),
                crate::crypto::aead::AEAD_KEY_LEN,
            )?;
            let volume_key_blob =
                crate::crypto::aead::decrypt(user_key.as_slice(), aad, &self.key_data)?;
            if volume_key_blob.len() < key_len + iv_len {
                return Err(anyhow::anyhow!("Decrypted key blob too short"));
            }
            let volume_key = &volume_key_blob[..key_len];
            let volume_iv = &volume_key_blob[key_len..key_len + iv_len];
            cipher.set_key(volume_key, volume_iv);
            cipher.set_name_encoding(&self.name_iface);
            return Ok(cipher);
        }

        // Derive user key based on configured KDF algorithm
        let user_key_blob = match self.kdf_algorithm {
            KdfAlgorithm::Pbkdf2 => {
                if self.kdf_iterations > 0 {
                    SslCipher::derive_key(password, &self.salt, self.kdf_iterations, user_key_len)?
                } else {
                    SslCipher::derive_key_legacy(password, key_len, iv_len)?
                }
            }
            KdfAlgorithm::Argon2id => {
                let memory_cost = self
                    .argon2_memory_cost
                    .unwrap_or(crate::constants::DEFAULT_ARGON2_MEMORY_COST);
                let time_cost = self
                    .argon2_time_cost
                    .unwrap_or(crate::constants::DEFAULT_ARGON2_TIME_COST);
                let parallelism = self
                    .argon2_parallelism
                    .unwrap_or(crate::constants::DEFAULT_ARGON2_PARALLELISM);

                SslCipher::derive_key_argon2id(
                    password,
                    &self.salt,
                    memory_cost,
                    time_cost,
                    parallelism,
                    user_key_len,
                )?
            }
        };

        // Split user_key_blob into key and IV
        let user_key = &user_key_blob[..key_len];
        let user_iv = &user_key_blob[key_len..];

        // Decrypt volume key
        let volume_key_blob =
            if self.kdf_iterations > 0 || self.kdf_algorithm == KdfAlgorithm::Argon2id {
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
    pub fn header_size(&self) -> u64 {
        if self.unique_iv { 8 } else { 0 }
    }

    pub fn block_mode(&self) -> crate::crypto::block::BlockMode {
        let block_mac = u64::try_from(self.block_mac_bytes.max(0)).unwrap_or(0);
        crate::crypto::block::BlockMode::from_config(self.config_type, block_mac)
    }

    pub fn block_overhead_bytes(&self) -> u64 {
        let block_mac = u64::try_from(self.block_mac_bytes.max(0)).unwrap_or(0);
        self.block_mode().overhead_bytes(block_mac)
    }

    /// Creates a default configuration useful for testing
    pub fn test_default() -> Self {
        Self {
            config_type: ConfigType::V6,
            creator: "test".to_string(),
            version: crate::constants::DEFAULT_CONFIG_VERSION,
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
            kdf_iterations: 0,
            desired_kdf_duration: 0,
            kdf_algorithm: KdfAlgorithm::Pbkdf2,
            argon2_memory_cost: None,
            argon2_time_cost: None,
            argon2_parallelism: None,
            plain_data: false,
            block_mac_bytes: 8,
            block_mac_rand_bytes: 0,
            unique_iv: true,
            external_iv_chaining: false,
            chained_name_iv: true,
            allow_holes: false,
            config_hash: None,
        }
    }
}

impl EncfsConfig {
    /// Saves the configuration to a file.
    /// Supports XML (V6) and protobuf (V7) based on config type or file extension.
    pub fn save(&self, path: &Path) -> Result<()> {
        let ext = path.extension().and_then(|s| s.to_str());
        let is_v7_path = path
            .file_name()
            .and_then(|s| s.to_str())
            .map(|s| s == ".encfs7" || s.ends_with(".encfs7.pb") || s.ends_with(".encfs7"))
            .unwrap_or(false);

        if self.config_type == ConfigType::V7 || is_v7_path {
            self.save_v7(path)
        } else if self.config_type == ConfigType::V6 && ext == Some("xml") {
            self.save_xml(path)
        } else {
            Err(anyhow::anyhow!(
                "Binary config format (V5) save not yet implemented"
            ))
        }
    }

    /// Saves the configuration file as XML, emulating the Boost Serialization format
    /// used for V6 configs.
    fn save_xml(&self, path: &Path) -> Result<()> {
        let file = File::create(path).context("Failed to create config file")?;
        let mut writer = std::io::BufWriter::new(file);

        let root = xml_ser::BoostSerializationRoot::from_config(self);

        // Write XML header and DOCTYPE manually as quick-xml doesn't support custom DOCTYPE well
        // with the default serializer, and we want exact control over the format.
        writer.write_all(b"<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n")?;
        writer.write_all(b"<!DOCTYPE boost_serialization>\n")?;

        let mut xml_buffer = String::new();
        let mut serializer = quick_xml::se::Serializer::new(&mut xml_buffer);
        serializer.indent(' ', 4);

        root.serialize(serializer)
            .context("Failed to serialize XML")?;

        writer.write_all(xml_buffer.as_bytes())?;

        // Append a newline at the end
        writer.write_all(b"\n")?;

        Ok(())
    }

    /// Encrypts the volume key with AEAD and sets key_data and config_hash for V7.
    /// Call this before save() when creating a new V7 config or changing the password.
    pub fn set_v7_key(&mut self, password: &str, volume_key_blob: &[u8]) -> Result<()> {
        use crate::crypto::aead;
        use crate::crypto::ssl::SslCipher;

        if self.config_type != ConfigType::V7 {
            anyhow::bail!("set_v7_key only applies to V7 config");
        }
        let memory_cost = self
            .argon2_memory_cost
            .ok_or_else(|| anyhow::anyhow!("V7 requires Argon2 params"))?;
        let time_cost = self
            .argon2_time_cost
            .ok_or_else(|| anyhow::anyhow!("V7 requires Argon2 params"))?;
        let parallelism = self
            .argon2_parallelism
            .ok_or_else(|| anyhow::anyhow!("V7 requires Argon2 params"))?;

        let proto = self.encfs_config_to_proto_v7();
        let config_hash = Self::v7_config_hash_from_proto(&proto);

        let user_key = SslCipher::derive_key_argon2id(
            password,
            &self.salt,
            memory_cost,
            time_cost,
            parallelism,
            aead::AEAD_KEY_LEN,
        )?;

        let encrypted_key = aead::encrypt(user_key.as_slice(), &config_hash, volume_key_blob)?;

        self.key_data = encrypted_key;
        self.config_hash = Some(config_hash);
        Ok(())
    }

    /// Saves the configuration as V7 protobuf (AEAD-wrapped key already in key_data).
    fn save_v7(&self, path: &Path) -> Result<()> {
        use prost::Message;

        let mut proto = self.encfs_config_to_proto_v7();
        let expected_hash = Self::v7_config_hash_from_proto(&proto);
        let stored_hash = self
            .config_hash
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("V7 config missing config_hash; call set_v7_key"))?;
        if stored_hash.as_slice() != expected_hash.as_slice() {
            anyhow::bail!("V7 config hash mismatch; call set_v7_key before saving");
        }
        proto.config_hash = expected_hash;
        let buf = proto.encode_to_vec();
        let file = File::create(path).context("Failed to create config file")?;
        let mut writer = std::io::BufWriter::new(file);
        writer
            .write_all(V7_MAGIC)
            .context("Failed to write V7 magic")?;
        writer
            .write_all(&buf)
            .context("Failed to write V7 config")?;
        Ok(())
    }

    /// Builds V7 protobuf Config from EncfsConfig (key_data is used as encrypted_key).
    fn encfs_config_to_proto_v7(&self) -> crate::config_proto::Config {
        use crate::config_proto::{
            AesGcmSivBlockCipher, Argon2Kdf, BasicBlockCipher, BlockCipherAlgorithm, Config,
            FeatureFlags, NameEncoding, NameEncodingMode,
        };

        let algorithm = match self.cipher_iface.name.as_str() {
            "ssl/aes" => BlockCipherAlgorithm::Aes as i32,
            "ssl/blowfish" => BlockCipherAlgorithm::Blowfish as i32,
            _ => BlockCipherAlgorithm::Aes as i32,
        };

        let cipher = match self.block_mode() {
            crate::crypto::block::BlockMode::Legacy => Some(
                crate::config_proto::config::Cipher::Legacy(BasicBlockCipher {
                    algorithm,
                    key_size: self.key_size,
                    block_size: self.block_size,
                    block_mac_bytes: self.block_mac_bytes,
                    block_mac_rand_bytes: self.block_mac_rand_bytes,
                    unique_iv: self.unique_iv,
                }),
            ),
            crate::crypto::block::BlockMode::AesGcmSiv => Some(
                crate::config_proto::config::Cipher::GcmSiv(AesGcmSivBlockCipher {
                    key_size: self.key_size,
                    block_size: self.block_size,
                    unique_iv: self.unique_iv,
                }),
            ),
        };

        let mode = if self.name_iface.name == "nameio/block" {
            NameEncodingMode::Block as i32
        } else {
            NameEncodingMode::Stream as i32
        };

        let name_encoding = Some(NameEncoding {
            mode,
            chained_name_iv: self.chained_name_iv,
            external_iv_chaining: self.external_iv_chaining,
        });

        let argon2 = (self.argon2_memory_cost.is_some()
            && self.argon2_time_cost.is_some()
            && self.argon2_parallelism.is_some())
        .then(|| Argon2Kdf {
            salt: self.salt.clone(),
            memory_cost_kib: self.argon2_memory_cost.unwrap_or(0),
            time_cost: self.argon2_time_cost.unwrap_or(0),
            parallelism: self.argon2_parallelism.unwrap_or(0),
        });

        let feature_flags = Some(FeatureFlags {
            allow_holes: self.allow_holes,
        });

        Config {
            encrypted_key: self.key_data.clone(),
            argon2,
            cipher,
            name_encoding,
            feature_flags,
            config_hash: self.config_hash.clone().unwrap_or_default(),
        }
    }

    /// Computes the V7 config hash (SHA-256 of protobuf with encrypted_key and config_hash cleared).
    fn v7_config_hash_from_proto(proto: &crate::config_proto::Config) -> Vec<u8> {
        use prost::Message;
        use sha2::{Digest, Sha256};

        let mut proto_for_hash = proto.clone();
        proto_for_hash.encrypted_key = Vec::new();
        proto_for_hash.config_hash = Vec::new();
        let config_bytes = proto_for_hash.encode_to_vec();
        Sha256::digest(&config_bytes).to_vec()
    }
}

mod xml_ser {
    use super::*;
    use serde::Serialize;

    #[derive(Serialize)]
    #[serde(rename = "boost_serialization")]
    pub struct BoostSerializationRoot<'a> {
        #[serde(rename = "@signature")]
        signature: &'static str,
        #[serde(rename = "@version")]
        version: &'static str,

        cfg: EncfsConfigXml<'a>,
    }

    impl<'a> BoostSerializationRoot<'a> {
        pub fn from_config(config: &'a EncfsConfig) -> Self {
            Self {
                signature: "serialization::archive",
                version: "7",
                cfg: EncfsConfigXml::from_config(config),
            }
        }
    }

    #[derive(Serialize)]
    struct EncfsConfigXml<'a> {
        #[serde(rename = "@class_id")]
        class_id: &'static str,
        #[serde(rename = "@tracking_level")]
        tracking_level: &'static str,
        #[serde(rename = "@version")]
        version_attr: &'static str,

        version: i32,
        creator: &'a str,

        #[serde(rename = "cipherAlg")]
        cipher_alg: InterfaceXml<'a>,

        #[serde(rename = "nameAlg")]
        name_alg: InterfaceXml<'a>,

        #[serde(rename = "keySize")]
        key_size: i32,

        #[serde(rename = "blockSize")]
        block_size: i32,

        #[serde(rename = "plainData")]
        plain_data: u8,

        #[serde(rename = "uniqueIV")]
        unique_iv: u8,

        #[serde(rename = "chainedNameIV")]
        chained_name_iv: u8,

        #[serde(rename = "externalIVChaining")]
        external_iv_chaining: u8,

        #[serde(rename = "blockMACBytes")]
        block_mac_bytes: i32,

        #[serde(rename = "blockMACRandBytes")]
        block_mac_rand_bytes: i32,

        #[serde(rename = "allowHoles")]
        allow_holes: u8,

        #[serde(rename = "encodedKeySize")]
        encoded_key_size: usize,

        #[serde(rename = "encodedKeyData")]
        encoded_key_data: Base64Xml<'a>,

        #[serde(rename = "saltLen")]
        salt_len: usize,

        #[serde(rename = "saltData")]
        salt_data: Base64Xml<'a>,

        #[serde(rename = "kdfIterations")]
        kdf_iterations: i32,

        #[serde(rename = "desiredKDFDuration")]
        desired_kdf_duration: i64,

        #[serde(rename = "kdfAlgorithm", skip_serializing_if = "Option::is_none")]
        kdf_algorithm: Option<&'static str>,

        #[serde(rename = "argon2MemoryCost", skip_serializing_if = "Option::is_none")]
        argon2_memory_cost: Option<u32>,

        #[serde(rename = "argon2TimeCost", skip_serializing_if = "Option::is_none")]
        argon2_time_cost: Option<u32>,

        #[serde(rename = "argon2Parallelism", skip_serializing_if = "Option::is_none")]
        argon2_parallelism: Option<u32>,
    }

    impl<'a> EncfsConfigXml<'a> {
        fn from_config(config: &'a EncfsConfig) -> Self {
            let (kdf_algorithm, argon2_memory_cost, argon2_time_cost, argon2_parallelism) =
                match config.kdf_algorithm {
                    KdfAlgorithm::Pbkdf2 => (None, None, None, None),
                    KdfAlgorithm::Argon2id => (
                        Some("argon2id"),
                        config.argon2_memory_cost,
                        config.argon2_time_cost,
                        config.argon2_parallelism,
                    ),
                };

            Self {
                class_id: "0",
                tracking_level: "0",
                version_attr: "20",
                version: config.version,
                creator: &config.creator,
                cipher_alg: InterfaceXml::new(&config.cipher_iface, "1"),
                name_alg: InterfaceXml::new(&config.name_iface, "0"),
                key_size: config.key_size,
                block_size: config.block_size,
                plain_data: if config.plain_data { 1 } else { 0 },
                unique_iv: if config.unique_iv { 1 } else { 0 },
                chained_name_iv: if config.chained_name_iv { 1 } else { 0 },
                external_iv_chaining: if config.external_iv_chaining { 1 } else { 0 },
                block_mac_bytes: config.block_mac_bytes,
                block_mac_rand_bytes: config.block_mac_rand_bytes,
                allow_holes: if config.allow_holes { 1 } else { 0 },
                encoded_key_size: config.key_data.len(),
                encoded_key_data: Base64Xml {
                    data: &config.key_data,
                },
                salt_len: config.salt.len(),
                salt_data: Base64Xml { data: &config.salt },
                kdf_iterations: config.kdf_iterations,
                desired_kdf_duration: config.desired_kdf_duration,
                kdf_algorithm,
                argon2_memory_cost,
                argon2_time_cost,
                argon2_parallelism,
            }
        }
    }

    #[derive(Serialize)]
    struct InterfaceXml<'a> {
        #[serde(rename = "@class_id", skip_serializing_if = "Option::is_none")]
        class_id: Option<&'static str>,
        #[serde(rename = "@tracking_level", skip_serializing_if = "Option::is_none")]
        tracking_level: Option<&'static str>,
        #[serde(rename = "@version", skip_serializing_if = "Option::is_none")]
        version: Option<&'static str>,

        name: &'a str,
        major: i32,
        minor: i32,
    }

    impl<'a> InterfaceXml<'a> {
        fn new(iface: &'a Interface, class_id: &'static str) -> Self {
            let (cid, tl, v) = if class_id == "1" {
                (Some("1"), Some("0"), Some("0"))
            } else {
                (None, None, None)
            };

            Self {
                class_id: cid,
                tracking_level: tl,
                version: v,
                name: &iface.name,
                major: iface.major,
                minor: iface.minor,
            }
        }
    }

    struct Base64Xml<'a> {
        data: &'a [u8],
    }

    impl Serialize for Base64Xml<'_> {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: serde::Serializer,
        {
            use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
            let encoded = BASE64.encode(self.data);
            serializer.serialize_str(&encoded)
        }
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

        // Cleanup
        let _ = fs::remove_file(saved_path);

        Ok(())
    }
    fn create_test_config() -> EncfsConfig {
        EncfsConfig {
            config_type: ConfigType::V6,
            creator: "test".to_string(),
            version: crate::constants::DEFAULT_CONFIG_VERSION,
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
            kdf_algorithm: KdfAlgorithm::Pbkdf2,
            argon2_memory_cost: None,
            argon2_time_cost: None,
            argon2_parallelism: None,
            plain_data: false,
            block_mac_bytes: 0,
            block_mac_rand_bytes: 0,
            unique_iv: true,
            external_iv_chaining: false,
            chained_name_iv: true,
            allow_holes: false,
            config_hash: None,
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

    #[test]
    fn test_argon2_config_validation() {
        let mut config = create_test_config();
        config.kdf_algorithm = KdfAlgorithm::Argon2id;

        // Missing Argon2 parameters should fail
        assert!(config.validate().is_err());

        // Add valid parameters
        config.argon2_memory_cost = Some(crate::constants::DEFAULT_ARGON2_MEMORY_COST);
        config.argon2_time_cost = Some(crate::constants::DEFAULT_ARGON2_TIME_COST);
        config.argon2_parallelism = Some(crate::constants::DEFAULT_ARGON2_PARALLELISM);
        assert!(config.validate().is_ok());

        // Invalid memory cost (too small)
        config.argon2_memory_cost = Some(4);
        assert!(config.validate().is_err());
        config.argon2_memory_cost = Some(crate::constants::DEFAULT_ARGON2_MEMORY_COST);

        // Invalid time cost
        config.argon2_time_cost = Some(0);
        assert!(config.validate().is_err());
        config.argon2_time_cost = Some(crate::constants::DEFAULT_ARGON2_TIME_COST);

        // Invalid parallelism
        config.argon2_parallelism = Some(0);
        assert!(config.validate().is_err());
        config.argon2_parallelism = Some(crate::constants::DEFAULT_ARGON2_PARALLELISM);

        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_argon2_config_roundtrip() -> Result<()> {
        use crate::crypto::ssl::SslCipher;
        use std::fs;

        // Create an Argon2id config
        let mut config = create_test_config();
        config.kdf_algorithm = KdfAlgorithm::Argon2id;
        config.argon2_memory_cost = Some(32768); // 32 MiB
        config.argon2_time_cost = Some(2);
        config.argon2_parallelism = Some(2);
        config.salt = vec![
            1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20,
        ];

        // Generate encrypted volume key
        let password = "test_password";
        let key_len = (config.key_size / 8) as usize;
        let cipher = SslCipher::new(&config.cipher_iface, config.key_size)?;
        let iv_len = cipher.iv_len();
        let user_key_len = key_len + iv_len;

        let user_key_blob = SslCipher::derive_key_argon2id(
            password,
            &config.salt,
            config.argon2_memory_cost.unwrap(),
            config.argon2_time_cost.unwrap(),
            config.argon2_parallelism.unwrap(),
            user_key_len,
        )?;

        let user_key = &user_key_blob[..key_len];
        let user_iv = &user_key_blob[key_len..];

        // Create a fake volume key
        let volume_key = vec![0u8; key_len];
        let volume_iv = vec![1u8; iv_len];
        let mut volume_blob = Vec::with_capacity(key_len + iv_len);
        volume_blob.extend_from_slice(&volume_key);
        volume_blob.extend_from_slice(&volume_iv);

        let encrypted_key = cipher.encrypt_key(&volume_blob, user_key, user_iv)?;
        config.key_data = encrypted_key;

        // Save config
        let dir = std::env::temp_dir();
        let config_path = dir.join(format!("encfs_argon2_test_{}.xml", std::process::id()));
        config.save(&config_path)?;

        // Load config
        let loaded_config = EncfsConfig::load(&config_path)?;

        // Verify fields
        assert_eq!(loaded_config.kdf_algorithm, KdfAlgorithm::Argon2id);
        assert_eq!(loaded_config.argon2_memory_cost, Some(32768));
        assert_eq!(loaded_config.argon2_time_cost, Some(2));
        assert_eq!(loaded_config.argon2_parallelism, Some(2));

        // Verify we can decrypt with the loaded config (cipher creation should succeed)
        let _cipher2 = loaded_config.get_cipher(password)?;

        // Cleanup
        let _ = fs::remove_file(config_path);

        Ok(())
    }

    #[test]
    fn test_pbkdf2_config_backward_compatibility() -> Result<()> {
        // Load existing PBKDF2 config (should default to PBKDF2 algorithm)
        let fixture_path = Path::new("tests/fixtures/encfs6-std.xml");
        if !fixture_path.exists() {
            // Skip test if fixture not available
            return Ok(());
        }

        let config = EncfsConfig::load(fixture_path)?;

        // Should default to PBKDF2
        assert_eq!(config.kdf_algorithm, KdfAlgorithm::Pbkdf2);
        assert_eq!(config.argon2_memory_cost, None);
        assert_eq!(config.argon2_time_cost, None);
        assert_eq!(config.argon2_parallelism, None);

        Ok(())
    }

    #[test]
    fn test_v7_config_roundtrip() -> Result<()> {
        let dir = std::env::temp_dir();
        let config_path = dir.join(format!("encfs_v7_test_{}.encfs7", std::process::id()));

        // Build a V7 config (minimal Argon2 for test speed)
        let mut config = EncfsConfig {
            config_type: ConfigType::V7,
            creator: "encfs-rust-test".to_string(),
            version: crate::constants::DEFAULT_CONFIG_VERSION,
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
            salt: vec![0u8; 16],
            kdf_iterations: 0,
            desired_kdf_duration: 0,
            kdf_algorithm: KdfAlgorithm::Argon2id,
            argon2_memory_cost: Some(256),
            argon2_time_cost: Some(1),
            argon2_parallelism: Some(1),
            plain_data: false,
            block_mac_bytes: 8,
            block_mac_rand_bytes: 0,
            unique_iv: true,
            external_iv_chaining: false,
            chained_name_iv: true,
            allow_holes: false,
            config_hash: None,
        };
        openssl::rand::rand_bytes(&mut config.salt).context("rand")?;

        // Volume key blob: key (24) + iv (16) for AES-192
        let key_len = (config.key_size / 8) as usize;
        let iv_len = 16;
        let mut volume_key_blob = vec![0u8; key_len + iv_len];
        openssl::rand::rand_bytes(&mut volume_key_blob).context("rand")?;

        let password = "test_password";
        config.set_v7_key(password, &volume_key_blob)?;
        config.save(&config_path)?;

        let loaded = EncfsConfig::load(&config_path)?;
        assert_eq!(loaded.config_type, ConfigType::V7);
        let cipher = loaded.get_cipher(password)?;
        // Cipher should be usable (key set)
        assert_eq!(cipher.iv_len(), iv_len);

        let _ = std::fs::remove_file(config_path);
        Ok(())
    }

    #[test]
    fn test_standard_v7_defaults_to_aes_gcm_siv_blocks() {
        let cfg = EncfsConfig::standard_v7();
        assert_eq!(cfg.config_type, ConfigType::V7);
        assert_eq!(cfg.key_size, 256);
        assert_eq!(cfg.block_mode(), crate::crypto::block::BlockMode::AesGcmSiv);
        assert_eq!(
            cfg.block_overhead_bytes(),
            crate::crypto::block::AES_GCM_SIV_BLOCK_TAG_BYTES
        );
        assert!(cfg.validate().is_ok());
    }

    #[test]
    fn test_v7_aes_gcm_siv_serializes_dedicated_cipher_message() {
        let cfg = EncfsConfig::standard_v7();
        let proto = cfg.encfs_config_to_proto_v7();

        match proto.cipher {
            Some(crate::config_proto::config::Cipher::GcmSiv(ref c)) => {
                assert_eq!(c.key_size, cfg.key_size);
                assert_eq!(c.block_size, cfg.block_size);
                assert_eq!(c.unique_iv, cfg.unique_iv);
            }
            other => panic!("expected GcmSiv cipher variant, got {:?}", other),
        }
    }

    #[test]
    fn test_v7_legacy_serializes_legacy_cipher_message() {
        let mut cfg = EncfsConfig::standard_v7();
        cfg.block_mac_bytes = 8;
        cfg.block_mac_rand_bytes = 0;

        let proto = cfg.encfs_config_to_proto_v7();

        match proto.cipher {
            Some(crate::config_proto::config::Cipher::Legacy(ref c)) => {
                assert_eq!(c.key_size, cfg.key_size);
                assert_eq!(c.block_size, cfg.block_size);
                assert_eq!(c.block_mac_bytes, cfg.block_mac_bytes);
                assert_eq!(c.block_mac_rand_bytes, cfg.block_mac_rand_bytes);
                assert_eq!(c.unique_iv, cfg.unique_iv);
            }
            other => panic!("expected Legacy cipher variant, got {:?}", other),
        }
    }

    #[test]
    fn test_v7_aes_gcm_siv_roundtrip() -> Result<()> {
        let dir = std::env::temp_dir();
        let config_path = dir.join(format!(
            "encfs_v7_gcm_siv_test_{}.encfs7",
            std::process::id()
        ));

        let mut config = EncfsConfig::standard_v7();
        openssl::rand::rand_bytes(&mut config.salt).context("rand")?;
        let key_len = (config.key_size / 8) as usize;
        let iv_len = 16;
        let mut volume_key_blob = vec![0u8; key_len + iv_len];
        openssl::rand::rand_bytes(&mut volume_key_blob).context("rand")?;

        let password = "test_password";
        config.set_v7_key(password, &volume_key_blob)?;
        config.save(&config_path)?;

        let loaded = EncfsConfig::load(&config_path)?;
        assert_eq!(
            loaded.block_mode(),
            crate::crypto::block::BlockMode::AesGcmSiv
        );
        assert_eq!(
            loaded.block_overhead_bytes(),
            crate::crypto::block::AES_GCM_SIV_BLOCK_TAG_BYTES
        );
        let _cipher = loaded.get_cipher(password)?;

        let _ = std::fs::remove_file(config_path);
        Ok(())
    }

    #[test]
    fn test_v7_config_tampered_fails() -> Result<()> {
        let dir = std::env::temp_dir();
        let config_path = dir.join(format!(
            "encfs_v7_tamper_test_{}.encfs7",
            std::process::id()
        ));

        let mut config = EncfsConfig {
            config_type: ConfigType::V7,
            creator: "test".to_string(),
            version: crate::constants::DEFAULT_CONFIG_VERSION,
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
            salt: vec![0u8; 16],
            kdf_iterations: 0,
            desired_kdf_duration: 0,
            kdf_algorithm: KdfAlgorithm::Argon2id,
            argon2_memory_cost: Some(256),
            argon2_time_cost: Some(1),
            argon2_parallelism: Some(1),
            plain_data: false,
            block_mac_bytes: 8,
            block_mac_rand_bytes: 0,
            unique_iv: true,
            external_iv_chaining: false,
            chained_name_iv: true,
            allow_holes: false,
            config_hash: None,
        };
        openssl::rand::rand_bytes(&mut config.salt).context("rand")?;
        let volume_key_blob = vec![0u8; (config.key_size / 8) as usize + 16];
        config.set_v7_key("pass", &volume_key_blob)?;
        config.save(&config_path)?;

        // Tamper: flip a byte in the file. This may corrupt protobuf (load fails) or change
        // the config hash (get_cipher AEAD verification fails). Either outcome is acceptable.
        let mut bytes = std::fs::read(&config_path)?;
        let idx = bytes.len().saturating_sub(10);
        bytes[idx] = bytes[idx].wrapping_add(1);
        std::fs::write(&config_path, &bytes)?;

        match EncfsConfig::load(&config_path) {
            Ok(loaded) => {
                let res = loaded.get_cipher("pass");
                assert!(
                    res.is_err(),
                    "get_cipher should fail on tampered config (AEAD verification)"
                );
            }
            Err(_) => {
                // Tampering corrupted protobuf; load failed. Tampering detected.
            }
        }

        let _ = std::fs::remove_file(config_path);
        Ok(())
    }
}
