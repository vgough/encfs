/// Default size for salt in bytes (20 bytes = 160 bits)
pub const DEFAULT_SALT_SIZE: usize = 20;

/// Default number of PBKDF2 iterations
pub const DEFAULT_KDF_ITERATIONS: i32 = 100_000;

/// Default Argon2 memory cost in KiB (64 MiB)
/// This is based on rfc9106 recommended option #2 (w/ 3 iterations, 4 threads).
pub const DEFAULT_ARGON2_MEMORY_COST: u32 = 64 * 1024;

/// Default Argon2 time cost (iterations)
pub const DEFAULT_ARGON2_TIME_COST: u32 = 3;

/// Default Argon2 parallelism (threads)
pub const DEFAULT_ARGON2_PARALLELISM: u32 = 4;

/// Default configuration version for new configs
pub const DEFAULT_CONFIG_VERSION: i32 = 20260101;

/// Default block size for new filesystems
pub const DEFAULT_BLOCK_SIZE: i32 = 4096;

/// Buffer size for file operations (128 KB)
pub const FILE_BUFFER_SIZE: usize = 128 * 1024;

/// EncFS V5 configuration format minimum sub-version
pub const V5_MIN_SUBVERSION: i32 = 20040813;

/// Line length for Base64 encoded data in XML config
pub const XML_BASE64_LINE_LEN: usize = 76;
