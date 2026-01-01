#[macro_use]
extern crate rust_i18n;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use encfs::{config, constants, crypto::ssl::SslCipher};
use rpassword::prompt_password;
use std::io::{self, BufRead, Write};
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::process::Command as ProcessCommand;

i18n!("locales", fallback = "en");

#[derive(Parser)]
#[command(name = "encfsctl")]
#[command(about = "Administrative tool for working with EncFS filesystems")]
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,
    /// Root directory of encrypted filesystem (for default 'info' command)
    rootdir: Option<PathBuf>,
}

#[derive(Subcommand)]
enum Command {
    /// Display basic information about the filesystem
    Info {
        /// Root directory of encrypted filesystem
        rootdir: PathBuf,
    },
    /// Change password for the encrypted filesystem
    Passwd {
        /// Root directory of encrypted filesystem
        rootdir: PathBuf,
    },
    /// Show undecodable filenames in the volume
    Showcruft {
        /// Root directory of encrypted filesystem
        rootdir: PathBuf,
    },
    /// Decode encrypted filenames to plaintext
    Decode {
        /// Root directory of encrypted filesystem
        rootdir: PathBuf,
        /// Encrypted filenames to decode (if not provided, read from stdin)
        names: Vec<String>,
        /// External password program
        #[arg(long)]
        extpass: Option<String>,
    },
    /// Encode plaintext filenames to encrypted form
    Encode {
        /// Root directory of encrypted filesystem
        rootdir: PathBuf,
        /// Plaintext filenames to encode (if not provided, read from stdin)
        names: Vec<String>,
        /// External password program
        #[arg(long)]
        extpass: Option<String>,
    },
    /// Decode and output file content
    Cat {
        /// Root directory of encrypted filesystem
        rootdir: PathBuf,
        /// File path (plaintext or encrypted)
        path: String,
        /// External password program
        #[arg(long)]
        extpass: Option<String>,
        /// Reverse mode: encrypt plaintext instead
        #[arg(long)]
        reverse: bool,
    },
    /// List files in a directory with size and modification time
    Ls {
        /// Root directory of encrypted filesystem
        rootdir: PathBuf,
        /// Path within the encrypted filesystem (default: root)
        #[arg(default_value = "/")]
        path: String,
        /// External password program
        #[arg(long)]
        extpass: Option<String>,
    },
    /// Show the volume key (encoded with itself)
    #[command(name = "showKey")]
    ShowKey {
        /// Root directory of encrypted filesystem
        rootdir: PathBuf,
        /// External password program
        #[arg(long)]
        extpass: Option<String>,
    },
    /// Change password automatically (read old/new passwords from stdin)
    Autopasswd {
        /// Root directory of encrypted filesystem
        rootdir: PathBuf,
    },
    /// Export decrypted files to a destination directory
    Export {
        /// Root directory of encrypted filesystem
        rootdir: PathBuf,
        /// Destination directory for decrypted files
        destdir: PathBuf,
        /// External password program
        #[arg(long)]
        extpass: Option<String>,
        /// Fail on first error instead of warning and continuing
        #[arg(long)]
        fail_on_error: bool,
    },
}

fn main() -> Result<()> {
    encfs::init_locale();

    let cli = Cli::parse();

    match cli.command {
        Some(Command::Info { rootdir }) => cmd_info(&rootdir),
        Some(Command::Passwd { rootdir }) => cmd_passwd(&rootdir),
        Some(Command::Showcruft { rootdir }) => cmd_showcruft(&rootdir),
        Some(Command::Decode {
            rootdir,
            names,
            extpass,
        }) => cmd_decode(&rootdir, names, extpass),
        Some(Command::Encode {
            rootdir,
            names,
            extpass,
        }) => cmd_encode(&rootdir, names, extpass),
        Some(Command::Cat {
            rootdir,
            path,
            extpass,
            reverse,
        }) => cmd_cat(&rootdir, &path, extpass, reverse),
        Some(Command::Ls {
            rootdir,
            path,
            extpass,
        }) => cmd_ls(&rootdir, &path, extpass),
        Some(Command::ShowKey { rootdir, extpass }) => cmd_showkey(&rootdir, extpass),
        Some(Command::Autopasswd { rootdir }) => cmd_autopasswd(&rootdir),
        Some(Command::Export {
            rootdir,
            destdir,
            extpass,
            fail_on_error,
        }) => cmd_export(&rootdir, &destdir, extpass, fail_on_error),
        None => {
            // Default to info command if rootdir is provided
            if let Some(rootdir) = cli.rootdir {
                cmd_info(&rootdir)
            } else {
                eprintln!("{}", t!("ctl.error_root_required"));
                eprintln!("{}", t!("ctl.use_help"));
                Ok(())
            }
        }
    }
}

fn cmd_info(rootdir: &Path) -> Result<()> {
    use config::ConfigType;

    let config_path = find_config_file(rootdir)?;
    let config = config::EncfsConfig::load(&config_path).context(t!("ctl.error_failed_to_load_config"))?;

    // Display version info based on config type
    match config.config_type {
        ConfigType::V6 => {
            println!(
                "{}",
                t!(
                    "ctl.version6_config",
                    creator = config.creator,
                    version = config.version
                )
            );
        }
        ConfigType::V5 => {
            println!(
                "{}",
                t!(
                    "ctl.version5_config",
                    creator = config.creator,
                    version = config.version
                )
            );
        }
        ConfigType::V4 => {
            println!("{}", t!("ctl.version4_config", creator = config.creator));
        }
        ConfigType::V3 => {
            // V3 configs are detected but not supported
            println!("{}", t!("ctl.version3_config"));
            return Err(anyhow::anyhow!(
                "Version 3 configuration files are not supported"
            ));
        }
        ConfigType::Prehistoric => {
            println!("{}", t!("ctl.prehistoric_config"));
            return Err(anyhow::anyhow!("This old EncFS format is not supported"));
        }
        ConfigType::None => {
            return Err(anyhow::anyhow!("Unknown configuration format"));
        }
    }

    // Show filesystem info
    println!(
        "{}",
        t!(
            "ctl.filesystem_cipher",
            name = config.cipher_iface.name,
            major = config.cipher_iface.major,
            minor = config.cipher_iface.minor
        )
    );
    println!(
        "{}",
        t!(
            "ctl.filename_encoding",
            name = config.name_iface.name,
            major = config.name_iface.major,
            minor = config.name_iface.minor
        )
    );
    println!("{}", t!("ctl.key_size", size = config.key_size));
    println!("{}", t!("ctl.block_size", size = config.block_size));

    if config.unique_iv {
        println!("{}", t!("ctl.unique_iv_header"));
    }

    if config.chained_name_iv {
        println!("{}", t!("ctl.chained_name_iv"));
    }

    if config.external_iv_chaining {
        println!("{}", t!("ctl.external_iv_chaining"));
    }

    if config.block_mac_bytes > 0 {
        println!("{}", t!("ctl.block_mac", bytes = config.block_mac_bytes));
    }

    if config.kdf_iterations > 0 && !config.salt.is_empty() {
        println!(
            "{}",
            t!("ctl.pbkdf2_iterations", iterations = config.kdf_iterations)
        );
        println!("{}", t!("ctl.salt_size", bits = config.salt.len() * 8));
    }

    Ok(())
}

fn cmd_passwd(rootdir: &Path) -> Result<()> {
    let config_path = find_config_file(rootdir)?;
    let mut config =
        config::EncfsConfig::load(&config_path).context("Failed to load config file")?;

    // Get current password
    print!("{}", t!("ctl.enter_current_password"));
    io::stdout().flush()?;
    let current_password = prompt_password("")?;

    // Decrypt volume key with current password
    let cipher = config
        .get_cipher(&current_password)
        .context(t!("ctl.error_invalid_password"))?;

    // Get volume key from cipher (we need to extract it)
    // Actually, we need to decrypt the key_data again to get the volume key
    let key_len = (config.key_size / 8) as usize;
    let iv_len = cipher.iv_len();
    let user_key_len = key_len + iv_len;

    let user_key_blob = if config.kdf_iterations > 0 {
        SslCipher::derive_key(
            &current_password,
            &config.salt,
            config.kdf_iterations,
            user_key_len,
        )?
    } else {
        SslCipher::derive_key_legacy(&current_password, key_len, iv_len)?
    };

    let user_key = &user_key_blob[..key_len];
    let user_iv = &user_key_blob[key_len..];

    let volume_key_blob = if config.kdf_iterations > 0 {
        cipher.decrypt_key(&config.key_data, user_key, user_iv)?
    } else {
        cipher.decrypt_key_legacy(&config.key_data, user_key, user_iv)?
    };

    // Get new password
    print!("{}", t!("ctl.enter_new_password"));
    io::stdout().flush()?;
    let new_password = prompt_password("")?;

    // Generate new salt and iterations for new password
    use openssl::rand::rand_bytes;
    if config.salt.is_empty() {
        config.salt = vec![0u8; constants::DEFAULT_SALT_SIZE];
    }
    rand_bytes(&mut config.salt).context(t!("ctl.error_failed_to_generate_salt"))?;

    // Use a reasonable iteration count (or keep existing if set)
    if config.kdf_iterations == 0 {
        // For new passwords, use a default iteration count
        // In practice, EncFS would calculate this based on desired duration
        config.kdf_iterations = constants::DEFAULT_KDF_ITERATIONS; // Default reasonable value
    }

    // Create new cipher for encryption
    let new_cipher = SslCipher::new(&config.cipher_iface, config.key_size)?;

    // Derive new user key
    let new_user_key_blob = if config.kdf_iterations > 0 {
        SslCipher::derive_key(
            &new_password,
            &config.salt,
            config.kdf_iterations,
            user_key_len,
        )?
    } else {
        SslCipher::derive_key_legacy(&new_password, key_len, iv_len)?
    };

    let new_user_key = &new_user_key_blob[..key_len];
    let new_user_iv = &new_user_key_blob[key_len..];

    // Encrypt volume key with new user key
    let encrypted_key = if config.kdf_iterations > 0 {
        new_cipher.encrypt_key(&volume_key_blob, new_user_key, new_user_iv)?
    } else {
        // For legacy, we'd need encrypt_key_legacy, but for now use regular encrypt_key
        new_cipher.encrypt_key(&volume_key_blob, new_user_key, new_user_iv)?
    };

    config.key_data = encrypted_key;

    // Save config
    config
        .save(&config_path)
        .context(t!("ctl.error_failed_to_save_config"))?;

    println!("{}", t!("ctl.volume_key_updated"));

    Ok(())
}

struct ShowcruftStats {
    files_checked: i32,
    dirs_checked: i32,
    issues_found: i32,
}

fn cmd_showcruft(rootdir: &Path) -> Result<()> {
    let config_path = find_config_file(rootdir)?;
    let config = config::EncfsConfig::load(&config_path).context(t!("ctl.error_failed_to_load_config"))?;

    let password = get_password(&config_path, None)?;
    let cipher = config.get_cipher(&password).context("Invalid password")?;

    let mut stats = ShowcruftStats {
        files_checked: 0,
        dirs_checked: 0,
        issues_found: 0,
    };
    find_undecodable_files(
        rootdir,
        rootdir,
        &cipher,
        config.chained_name_iv,
        0, // Initial IV for root directory
        &mut stats,
    )?;

    // Print summary
    println!();
    println!(
        "{}",
        t!(
            "ctl.checked_files_dirs",
            files = stats.files_checked,
            dirs = stats.dirs_checked
        )
    );
    if stats.issues_found == 0 {
        println!("{}", t!("ctl.no_undecodable_files"));
    } else if stats.issues_found == 1 {
        println!("{}", t!("ctl.found_one_undecodable"));
    } else {
        println!(
            "{}",
            t!("ctl.found_undecodable_files", count = stats.issues_found)
        );
    }

    Ok(())
}

fn cmd_decode(rootdir: &Path, names: Vec<String>, extpass: Option<String>) -> Result<()> {
    let config_path = find_config_file(rootdir)?;
    let config = config::EncfsConfig::load(&config_path).context(t!("ctl.error_failed_to_load_config"))?;

    let password = get_password(&config_path, extpass)?;
    let cipher = config.get_cipher(&password).context("Invalid password")?;

    if names.is_empty() {
        // Read from stdin
        let stdin = io::stdin();
        for line in stdin.lock().lines() {
            let line = line?;
            let encoded_path = line.trim();
            if encoded_path.is_empty() {
                continue;
            }
            match decode_path_string(&cipher, encoded_path, config.chained_name_iv) {
                Ok(decoded) => println!("{}", decoded),
                Err(e) => eprintln!(
                    "{}",
                    t!("ctl.error_decoding", path = encoded_path, error = e)
                ),
            }
        }
    } else {
        // Decode command line arguments
        for name in names {
            match decode_path_string(&cipher, &name, config.chained_name_iv) {
                Ok(decoded) => println!("{}", decoded),
                Err(e) => eprintln!("{}", t!("ctl.error_decoding", path = name, error = e)),
            }
        }
    }

    Ok(())
}

fn cmd_encode(rootdir: &Path, names: Vec<String>, extpass: Option<String>) -> Result<()> {
    let config_path = find_config_file(rootdir)?;
    let config = config::EncfsConfig::load(&config_path).context(t!("ctl.error_failed_to_load_config"))?;

    let password = get_password(&config_path, extpass)?;
    let cipher = config.get_cipher(&password).context("Invalid password")?;

    if names.is_empty() {
        // Read from stdin
        let stdin = io::stdin();
        for line in stdin.lock().lines() {
            let line = line?;
            let plaintext_path = line.trim();
            if plaintext_path.is_empty() {
                continue;
            }
            match encode_path_string(&cipher, plaintext_path, config.chained_name_iv) {
                Ok(encoded) => println!("{}", encoded),
                Err(e) => eprintln!(
                    "{}",
                    t!("ctl.error_encoding", path = plaintext_path, error = e)
                ),
            }
        }
    } else {
        // Encode command line arguments
        for name in names {
            match encode_path_string(&cipher, &name, config.chained_name_iv) {
                Ok(encoded) => println!("{}", encoded),
                Err(e) => eprintln!("{}", t!("ctl.error_encoding", path = name, error = e)),
            }
        }
    }

    Ok(())
}

fn cmd_cat(rootdir: &Path, path: &str, extpass: Option<String>, reverse: bool) -> Result<()> {
    let config_path = find_config_file(rootdir)?;
    let config = config::EncfsConfig::load(&config_path).context(t!("ctl.error_failed_to_load_config"))?;

    let password = get_password(&config_path, extpass)?;
    let cipher = config.get_cipher(&password).context("Invalid password")?;

    if reverse {
        // Encrypt plaintext and output
        let mut file = std::fs::File::open(rootdir.join(path)).context(t!("ctl.error_failed_to_open_file"))?;
        let mut plaintext = Vec::new();
        std::io::Read::read_to_end(&mut file, &mut plaintext)?;

        // For reverse mode, we'd need to implement encryption
        // This is a simplified version - full implementation would need block encryption
        return Err(anyhow::anyhow!("--reverse mode not yet fully implemented"));
    } else {
        // Decrypt and output
        let (file_path, path_iv) =
            resolve_file_path(rootdir, path, &cipher, config.chained_name_iv)?;
        let file = std::fs::File::open(&file_path).context(t!("ctl.error_failed_to_open_encrypted_file"))?;

        // Read header to get file IV
        use std::os::unix::fs::FileExt;

        let header_size = config.header_size();
        let file_iv = if header_size > 0 {
            let mut header = vec![0u8; header_size as usize];
            let n = file.read_at(&mut header, 0)?;
            if n < header.len() {
                return Err(anyhow::anyhow!("Encrypted file has incomplete header"));
            }

            // Use path IV for external IV chaining (paranoia mode)
            let external_iv = if config.external_iv_chaining {
                path_iv
            } else {
                0
            };
            cipher.decrypt_header(&mut header, external_iv)?
        } else {
            0
        };

        // Use FileDecoder to decrypt content
        use encfs::crypto::file::FileDecoder;
        let decoder = FileDecoder::new(
            &cipher,
            &file,
            file_iv,
            header_size, // header_size
            config.block_size as u64,
            config.block_mac_bytes as u64,
        );

        // Stream to stdout to avoid allocating the full file in memory.
        let mut out = io::stdout().lock();
        let mut offset = 0u64;
        let mut buf = vec![0u8; constants::FILE_BUFFER_SIZE];
        loop {
            let bytes_read = decoder.read_at(&mut buf, offset)?;
            if bytes_read == 0 {
                break;
            }
            out.write_all(&buf[..bytes_read])?;
            offset += bytes_read as u64;
        }
    }

    Ok(())
}

fn cmd_ls(rootdir: &Path, path: &str, extpass: Option<String>) -> Result<()> {
    use chrono::{DateTime, Local};
    use encfs::crypto::file::FileDecoder;
    use std::os::unix::fs::MetadataExt;

    let config_path = find_config_file(rootdir)?;
    let config = config::EncfsConfig::load(&config_path).context(t!("ctl.error_failed_to_load_config"))?;

    let password = get_password(&config_path, extpass)?;
    let cipher = config.get_cipher(&password).context("Invalid password")?;

    // Encrypt the path to get the real directory path
    let plaintext_path = PathBuf::from(path);
    let (encrypted_dir_path, dir_iv) =
        encrypt_path_with_iv(rootdir, &plaintext_path, &cipher, config.chained_name_iv)?;

    let entries = std::fs::read_dir(&encrypted_dir_path).context(t!("ctl.error_failed_to_read_directory"))?;

    for entry in entries {
        let entry = match entry {
            Ok(e) => e,
            Err(e) => {
                eprintln!("{}", t!("ctl.warning_read_dir_entry", error = e));
                continue;
            }
        };

        let file_name = entry.file_name();
        let name_str = match file_name.to_str() {
            Some(s) => s,
            None => {
                eprintln!(
                    "Warning: Skipping file with non-UTF-8 filename: {:?}",
                    file_name
                );
                continue;
            }
        };

        // Skip config files
        if name_str.starts_with(".encfs") {
            continue;
        }

        // Try to decrypt the filename
        match cipher.decrypt_filename(name_str, dir_iv) {
            Ok((decrypted_name_bytes, _)) => {
                let process_res = (|| -> Result<()> {
                    let metadata = std::fs::symlink_metadata(entry.path())?;

                    // Calculate logical size for files
                    let size = if metadata.is_file() {
                        FileDecoder::<std::fs::File>::calculate_logical_size(
                            metadata.len(),
                            config.header_size(),
                            config.block_size as u64,
                            config.block_mac_bytes as u64,
                        )
                    } else {
                        metadata.len()
                    };

                    // Format modification time
                    let mtime = metadata.mtime();
                    let datetime: DateTime<Local> = DateTime::from_timestamp(mtime, 0)
                        .unwrap_or_default()
                        .into();
                    let time_str = datetime.format("%Y-%m-%d %H:%M:%S");

                    let name_display = String::from_utf8_lossy(&decrypted_name_bytes);
                    println!("{:>11} {} {}", size, time_str, name_display);
                    Ok(())
                })();

                if let Err(e) = process_res {
                    eprintln!(
                        "{}",
                        t!("ctl.warning_error_processing", name = name_str, error = e)
                    );
                }
            }
            Err(_) => {
                // Skip files we can't decrypt
                continue;
            }
        }
    }

    Ok(())
}

fn cmd_showkey(rootdir: &Path, extpass: Option<String>) -> Result<()> {
    use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};

    let config_path = find_config_file(rootdir)?;
    let config = config::EncfsConfig::load(&config_path).context(t!("ctl.error_failed_to_load_config"))?;

    let password = get_password(&config_path, extpass)?;

    // We need to get the raw volume key blob
    let key_len = (config.key_size / 8) as usize;
    let cipher = SslCipher::new(&config.cipher_iface, config.key_size)?;
    let iv_len = cipher.iv_len();
    let user_key_len = key_len + iv_len;

    let user_key_blob = if config.kdf_iterations > 0 {
        SslCipher::derive_key(&password, &config.salt, config.kdf_iterations, user_key_len)?
    } else {
        SslCipher::derive_key_legacy(&password, key_len, iv_len)?
    };

    let user_key = &user_key_blob[..key_len];
    let user_iv = &user_key_blob[key_len..];

    let volume_key_blob = if config.kdf_iterations > 0 {
        cipher.decrypt_key(&config.key_data, user_key, user_iv)?
    } else {
        cipher.decrypt_key_legacy(&config.key_data, user_key, user_iv)?
    };

    // Encode the volume key with itself (same as C++ encodeAsString)
    // This uses stream_encode with the volume key as both key and data
    let volume_key = &volume_key_blob[..key_len];
    let volume_iv = &volume_key_blob[key_len..key_len + iv_len];

    let mut encoded_key = volume_key_blob.clone();
    cipher.stream_encode(&mut encoded_key, 0, volume_key, volume_iv)?;

    // Output as base64
    let b64_key = BASE64.encode(&encoded_key);
    println!("{}", b64_key);

    Ok(())
}

fn cmd_autopasswd(rootdir: &Path) -> Result<()> {
    let config_path = find_config_file(rootdir)?;
    let mut config =
        config::EncfsConfig::load(&config_path).context("Failed to load config file")?;

    // Read current password from stdin (first line)
    let stdin = io::stdin();
    let mut lines = stdin.lock().lines();

    let current_password = lines
        .next()
        .ok_or_else(|| anyhow::anyhow!("No current password provided"))?
        .context(t!("ctl.error_failed_to_read_current_password"))?;

    // Verify current password
    let cipher = config
        .get_cipher(&current_password)
        .context(t!("ctl.error_invalid_password"))?;

    // Get volume key
    let key_len = (config.key_size / 8) as usize;
    let iv_len = cipher.iv_len();
    let user_key_len = key_len + iv_len;

    let user_key_blob = if config.kdf_iterations > 0 {
        SslCipher::derive_key(
            &current_password,
            &config.salt,
            config.kdf_iterations,
            user_key_len,
        )?
    } else {
        SslCipher::derive_key_legacy(&current_password, key_len, iv_len)?
    };

    let user_key = &user_key_blob[..key_len];
    let user_iv = &user_key_blob[key_len..];

    let volume_key_blob = if config.kdf_iterations > 0 {
        cipher.decrypt_key(&config.key_data, user_key, user_iv)?
    } else {
        cipher.decrypt_key_legacy(&config.key_data, user_key, user_iv)?
    };

    // Read new password from stdin (second line)
    let new_password = lines
        .next()
        .ok_or_else(|| anyhow::anyhow!("No new password provided"))?
        .context(t!("ctl.error_failed_to_read_new_password"))?;

    // Generate new salt
    use openssl::rand::rand_bytes;
    if config.salt.is_empty() {
        config.salt = vec![0u8; constants::DEFAULT_SALT_SIZE];
    }
    rand_bytes(&mut config.salt).context(t!("ctl.error_failed_to_generate_salt"))?;

    if config.kdf_iterations == 0 {
        config.kdf_iterations = constants::DEFAULT_KDF_ITERATIONS;
    }

    // Create new cipher for encryption
    let new_cipher = SslCipher::new(&config.cipher_iface, config.key_size)?;

    // Derive new user key
    let new_user_key_blob = if config.kdf_iterations > 0 {
        SslCipher::derive_key(
            &new_password,
            &config.salt,
            config.kdf_iterations,
            user_key_len,
        )?
    } else {
        SslCipher::derive_key_legacy(&new_password, key_len, iv_len)?
    };

    let new_user_key = &new_user_key_blob[..key_len];
    let new_user_iv = &new_user_key_blob[key_len..];

    // Encrypt volume key with new user key
    let encrypted_key = new_cipher.encrypt_key(&volume_key_blob, new_user_key, new_user_iv)?;

    config.key_data = encrypted_key;

    // Save config
    config
        .save(&config_path)
        .context(t!("ctl.error_failed_to_save_config"))?;

    println!("{}", t!("ctl.volume_key_updated"));

    Ok(())
}

fn cmd_export(
    rootdir: &Path,
    destdir: &Path,
    extpass: Option<String>,
    fail_on_error: bool,
) -> Result<()> {
    let config_path = find_config_file(rootdir)?;
    let config = config::EncfsConfig::load(&config_path).context(t!("ctl.error_failed_to_load_config"))?;

    let password = get_password(&config_path, extpass)?;
    let cipher = config.get_cipher(&password).context("Invalid password")?;

    // Create destination directory if it doesn't exist
    if !destdir.exists() {
        std::fs::create_dir_all(destdir).context(t!("ctl.error_failed_to_create_destination_directory"))?;
    }

    // Start recursive export from root
    export_directory(
        rootdir,
        destdir,
        &cipher,
        &config,
        0, // initial IV
        fail_on_error,
    )?;

    Ok(())
}

fn export_directory(
    current_encrypted_dir: &Path,
    current_dest_dir: &Path,
    cipher: &SslCipher,
    config: &config::EncfsConfig,
    dir_iv: u64,
    fail_on_error: bool,
) -> Result<()> {
    use encfs::crypto::file::FileDecoder;
    use std::os::unix::fs::{FileExt, MetadataExt, PermissionsExt};

    let entries = std::fs::read_dir(current_encrypted_dir).context(t!("ctl.error_failed_to_read_directory"))?;

    for entry in entries {
        let entry = match entry {
            Ok(e) => e,
            Err(e) => {
                if fail_on_error {
                    return Err(anyhow::anyhow!("Failed to read directory entry: {}", e));
                }
                eprintln!("{}", t!("ctl.warning_read_dir_entry", error = e));
                continue;
            }
        };

        let entry_path = entry.path();

        // Use a closure to handle per-file errors without aborting the loop
        let process_res = (|| -> Result<()> {
            let file_name = entry.file_name();
            let name_str = match file_name.to_str() {
                Some(s) => s,
                None => {
                    if fail_on_error {
                        return Err(anyhow::anyhow!("Non-UTF-8 filename: {:?}", file_name));
                    }
                    eprintln!(
                        "Warning: Skipping file with non-UTF-8 filename: {:?}",
                        file_name
                    );
                    return Ok(());
                }
            };

            // Skip config files
            if name_str.starts_with(".encfs") {
                return Ok(());
            }

            // Try to decrypt the filename
            let (decrypted_name_bytes, new_iv) = match cipher.decrypt_filename(name_str, dir_iv) {
                Ok(result) => result,
                Err(e) => {
                    if fail_on_error {
                        return Err(anyhow::anyhow!("Could not decrypt {}: {}", name_str, e));
                    }
                    eprintln!(
                        "{}",
                        t!("ctl.warning_could_not_decrypt", name = name_str, error = e)
                    );
                    return Ok(());
                }
            };

            // Use symlink_metadata to avoid following symlinks
            let metadata = std::fs::symlink_metadata(entry.path())?;
            let dest_path =
                current_dest_dir.join(std::ffi::OsStr::from_bytes(&decrypted_name_bytes));

            if metadata.is_dir() {
                // Create destination directory with same permissions
                std::fs::create_dir_all(&dest_path)?;
                std::fs::set_permissions(
                    &dest_path,
                    std::fs::Permissions::from_mode(metadata.mode()),
                )?;

                // Recurse into subdirectory
                let next_iv = if config.chained_name_iv { new_iv } else { 0 };
                export_directory(
                    &entry.path(),
                    &dest_path,
                    cipher,
                    config,
                    next_iv,
                    fail_on_error,
                )?;
            } else if metadata.is_symlink() {
                // Handle symlinks - read and decrypt the link target
                let link_target = std::fs::read_link(entry.path())?;
                if let Some(target_str) = link_target.to_str() {
                    // Symlink targets are encrypted as a single filename string using the symlink's
                    // path IV (matching `fs.rs` symlink/readlink).
                    let link_path_iv = if config.chained_name_iv { new_iv } else { 0 };
                    let (decrypted_target_bytes, _) =
                        match cipher.decrypt_filename(target_str, link_path_iv) {
                            Ok(res) => res,
                            Err(e) => {
                                if fail_on_error {
                                    return Err(anyhow::anyhow!(
                                        "Undecryptable symlink target {:?}: {}",
                                        entry.path(),
                                        e
                                    ));
                                }
                                eprintln!(
                                    "Warning: Skipping symlink with undecryptable target {:?}: {}",
                                    entry.path(),
                                    e
                                );
                                return Ok(());
                            }
                        };

                    #[cfg(unix)]
                    std::os::unix::fs::symlink(
                        std::ffi::OsStr::from_bytes(&decrypted_target_bytes),
                        &dest_path,
                    )?;
                } else {
                    eprintln!(
                        "Warning: Skipping symlink with non-UTF-8 target: {:?}",
                        entry.path()
                    );
                }
            } else if metadata.is_file() {
                // Decrypt and copy file content
                let src_file = std::fs::File::open(entry.path())?;

                let header_size = config.header_size();
                let file_iv = if header_size > 0 {
                    // Read and decrypt file header
                    let mut header = vec![0u8; header_size as usize];
                    let bytes_read = src_file.read_at(&mut header, 0)?;

                    if bytes_read < header.len() {
                        let name_display = String::from_utf8_lossy(&decrypted_name_bytes);
                        eprintln!(
                            "{}",
                            t!("ctl.warning_incomplete_header", name = name_display)
                        );
                        return Ok(());
                    }

                    // Calculate path IV for external IV chaining
                    let path_iv = if config.external_iv_chaining && config.chained_name_iv {
                        new_iv
                    } else {
                        0
                    };

                    cipher.decrypt_header(&mut header, path_iv)?
                } else {
                    0
                };

                // Decrypt content using FileDecoder
                let decoder = FileDecoder::new(
                    cipher,
                    &src_file,
                    file_iv,
                    header_size, // header_size
                    config.block_size as u64,
                    config.block_mac_bytes as u64,
                );

                let file_size = metadata.len();
                let logical_size = FileDecoder::<std::fs::File>::calculate_logical_size(
                    file_size,
                    header_size,
                    config.block_size as u64,
                    config.block_mac_bytes as u64,
                );

                let mut dest_file = std::fs::File::create(&dest_path)?;

                let mut buffer = vec![0u8; crate::constants::FILE_BUFFER_SIZE];
                let mut offset = 0;
                let mut remaining = logical_size;

                while remaining > 0 {
                    let to_read = std::cmp::min(remaining, buffer.len() as u64) as usize;
                    let bytes_read = decoder.read_at(&mut buffer[..to_read], offset)?;
                    if bytes_read == 0 {
                        break; // EOF
                    }

                    std::io::Write::write_all(&mut dest_file, &buffer[..bytes_read])?;
                    offset += bytes_read as u64;
                    remaining -= bytes_read as u64;
                }

                // Preserve permissions
                std::fs::set_permissions(
                    &dest_path,
                    std::fs::Permissions::from_mode(metadata.mode()),
                )?;
            }
            Ok(())
        })();

        if let Err(e) = process_res {
            if fail_on_error {
                return Err(e);
            }
            eprintln!(
                "{}",
                t!(
                    "ctl.warning_export_failed",
                    path = entry_path.display(),
                    error = e
                )
            );
        }
    }
    Ok(())
}

fn decode_path_string(cipher: &SslCipher, encoded_path: &str, chained_iv: bool) -> Result<String> {
    // Decode an encrypted path by decoding each component with IV chaining across path components.
    // Note: IV chaining is per-path-component, not across unrelated sibling names.
    let mut out = PathBuf::new();
    let mut iv = 0u64;

    for component in Path::new(encoded_path).components() {
        match component {
            std::path::Component::RootDir => {}
            std::path::Component::CurDir => {}
            std::path::Component::Normal(name) => {
                let name_str = name
                    .to_str()
                    .ok_or_else(|| anyhow::anyhow!("Invalid UTF-8"))?;
                let (decrypted_name_bytes, new_iv) = cipher.decrypt_filename(name_str, iv)?;
                out.push(std::ffi::OsStr::from_bytes(&decrypted_name_bytes));
                if chained_iv {
                    iv = new_iv;
                }
            }
            _ => return Err(anyhow::anyhow!("Invalid path component")),
        }
    }

    Ok(out.to_string_lossy().to_string())
}

fn encode_path_string(
    cipher: &SslCipher,
    plaintext_path: &str,
    chained_iv: bool,
) -> Result<String> {
    // Encode a plaintext path by encoding each component with IV chaining across path components.
    let mut out = PathBuf::new();
    let mut iv = 0u64;

    for component in Path::new(plaintext_path).components() {
        match component {
            std::path::Component::RootDir => {}
            std::path::Component::CurDir => {}
            std::path::Component::Normal(name) => {
                let name_bytes = name.as_bytes();
                let (encrypted_name, new_iv) = cipher.encrypt_filename(name_bytes, iv)?;
                out.push(encrypted_name);
                if chained_iv {
                    iv = new_iv;
                }
            }
            _ => return Err(anyhow::anyhow!("Invalid path component")),
        }
    }

    Ok(out.to_string_lossy().to_string())
}

fn encrypt_path_with_iv(
    rootdir: &Path,
    plaintext_path: &Path,
    cipher: &SslCipher,
    chained_iv: bool,
) -> Result<(PathBuf, u64)> {
    let mut encrypted_path = PathBuf::new();
    let mut iv = 0u64;

    for component in plaintext_path.components() {
        match component {
            std::path::Component::RootDir => {}
            std::path::Component::CurDir => {}
            std::path::Component::Normal(name) => {
                let name_bytes = name.as_bytes();
                let (encrypted_name, new_iv) = cipher.encrypt_filename(name_bytes, iv)?;
                encrypted_path.push(encrypted_name);
                if chained_iv {
                    iv = new_iv;
                }
            }
            _ => return Err(anyhow::anyhow!("Invalid path component")),
        }
    }

    Ok((rootdir.join(encrypted_path), iv))
}

// Helper functions

fn find_config_file(rootdir: &Path) -> Result<PathBuf> {
    // Try config files in order from newest to oldest format
    let config_files = [
        ".encfs6.xml", // V6 - current XML format
        ".encfs5",     // V5 - binary format
        ".encfs4",     // V4 - older binary format
        ".encfs3",     // V3 - very old, not supported but detected
    ];

    for filename in &config_files {
        let path = rootdir.join(filename);
        if path.exists() {
            return Ok(path);
        }
    }

    Err(anyhow::anyhow!(
        "No config file found. Looked for .encfs6.xml, .encfs5, .encfs4, .encfs3 in {}",
        rootdir.display()
    ))
}

fn get_password(_config_path: &Path, extpass: Option<String>) -> Result<String> {
    if let Some(prog) = extpass {
        get_password_from_program(&prog)
    } else {
        prompt_password("EncFS Password: ").context(t!("ctl.error_failed_to_read_password"))
    }
}

fn get_password_from_program(prog: &str) -> Result<String> {
    let output = ProcessCommand::new("sh")
        .arg("-c")
        .arg(prog)
        .output()
        .context(t!("ctl.error_failed_to_execute_password_program"))?;

    if !output.status.success() {
        return Err(anyhow::anyhow!("Password program exited with error"));
    }

    String::from_utf8(output.stdout)
        .context(t!("ctl.error_password_program_invalid_utf8"))
        .map(|s| s.trim_end().to_string())
}

fn find_undecodable_files(
    rootdir: &Path,
    current_dir: &Path,
    cipher: &SslCipher,
    chained_iv: bool,
    dir_iv: u64,
    stats: &mut ShowcruftStats,
) -> Result<()> {
    let entries = std::fs::read_dir(current_dir).context(t!("ctl.error_failed_to_read_directory"))?;

    stats.dirs_checked += 1;
    let mut showed_dir = false;
    let mut dirs_to_recurse = Vec::new();

    for entry in entries {
        let entry = match entry {
            Ok(e) => e,
            Err(e) => {
                eprintln!("{}", t!("ctl.warning_read_dir_entry", error = e));
                continue;
            }
        };

        let file_name = entry.file_name();
        let name_str = match file_name.to_str() {
            Some(s) => s,
            None => {
                // Non-UTF-8 filename is definitely cruft - encrypted EncFS filenames
                // should be base64-like ASCII. This indicates corruption or manually
                // created files in the encrypted directory.
                stats.files_checked += 1;
                if !showed_dir {
                    let rel_path = current_dir.strip_prefix(rootdir).unwrap_or(current_dir);
                    println!("{}", t!("ctl.in_directory", path = rel_path.display()));
                    showed_dir = true;
                }
                println!(
                    "{}",
                    t!("ctl.non_utf8_filename", path = entry.path().display())
                );
                stats.issues_found += 1;
                continue;
            }
        };

        // Skip hidden files (including config files)
        if name_str.starts_with(".") {
            continue;
        }

        stats.files_checked += 1;

        // Try to decrypt filename using the parent directory's IV
        match cipher.decrypt_filename(name_str, dir_iv) {
            Ok((_, new_iv)) => {
                // Successfully decoded - check if it's a directory
                if let Ok(file_type) = entry.file_type() {
                    if file_type.is_dir() {
                        // Store both the path and the IV for recursion
                        let next_iv = if chained_iv { new_iv } else { 0 };
                        dirs_to_recurse.push((entry.path(), next_iv));
                    }
                } else {
                    eprintln!(
                        "{}",
                        t!("ctl.warning_file_type", path = entry.path().display())
                    );
                }
            }
            Err(_) => {
                // Failed to decode - this is "cruft"
                if !showed_dir {
                    let rel_path = current_dir.strip_prefix(rootdir).unwrap_or(current_dir);
                    println!("{}", t!("ctl.in_directory", path = rel_path.display()));
                    showed_dir = true;
                }
                println!("{}", entry.path().display());
                stats.issues_found += 1;
            }
        }
    }

    // Recurse into successfully decoded directories
    for (dir_path, next_iv) in dirs_to_recurse {
        find_undecodable_files(rootdir, &dir_path, cipher, chained_iv, next_iv, stats)?;
    }

    Ok(())
}

fn resolve_file_path(
    rootdir: &Path,
    path: &str,
    cipher: &SslCipher,
    chained_iv: bool,
) -> Result<(PathBuf, u64)> {
    // Try as plaintext path first
    let plaintext_path = PathBuf::from(path);
    let (encrypted_path, path_iv) =
        encrypt_path_with_iv(rootdir, &plaintext_path, cipher, chained_iv)?;

    if encrypted_path.exists() {
        return Ok((encrypted_path, path_iv));
    }

    // Try as encrypted path - need to decrypt to get IV
    let encrypted_path = rootdir.join(path);
    if encrypted_path.exists() {
        // Decrypt the path to get the IV
        let rel_path = PathBuf::from(path);
        let (_, path_iv) = decrypt_path_with_iv(&rel_path, cipher, chained_iv)?;
        return Ok((encrypted_path, path_iv));
    }

    Err(anyhow::anyhow!("File not found: {}", path))
}

fn decrypt_path_with_iv(
    encrypted_path: &Path,
    cipher: &SslCipher,
    chained_iv: bool,
) -> Result<(PathBuf, u64)> {
    let mut decrypted_path = PathBuf::new();
    let mut iv = 0u64;

    for component in encrypted_path.components() {
        match component {
            std::path::Component::RootDir => {}
            std::path::Component::CurDir => {}
            std::path::Component::Normal(name) => {
                let name_str = name
                    .to_str()
                    .ok_or_else(|| anyhow::anyhow!("Invalid UTF-8"))?;
                let (decrypted_name_bytes, new_iv) = cipher.decrypt_filename(name_str, iv)?;
                decrypted_path.push(std::ffi::OsStr::from_bytes(&decrypted_name_bytes));
                if chained_iv {
                    iv = new_iv;
                }
            }
            _ => return Err(anyhow::anyhow!("Invalid path component")),
        }
    }

    Ok((decrypted_path, iv))
}

#[cfg(test)]
mod tests {
    use super::*;
    use encfs::config::{ConfigType, EncfsConfig, Interface};
    use encfs::crypto::ssl::SslCipher;
    use std::fs;
    use std::os::unix::fs::symlink;

    #[test]
    fn test_export_symlink_repro() -> Result<()> {
        let temp_dir =
            std::env::temp_dir().join(format!("encfs_export_test_{}", std::process::id()));
        let src_dir = temp_dir.join("src");
        let dst_dir = temp_dir.join("dst");
        fs::create_dir_all(&src_dir)?;
        fs::create_dir_all(&dst_dir)?;

        // Setup Cipher
        let iface = Interface {
            name: "ssl/aes".to_string(),
            major: 3,
            minor: 0,
            age: 0,
        };
        // 192 bit key
        let mut cipher = SslCipher::new(&iface, 192)?;
        let key = vec![0u8; 24];
        let iv = vec![0u8; cipher.iv_len()];
        cipher.set_key(&key, &iv);

        // Setup Config
        let config = EncfsConfig {
            config_type: ConfigType::V6,
            creator: "test".to_string(),
            version: constants::DEFAULT_CONFIG_VERSION,
            cipher_iface: iface.clone(),
            name_iface: iface.clone(),
            key_size: 192,
            block_size: 1024,
            key_data: vec![],
            salt: vec![],
            kdf_iterations: 0,
            desired_kdf_duration: 0,
            plain_data: false,
            block_mac_bytes: 0,
            block_mac_rand_bytes: 0,
            unique_iv: true,
            external_iv_chaining: false,
            chained_name_iv: true,
            allow_holes: false,
        };

        // Prepare symlink
        let symlink_name = "mysymlink";
        let symlink_target = "target_path";

        // Encrypt name
        let (enc_name, name_iv) = cipher.encrypt_filename(symlink_name.as_bytes(), 0)?;

        // Encrypt target string (to be content of symlink)
        // export_directory uses link_path_iv = new_iv (from name decryption) if chained_name_iv
        let link_iv = if config.chained_name_iv { name_iv } else { 0 };
        let (enc_target, _) = cipher.encrypt_filename(symlink_target.as_bytes(), link_iv)?;

        // Create the symlink in source
        // The symlink points to 'enc_target'
        let link_path = src_dir.join(&enc_name);
        symlink(&enc_target, &link_path)?;

        // Make the target exist so metadata() doesn't fail (simulating follows symlink bug)
        // The symlink points to enc_target relative to src_dir
        fs::write(src_dir.join(&enc_target), "dummy content")?;

        // Run export
        export_directory(&src_dir, &dst_dir, &cipher, &config, 0, false)?;

        // Check destination
        let exported_link = dst_dir.join(symlink_name);

        // Assertions
        if !exported_link.exists() && fs::symlink_metadata(&exported_link).is_err() {
            panic!("Exported link/file not found at {:?}", exported_link);
        }

        // Check if it is a symlink
        let meta = fs::symlink_metadata(&exported_link)?;
        if !meta.file_type().is_symlink() {
            println!(
                "Bug reproduced: Exported item is not a symlink (is_file={})",
                meta.is_file()
            );
            panic!("Exported item is not a symlink");
        }

        // Verify target
        let target = fs::read_link(&exported_link)?;
        assert_eq!(target.to_str().unwrap(), symlink_target);

        // Cleanup
        let _ = fs::remove_dir_all(temp_dir);

        Ok(())
    }

    #[test]
    fn test_export_bad_symlink_repro() -> Result<()> {
        use std::ffi::OsStr;
        use std::os::unix::ffi::OsStrExt;

        let temp_dir =
            std::env::temp_dir().join(format!("encfs_export_bad_symlink_{}", std::process::id()));
        let src_dir = temp_dir.join("src");
        let dst_dir = temp_dir.join("dst");
        fs::create_dir_all(&src_dir)?;
        fs::create_dir_all(&dst_dir)?;

        // Setup Cipher
        let iface = Interface {
            name: "ssl/aes".to_string(),
            major: 3,
            minor: 0,
            age: 0,
        };
        let mut cipher = SslCipher::new(&iface, 192)?;
        let key = vec![0u8; 24];
        let iv = vec![0u8; cipher.iv_len()];
        cipher.set_key(&key, &iv);

        // Setup Config
        let config = EncfsConfig {
            config_type: ConfigType::V6,
            creator: "test".to_string(),
            version: constants::DEFAULT_CONFIG_VERSION,
            cipher_iface: iface.clone(),
            name_iface: iface.clone(),
            key_size: 192,
            block_size: 1024,
            key_data: vec![],
            salt: vec![],
            kdf_iterations: 0,
            desired_kdf_duration: 0,
            plain_data: false,
            block_mac_bytes: 0,
            block_mac_rand_bytes: 0,
            unique_iv: true,
            external_iv_chaining: false,
            chained_name_iv: true,
            allow_holes: false,
        };

        // Create a symlink with non-UTF8 target
        // 0xFF is invalid UTF-8
        let bad_bytes = b"target_\xff_path";
        let bad_target = OsStr::from_bytes(bad_bytes);

        let link_name = "bad_link";
        // Encrypt name so it's picked up
        let (enc_link_name, _) = cipher.encrypt_filename(link_name.as_bytes(), 0)?;

        let link_path = src_dir.join(&enc_link_name);
        symlink(bad_target, &link_path)?;

        // Run export
        // This should NOT fail, but should just output a warning (after we fix it)
        // and skip the file.
        export_directory(&src_dir, &dst_dir, &cipher, &config, 0, false)?;

        // Check destination - should NOT exist
        let exported_link = dst_dir.join(link_name);
        assert!(
            !exported_link.exists() && fs::symlink_metadata(&exported_link).is_err(),
            "Bad symlink should be skipped"
        );

        // Cleanup
        let _ = fs::remove_dir_all(temp_dir);

        Ok(())
    }

    #[test]
    fn test_v4_export_header_issue() -> Result<()> {
        use std::io::Write;

        let temp_dir =
            std::env::temp_dir().join(format!("encfs_v4_export_test_{}", std::process::id()));
        let src_dir = temp_dir.join("src");
        let dst_dir = temp_dir.join("dst");
        fs::create_dir_all(&src_dir)?;
        fs::create_dir_all(&dst_dir)?;

        // Setup Cipher (Use same as V6 for simplicity of test, but config is V4)
        let iface = Interface {
            name: "ssl/aes".to_string(),
            major: 3,
            minor: 0,
            age: 0,
        };
        let mut cipher = SslCipher::new(&iface, 192)?;
        let key = vec![0u8; 24];
        let iv = vec![0u8; cipher.iv_len()];
        cipher.set_key(&key, &iv);

        // Setup V4 Config (unique_iv = false)
        let config = EncfsConfig {
            config_type: ConfigType::V4,
            creator: "test".to_string(),
            version: 0,
            cipher_iface: iface.clone(),
            name_iface: iface.clone(),
            key_size: 192,
            block_size: 1024,
            key_data: vec![],
            salt: vec![],
            kdf_iterations: 0,
            desired_kdf_duration: 0,
            plain_data: false,
            block_mac_bytes: 0,
            block_mac_rand_bytes: 0,
            unique_iv: false, // Critical for this test
            external_iv_chaining: false,
            chained_name_iv: false, // V4 usually false
            allow_holes: false,
        };

        // Create a plain file
        let filename = "myfile.txt";
        let content = b"Hello V4 World";

        // encrypt filename (V4 usually stream encoding, but we reuse cipher setup)
        let (enc_name, _) = cipher.encrypt_filename(filename.as_bytes(), 0)?;

        // Encrypt content WITHOUT header (because unique_iv is false)
        // For V4, typically we just encrypt with file_iv = 0 (if no external chaining)
        let enc_path = src_dir.join(&enc_name);
        let mut enc_file = std::fs::File::create(&enc_path)?;

        // Manually encrypt content
        // We use block 0, file_iv 0.
        // FileDecoder/Encoder handles this. We can use SslCipher directly.
        // For partial block (stream cipher):
        let mut enc_content = content.to_vec();
        // encrypt_block_inplace(buffer, block_num, file_iv, block_size)
        // logical block 0.
        cipher.encrypt_block_inplace(&mut enc_content, 0, 0, 1024)?;
        enc_file.write_all(&enc_content)?;

        // Run export
        // If the bug exists, export_directory will try to read 8 bytes header.
        // "Hello V4 World" is 14 bytes.
        // It will take first 8 bytes as "header", decrypt them (garbage IV),
        // then decrypt the rest (6 bytes) using that garbage IV.
        // The output will be truncated (6 bytes instead of 14) and garbage.
        export_directory(&src_dir, &dst_dir, &cipher, &config, 0, false)?;

        let exported_path = dst_dir.join(filename);
        if !exported_path.exists() {
            panic!("Exported file not found");
        }

        let exported_content = fs::read(&exported_path)?;

        // Diagnostic output
        println!("Original len: {}", content.len());
        println!("Exported len: {}", exported_content.len());

        if exported_content.len() != content.len() {
            println!(
                "Bug reproduced: Exported content length mismatch. Expected {}, got {}",
                content.len(),
                exported_content.len()
            );
            // Assert failure to confirm repro
            assert_eq!(
                exported_content.len(),
                content.len(),
                "Content length mismatch (header likely consumed)"
            );
        }

        assert_eq!(exported_content, content, "Content mismatch");

        // Cleanup
        let _ = fs::remove_dir_all(temp_dir);

        Ok(())
    }

    #[test]
    fn test_showcruft_broken_symlink() -> Result<()> {
        use std::os::unix::fs::symlink;

        let temp_dir =
            std::env::temp_dir().join(format!("encfs_showcruft_test_{}", std::process::id()));
        fs::create_dir_all(&temp_dir)?;

        // Setup Cipher
        let iface = Interface {
            name: "ssl/aes".to_string(),
            major: 3,
            minor: 0,
            age: 0,
        };
        let mut cipher = SslCipher::new(&iface, 192)?;
        let key = vec![0u8; 24]; // 192 bits
        let iv = vec![0u8; cipher.iv_len()];
        cipher.set_key(&key, &iv);
        let dir_iv = 0;

        // 1. Create a broken symlink with encrypted name
        let (enc_broken_name, _) = cipher.encrypt_filename("broken_link".as_bytes(), dir_iv)?;
        let broken_path = temp_dir.join(&enc_broken_name);
        symlink("non_existent_target", &broken_path)?;

        // 2. Create a directory with encrypted name
        let (enc_subdir_name, _sub_iv) = cipher.encrypt_filename("subdir".as_bytes(), dir_iv)?;
        let subdir_path = temp_dir.join(&enc_subdir_name);
        fs::create_dir_all(&subdir_path)?;

        // 3. Create a valid file inside the subdirectory (undecodable/plaintext to trigger issue count)
        // We leave it plaintext so it counts as 1 issue found inside the dir
        fs::write(subdir_path.join("plaintext_file"), "content")?;

        // 4. Create a symlink to the directory (encrypted name)
        let (enc_link_name, _) = cipher.encrypt_filename("link_to_subdir".as_bytes(), dir_iv)?;
        let link_path = temp_dir.join(&enc_link_name);
        // Point to the relative name of the subdir
        symlink(&enc_subdir_name, &link_path)?;

        let mut stats = ShowcruftStats {
            files_checked: 0,
            dirs_checked: 0,
            issues_found: 0,
        };

        // Run find_undecodable_files
        find_undecodable_files(&temp_dir, &temp_dir, &cipher, false, dir_iv, &mut stats)?;

        // Cleanup
        let _ = fs::remove_dir_all(&temp_dir);

        // Verification:
        // Root dir checked: 1
        // Subdir checked: 1 (recurse into enc_subdir)
        // Symlink checked: 0 (should NOT recurse into enc_link_name)
        // Total dirs: 2
        assert_eq!(stats.dirs_checked, 2, "Should check exactly 2 directories");

        // Files checked:
        // Root: 3 entries (broken_link, subdir, link_to_subdir)
        // Subdir: 1 entry (plaintext_file)
        // Total files checked: 4
        assert_eq!(stats.files_checked, 4, "Should check 4 files");

        // Issues found:
        // plaintext_file inside subdir is undecodable -> 1
        // invalid broken symlink target? No, we don't check target validity in showcruft, only filename.
        // Filenames in root are all valid encrypted names.
        // So issues should be 1.
        assert_eq!(
            stats.issues_found, 1,
            "Should find 1 issue (plaintext file in subdir)"
        );

        Ok(())
    }

    #[test]
    fn test_export_symlink_decryption_fail() -> Result<()> {
        let temp_dir = std::env::temp_dir().join(format!(
            "encfs_export_decryption_fail_{}",
            std::process::id()
        ));
        let src_dir = temp_dir.join("src");
        let dst_dir = temp_dir.join("dst");
        fs::create_dir_all(&src_dir)?;
        fs::create_dir_all(&dst_dir)?;

        // Setup Cipher
        let iface = Interface {
            name: "ssl/aes".to_string(),
            major: 3,
            minor: 0,
            age: 0,
        };
        let mut cipher = SslCipher::new(&iface, 192)?;
        let key = vec![0u8; 24];
        let iv = vec![0u8; cipher.iv_len()];
        cipher.set_key(&key, &iv);

        // Setup Config
        let config = EncfsConfig {
            config_type: ConfigType::V6,
            creator: "test".to_string(),
            version: constants::DEFAULT_CONFIG_VERSION,
            cipher_iface: iface.clone(),
            name_iface: iface.clone(),
            key_size: 192,
            block_size: 1024,
            key_data: vec![],
            salt: vec![],
            kdf_iterations: 0,
            desired_kdf_duration: 0,
            plain_data: false,
            block_mac_bytes: 0,
            block_mac_rand_bytes: 0,
            unique_iv: true,
            external_iv_chaining: false,
            chained_name_iv: true,
            allow_holes: false,
        };

        // Create a symlink with encrypted name but GARBAGE target
        // The export function tries to decrypt the target.
        let link_name = "mylink";
        let (enc_name, _) = cipher.encrypt_filename(link_name.as_bytes(), 0)?;

        let link_path = src_dir.join(&enc_name);
        // "INVALID_TARGET" is unlikely to be a valid encrypted string that decrypts successfully
        symlink("INVALID_TARGET", &link_path)?;

        // Run export
        // This fails if the bug is present
        match export_directory(&src_dir, &dst_dir, &cipher, &config, 0, false) {
            Ok(_) => {}
            Err(e) => {
                // Clean up before panicking
                let _ = fs::remove_dir_all(temp_dir);
                panic!(
                    "export_directory failed on undecryptable symlink target: {}",
                    e
                );
            }
        }

        // Cleanup
        let _ = fs::remove_dir_all(temp_dir);

        Ok(())
    }

    #[test]
    fn test_export_fail_on_error() -> Result<()> {
        let temp_dir =
            std::env::temp_dir().join(format!("encfs_export_fail_on_error_{}", std::process::id()));
        let src_dir = temp_dir.join("src");
        let dst_dir = temp_dir.join("dst");
        fs::create_dir_all(&src_dir)?;
        fs::create_dir_all(&dst_dir)?;

        let iface = Interface {
            name: "ssl/aes".to_string(),
            major: 3,
            minor: 0,
            age: 0,
        };
        let mut cipher = SslCipher::new(&iface, 192)?;
        let key = vec![0u8; 24];
        let iv = vec![0u8; cipher.iv_len()];
        cipher.set_key(&key, &iv);

        let config = EncfsConfig {
            config_type: ConfigType::V6,
            creator: "test".to_string(),
            version: constants::DEFAULT_CONFIG_VERSION,
            cipher_iface: iface.clone(),
            name_iface: iface.clone(),
            key_size: 192,
            block_size: 1024,
            key_data: vec![],
            salt: vec![],
            kdf_iterations: 0,
            desired_kdf_duration: 0,
            plain_data: false,
            block_mac_bytes: 0,
            block_mac_rand_bytes: 0,
            unique_iv: true,
            external_iv_chaining: false,
            chained_name_iv: true,
            allow_holes: false,
        };

        // Create a symlink with encrypted name and GARBAGE target (undecryptable)
        let link_name = "fail_link";
        let (enc_name, _) = cipher.encrypt_filename(link_name.as_bytes(), 0)?;
        symlink("INVALID_TARGET", src_dir.join(&enc_name))?;

        // Run export with fail_on_error = true
        let result = export_directory(&src_dir, &dst_dir, &cipher, &config, 0, true);

        // Should return Error
        assert!(
            result.is_err(),
            "Export should fail when fail_on_error is true"
        );
        let err = result.unwrap_err();
        assert!(
            err.to_string().contains("Undecryptable symlink target"),
            "Unexpected error: {}",
            err
        );

        // Cleanup
        let _ = fs::remove_dir_all(temp_dir);
        Ok(())
    }
}
