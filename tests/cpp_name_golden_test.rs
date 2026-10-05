//! Filename and symlink-target encodings checked against output from the
//! C++ EncFS 1.9.5 sources (`NameIO::encodePath`, and `"+" + encodeName` for
//! absolute symlink targets), built from the `v1.9.5` tag and run on the
//! `encfs6-direct-nochain.xml` key (password "test") with the name codec and
//! `chainedNameIV` overridden per case.

use encfs::config::EncfsConfig;
use encfs::fs::EncFs;
use std::path::{Path, PathBuf};

struct Case {
    codec: &'static str,
    major: i32,
    chained: bool,
    /// (plaintext, C++ encoding) pairs; relative entries are paths,
    /// absolute ones are symlink targets.
    goldens: &'static [(&'static str, &'static str)],
}

const CASES: &[Case] = &[
    Case {
        codec: "nameio/block32",
        major: 4,
        chained: false,
        goldens: &[
            ("file_2", "4LAGZFYFTW34NYRGX25KXCABDTNJC"),
            (
                "dir/foo",
                "CTGO5MDOQQSJL7HRVBM6DMLRM6TJA/ADGFAJRXTKWPMYENIMC46ESAC3C4D",
            ),
            ("a.b", "LZO2XUDY32B5VDB3TZPSPKIJICRHF"),
            ("Mixed_Case", "QEO4HNSIMCSZRAC3NB5N5ZXP5ORMA"),
            ("/etc/hosts", "+CZNVYCUPICVTQJVVJZ5SNSHYD55KL"),
        ],
    },
    Case {
        codec: "nameio/block32",
        major: 4,
        chained: true,
        goldens: &[
            ("file_2", "DYVGNY322UNCYXNZK3TD27UTIKQ6G"),
            (
                "dir/foo",
                "4MLH5PC2V6FWUONACUP45UZ6RDK3O/F74R365RYISACAGXTMLSHJ4MCU5IK",
            ),
            ("a.b", "HOLTYOAR527QITG2BKZ6TAVSUZF4P"),
            ("Mixed_Case", "HF7SZKHEWYBGZL4P2LSM6XOMS36PM"),
            ("/etc/hosts", "+CZNVYCUPICVTQJVVJZ5SNSHYD55KL"),
        ],
    },
    Case {
        codec: "nameio/stream",
        major: 2,
        chained: false,
        goldens: &[
            ("file_2", "OBra3AoYQ-2"),
            ("dir/foo", "YkivKR0/ehSZIvC"),
            ("a.b", "7jaFE73"),
            ("Mixed_Case", "7qQvlh4-1YAduC1o"),
            ("/etc/hosts", "+KF4rvSTbbUUo-2C"),
        ],
    },
    Case {
        codec: "nameio/stream",
        major: 2,
        chained: true,
        goldens: &[
            ("file_2", "NmVGWSkdil0"),
            ("dir/foo", "SZa0Oe1/3MjvvG8"),
            ("a.b", ",aU2VE1"),
            ("Mixed_Case", "s9JAminXZ56a7ECN"),
            ("/etc/hosts", "+KF4rvSTbbUUo-2C"),
        ],
    },
    Case {
        codec: "nameio/block",
        major: 4,
        chained: false,
        goldens: &[
            ("file_2", "w3kY9smoitBQoQpRpJ,0XN97"),
            (
                "dir/foo",
                "WdlpN1528Hfz7K1AzUhWAzA-/UVd,GlvINTAAdVM0ib6-WhUD",
            ),
        ],
    },
];

fn fixture_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures")
}

#[test]
fn names_and_symlink_targets_match_cpp() -> anyhow::Result<()> {
    let base = EncfsConfig::load(&fixture_root().join("encfs6-direct-nochain.xml"))?;
    for case in CASES {
        let mut config = base.clone();
        config.name_iface.name = case.codec.to_string();
        config.name_iface.major = case.major;
        config.chained_name_iv = case.chained;
        let tag = format!("{} chained={}", case.codec, case.chained);

        let cipher = config.get_cipher("test")?;
        for &(plain, golden) in case.goldens {
            if plain.starts_with('/') {
                // Symlink targets are stored with the same encoding.
                let stored =
                    encfs::symlink_target::encrypt(cipher.as_ref(), &config, plain.as_bytes(), 0)?;
                assert_eq!(String::from_utf8(stored)?, golden, "{tag}: {plain}");
                let back =
                    encfs::symlink_target::decrypt(cipher.as_ref(), &config, golden.as_bytes(), 0)?;
                assert_eq!(back, plain.as_bytes(), "{tag}: {plain}");
                continue;
            }
            let stored =
                encfs::symlink_target::encrypt(cipher.as_ref(), &config, plain.as_bytes(), 0)?;
            assert_eq!(String::from_utf8(stored)?, golden, "{tag}: target {plain}");
        }

        let encfs = EncFs::new(fixture_root(), config.get_cipher("test")?, config.clone());
        for &(plain, golden) in case.goldens.iter().filter(|(p, _)| !p.starts_with('/')) {
            let (encrypted, _) = encfs
                .encrypt_path(Path::new(plain))
                .map_err(|e| anyhow::anyhow!("{tag}: encrypt_path({plain}) failed: {e}"))?;
            assert_eq!(encrypted, fixture_root().join(golden), "{tag}: {plain}");

            let (decrypted, _) = encfs
                .decrypt_path(Path::new(golden))
                .map_err(|e| anyhow::anyhow!("{tag}: decrypt_path({golden}) failed: {e}"))?;
            assert_eq!(decrypted, Path::new(plain), "{tag}: {golden}");

            if case.codec == "nameio/block32" {
                // C++ decodes Base32 case-insensitively.
                let lower = golden.to_ascii_lowercase();
                let (decrypted, _) = encfs
                    .decrypt_path(Path::new(&lower))
                    .map_err(|e| anyhow::anyhow!("{tag}: decrypt_path({lower}) failed: {e}"))?;
                assert_eq!(decrypted, Path::new(plain), "{tag}: {lower}");
            }
        }
    }
    Ok(())
}
