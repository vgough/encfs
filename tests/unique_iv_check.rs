use encfs::config::EncfsConfig;
use std::io::Write;

#[test]
fn test_unique_iv_false_is_rejected() {
    let xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE boost_serialization>
<boost_serialization signature="serialization::archive" version="7">
    <cfg class_id="0" tracking_level="0" version="20">
        <version>20100713</version>
        <creator>EncFS Test</creator>
        <cipherAlg class_id="1" tracking_level="0" version="0">
            <name>ssl/aes</name>
            <major>3</major>
            <minor>0</minor>
        </cipherAlg>
        <nameAlg>
            <name>nameio/block</name>
            <major>4</major>
            <minor>0</minor>
        </nameAlg>
        <keySize>192</keySize>
        <blockSize>1024</blockSize>
        <plainData>0</plainData>
        <uniqueIV>0</uniqueIV> <!-- This is the problematic value -->
        <chainedNameIV>1</chainedNameIV>
        <externalIVChaining>0</externalIVChaining>
        <blockMACBytes>0</blockMACBytes>
        <blockMACRandBytes>0</blockMACRandBytes>
        <allowHoles>1</allowHoles>
        <encodedKeySize>44</encodedKeySize>
        <encodedKeyData>
+qPhkOEwsxhmeghgGYlexofVLdT39dHDAW0MSNV0xPoeMa4qBihM1X9FdD4=
        </encodedKeyData>
        <saltLen>20</saltLen>
        <saltData>
tccFKejCQQ9w0b9oEaATUZ0eFWE=
        </saltData>
        <kdfIterations>500000</kdfIterations>
        <desiredKDFDuration>500</desiredKDFDuration>
    </cfg>
</boost_serialization>
"#;

    // Use a temp file
    let dir = std::env::temp_dir();
    let config_path = dir.join(format!("encfs_test_unique_iv_{}.xml", std::process::id()));

    let mut f = std::fs::File::create(&config_path).expect("failed to create temp file");
    f.write_all(xml.as_bytes()).expect("failed to write config");
    drop(f);

    // Try to load it
    let result = EncfsConfig::load(&config_path);

    // Cleanup
    let _ = std::fs::remove_file(&config_path);

    // Assert that it fails
    // Currently (before fix), this will probably succeed (Ok), so we expect assert!(result.is_err()) to fail.
    assert!(
        result.is_err(),
        "EncfsConfig::load should fail when uniqueIV is 0 (false), but it succeeded: {:?}",
        result
    );
}
