use std::io::Result;

fn main() -> Result<()> {
    let protoc_path = protoc_bin_vendored::protoc_bin_path().expect("vendored protoc");
    // SAFETY: build script runs in isolated build environment; no other threads rely on PROTOC.
    unsafe {
        std::env::set_var("PROTOC", protoc_path);
    }

    prost_build::Config::new()
        .compile_protos(&["proto/encfs_config.proto"], &["proto"])
        .expect("Failed to compile protos");
    Ok(())
}
