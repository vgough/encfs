use std::io::Result;

fn main() -> Result<()> {
    // protoc-bin-vendored only ships binaries for Linux, macOS and Windows,
    // so on other platforms (FreeBSD) there is nothing to point PROTOC at.
    // Leaving PROTOC unset makes prost-build search PATH for protoc instead.
    if let Ok(protoc_path) = protoc_bin_vendored::protoc_bin_path() {
        // SAFETY: build script runs in isolated build environment; no other threads rely on PROTOC.
        unsafe {
            std::env::set_var("PROTOC", protoc_path);
        }
    }

    prost_build::Config::new()
        .compile_protos(&["proto/encfs_config.proto"], &["proto"])
        .expect("Failed to compile protos");
    Ok(())
}
