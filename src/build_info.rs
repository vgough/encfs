//! Build metadata shared by all command-line programs.

/// Package version followed by revision, build date, compiler, and target details.
pub const VERSION: &str = concat!(env!("CARGO_PKG_VERSION"), " ", env!("ENCFS_BUILD_INFO"));

/// A help banner identifying the program and the build it came from.
pub fn banner(program: &str) -> String {
    format!("{program} {VERSION}")
}
