use std::ffi::OsString;
use std::num::NonZeroU32;
#[cfg(target_os = "linux")]
use std::os::unix::io::RawFd;

#[cfg(target_os = "freebsd")]
use nix::mount::Nmount;
#[cfg(target_os = "linux")]
use nix::unistd;

/// Default max write size (128KB)
pub const DEFAULT_MAX_WRITE: u32 = 128 * 1024;

/// mount options.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct MountOptions {
    // Options implemented within rfuse3
    pub(crate) nonempty: bool,

    // mount options
    pub(crate) allow_other: bool,
    pub(crate) allow_root: bool,
    pub(crate) custom_options: Option<OsString>,
    #[cfg(target_os = "linux")]
    pub(crate) dirsync: bool,
    pub(crate) default_permissions: bool,
    pub(crate) fs_name: Option<String>,
    pub(crate) gid: Option<u32>,
    #[cfg(any(target_os = "macos", target_os = "freebsd"))]
    pub(crate) intr: bool,
    #[cfg(target_os = "linux")]
    pub(crate) nodiratime: bool,
    pub(crate) noatime: bool,
    #[cfg(target_os = "linux")]
    pub(crate) nodev: bool,
    pub(crate) noexec: bool,
    pub(crate) nosuid: bool,
    pub(crate) read_only: bool,
    #[cfg(target_os = "freebsd")]
    pub(crate) suiddir: bool,
    pub(crate) sync: bool,
    pub(crate) uid: Option<u32>,

    // Optional FUSE features
    pub(crate) dont_mask: bool,
    pub(crate) no_open_support: bool,
    pub(crate) no_open_dir_support: bool,
    pub(crate) handle_killpriv: bool,
    pub(crate) write_back: bool,
    pub(crate) direct_io: bool,
    pub(crate) force_readdir_plus: bool,

    // FUSE transfer size options
    /// Maximum size of write requests. Default is 128KB.
    pub(crate) max_write: NonZeroU32,
    /// Maximum readahead size. If None, uses kernel's default.
    pub(crate) max_readahead: Option<u32>,

    // Other FUSE mount options
    // default 40000
    pub(crate) rootmode: Option<u32>,
}

impl Default for MountOptions {
    fn default() -> Self {
        Self {
            nonempty: false,
            allow_other: false,
            allow_root: false,
            custom_options: None,
            #[cfg(target_os = "linux")]
            dirsync: false,
            default_permissions: false,
            fs_name: None,
            gid: None,
            #[cfg(any(target_os = "macos", target_os = "freebsd"))]
            intr: false,
            #[cfg(target_os = "linux")]
            nodiratime: false,
            noatime: false,
            #[cfg(target_os = "linux")]
            nodev: false,
            noexec: false,
            nosuid: false,
            read_only: false,
            #[cfg(target_os = "freebsd")]
            suiddir: false,
            sync: false,
            uid: None,
            dont_mask: false,
            no_open_support: false,
            no_open_dir_support: false,
            handle_killpriv: false,
            write_back: false,
            direct_io: false,
            force_readdir_plus: false,
            max_write: NonZeroU32::new(DEFAULT_MAX_WRITE).unwrap(),
            max_readahead: None,
            rootmode: None,
        }
    }
}

impl MountOptions {
    /// set fuse filesystem mount `user_id`, default is current uid.
    pub fn uid(&mut self, uid: u32) -> &mut Self {
        self.uid.replace(uid);

        self
    }

    /// set fuse filesystem mount `group_id`, default is current gid.
    pub fn gid(&mut self, gid: u32) -> &mut Self {
        self.gid.replace(gid);

        self
    }

    /// set fuse filesystem name, default is **fuse**.
    pub fn fs_name(&mut self, name: impl Into<String>) -> &mut Self {
        self.fs_name.replace(name.into());

        self
    }

    /// set fuse filesystem `rootmode`, default is 40000.
    #[cfg(target_os = "linux")]
    pub fn rootmode(&mut self, rootmode: u32) -> &mut Self {
        self.rootmode.replace(rootmode);

        self
    }

    /// set fuse filesystem `allow_root` mount option, default is disable.
    pub fn allow_root(&mut self, allow_root: bool) -> &mut Self {
        self.allow_root = allow_root;

        self
    }

    /// set fuse filesystem `allow_other` mount option, default is disable.
    pub fn allow_other(&mut self, allow_other: bool) -> &mut Self {
        self.allow_other = allow_other;

        self
    }

    /// set fuse filesystem `ro` mount option, default is disable.
    pub fn read_only(&mut self, read_only: bool) -> &mut Self {
        self.read_only = read_only;

        self
    }

    /// allow fuse filesystem mount on a non-empty directory, default is not allowed.
    pub fn nonempty(&mut self, nonempty: bool) -> &mut Self {
        self.nonempty = nonempty;

        self
    }

    /// set fuse filesystem `default_permissions` mount option, default is disable.
    ///
    /// When `default_permissions` is set, the [`raw::access`] and [`path::access`] is useless.
    ///
    /// [`raw::access`]: crate::raw::Filesystem::access
    /// [`path::access`]: crate::path::PathFilesystem::access
    pub fn default_permissions(&mut self, default_permissions: bool) -> &mut Self {
        self.default_permissions = default_permissions;

        self
    }

    /// don't apply umask to file mode on create operations, default is disable.
    pub fn dont_mask(&mut self, dont_mask: bool) -> &mut Self {
        self.dont_mask = dont_mask;

        self
    }

    /// make kernel support zero-message opens, default is disable
    pub fn no_open_support(&mut self, no_open_support: bool) -> &mut Self {
        self.no_open_support = no_open_support;

        self
    }

    /// make kernel support zero-message opendir, default is disable
    pub fn no_open_dir_support(&mut self, no_open_dir_support: bool) -> &mut Self {
        self.no_open_dir_support = no_open_dir_support;

        self
    }

    /// fs handle killing `suid`/`sgid`/`cap` on `write`/`chown`/`trunc`, default is disable.
    pub fn handle_killpriv(&mut self, handle_killpriv: bool) -> &mut Self {
        self.handle_killpriv = handle_killpriv;

        self
    }

    /// try to set the `FUSE_WRITEBACK_CACHE` enable write back cache for buffered writes, default
    /// is disable.
    ///
    /// # Notes:
    ///
    /// if enable this feature, when write flags has `FUSE_WRITE_CACHE`, file handle is guessed.
    pub fn write_back(&mut self, write_back: bool) -> &mut Self {
        self.write_back = write_back;

        self
    }

    /// Force direct I/O for all file opens, similar to libfuse `-o direct_io`.
    ///
    /// This maps to setting `FOPEN_DIRECT_IO` on `open`/`create` replies.
    pub fn direct_io(&mut self, direct_io: bool) -> &mut Self {
        self.direct_io = direct_io;

        self
    }

    /// force filesystem use readdirplus only, when kernel use readdir will return `ENOSYS`,
    /// default is disable.
    ///
    /// # Notes:
    /// this may don't work with some old Linux Kernel.
    pub fn force_readdir_plus(&mut self, force_readdir_plus: bool) -> &mut Self {
        self.force_readdir_plus = force_readdir_plus;

        self
    }

    /// set custom options for fuse filesystem, the custom options will be used in mount
    pub fn custom_options(&mut self, custom_options: impl Into<OsString>) -> &mut Self {
        self.custom_options = Some(custom_options.into());

        self
    }

    /// Set the maximum size of write requests sent by the kernel.
    /// Default is 128KB. Larger values can improve performance for large writes.
    ///
    /// # Example
    /// ```
    /// use std::num::NonZeroU32;
    /// use rfuse3::MountOptions;
    ///
    /// let mut options = MountOptions::default();
    /// options.max_write(NonZeroU32::new(1024 * 1024).unwrap()); // 1MB
    /// ```
    pub fn max_write(&mut self, max_write: NonZeroU32) -> &mut Self {
        self.max_write = max_write;

        self
    }

    /// Set the maximum readahead size. If not set, uses the kernel's default value.
    /// Larger values can improve sequential read performance.
    ///
    /// # Example
    /// ```
    /// use rfuse3::MountOptions;
    ///
    /// let mut options = MountOptions::default();
    /// options.max_readahead(Some(256 * 1024)); // 256KB
    /// ```
    pub fn max_readahead(&mut self, max_readahead: Option<u32>) -> &mut Self {
        self.max_readahead = max_readahead;

        self
    }

    #[cfg(target_os = "freebsd")]
    pub(crate) fn build(&self) -> Nmount {
        let mut nmount = Nmount::new();
        nmount
            .str_opt(c"fstype", c"fusefs")
            .str_opt(c"from", c"/dev/fuse");
        if self.allow_other {
            nmount.null_opt(c"allow_other");
        }
        if self.allow_root {
            nmount.null_opt(c"allow_root");
        }
        if self.default_permissions {
            nmount.null_opt(c"default_permissions");
        }
        if let Some(fs_name) = &self.fs_name {
            nmount.str_opt_owned(c"subtype=", fs_name.as_str());
        }
        if self.intr {
            nmount.null_opt(c"intr");
        }
        if let Some(custom_options) = self.custom_options.as_ref() {
            nmount.null_opt_owned(custom_options.as_os_str());
        }
        // TODO: additional options: push_symlinks_in, max_read=, timeout=
        nmount
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn build(&self, fd: RawFd) -> OsString {
        let mut opts = vec![
            format!("fd={fd}"),
            format!(
                "user_id={}",
                self.uid.unwrap_or_else(|| unistd::getuid().as_raw())
            ),
            format!(
                "group_id={}",
                self.gid.unwrap_or_else(|| unistd::getgid().as_raw())
            ),
            format!("rootmode={}", self.rootmode.unwrap_or(40000)),
        ];

        if self.allow_root {
            opts.push("allow_root".to_string());
        }

        if self.allow_other {
            opts.push("allow_other".to_string());
        }

        if self.default_permissions {
            opts.push("default_permissions".to_string());
        }

        let mut options = OsString::from(opts.join(","));

        if let Some(custom_options) = &self.custom_options {
            options.push(",");
            options.push(custom_options);
        }

        options
    }

    #[cfg(target_os = "macos")]
    pub(crate) fn build(&self) -> OsString {
        let mut opts = vec![String::from("-o fsname=ofs")];

        if self.allow_root {
            opts.push("-o allow_root".to_string());
        }

        if self.allow_other {
            opts.push("-o allow_other".to_string());
        }

        let mut options = OsString::from(opts.join(" "));

        if let Some(custom_options) = &self.custom_options {
            options.push(" ");
            options.push(custom_options);
        }

        options
    }

    #[cfg(all(target_os = "linux", feature = "unprivileged"))]
    pub(crate) fn build_with_unprivileged(&self) -> OsString {
        let mut opts = vec![
            format!(
                "user_id={}",
                self.uid.unwrap_or_else(|| unistd::getuid().as_raw())
            ),
            format!(
                "group_id={}",
                self.gid.unwrap_or_else(|| unistd::getgid().as_raw())
            ),
            format!("rootmode={}", self.rootmode.unwrap_or(40000)),
            format!(
                "fsname={}",
                self.fs_name.as_ref().unwrap_or(&"fuse".to_string())
            ),
        ];

        if self.allow_root {
            opts.push("allow_root".to_string());
        }

        if self.allow_other {
            opts.push("allow_other".to_string());
        }

        if self.read_only {
            opts.push("ro".to_string());
        }

        if self.default_permissions {
            opts.push("default_permissions".to_string());
        }

        let mut options = OsString::from(opts.join(","));

        if let Some(custom_options) = &self.custom_options {
            options.push(",");
            options.push(custom_options);
        }

        options
    }

    #[cfg(target_os = "freebsd")]
    pub(crate) fn flags(&self) -> nix::mount::MntFlags {
        use nix::mount::MntFlags;

        let mut flags = MntFlags::empty();
        if self.noatime {
            flags.insert(MntFlags::MNT_NOATIME);
        }
        if self.noexec {
            flags.insert(MntFlags::MNT_NOEXEC);
        }
        if self.nosuid {
            flags.insert(MntFlags::MNT_NOSUID);
        }
        if self.read_only {
            flags.insert(MntFlags::MNT_RDONLY);
        }
        if self.suiddir {
            flags.insert(MntFlags::MNT_SUIDDIR);
        }
        if self.sync {
            flags.insert(MntFlags::MNT_SYNCHRONOUS);
        }
        flags
    }

    #[cfg(target_os = "macos")]
    #[allow(dead_code)]
    pub(crate) fn flags(&self) -> nix::mount::MntFlags {
        use nix::mount::MntFlags;

        let mut flags = MntFlags::empty();
        if self.noatime {
            flags.insert(MntFlags::MNT_NOATIME);
        }
        if self.noexec {
            flags.insert(MntFlags::MNT_NOEXEC);
        }
        if self.nosuid {
            flags.insert(MntFlags::MNT_NOSUID);
        }
        if self.read_only {
            flags.insert(MntFlags::MNT_RDONLY);
        }

        if self.sync {
            flags.insert(MntFlags::MNT_SYNCHRONOUS);
        }
        flags
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn flags(&self) -> nix::mount::MsFlags {
        use nix::mount::MsFlags;

        let mut flags = MsFlags::empty();
        if self.dirsync {
            flags.insert(MsFlags::MS_DIRSYNC);
        }
        if self.noatime {
            flags.insert(MsFlags::MS_NOATIME);
        }
        if self.nodev {
            flags.insert(MsFlags::MS_NODEV);
        }
        if self.nodiratime {
            flags.insert(MsFlags::MS_NODIRATIME);
        }
        if self.noexec {
            flags.insert(MsFlags::MS_NOEXEC);
        }
        if self.nosuid {
            flags.insert(MsFlags::MS_NOSUID);
        }
        if self.read_only {
            flags.insert(MsFlags::MS_RDONLY);
        }
        if self.sync {
            flags.insert(MsFlags::MS_SYNCHRONOUS);
        }
        flags
    }
}
