use std::io;
use std::path::Path;

use crate::path::inode_path_bridge::InodePathBridge;
use crate::path::path_filesystem::PathFilesystem;
use crate::raw;
use crate::MountOptions;

#[cfg(any(feature = "async-io-runtime", feature = "tokio-runtime"))]
#[derive(Debug)]
/// fuse filesystem session, path based.
pub struct Session {
    mount_options: MountOptions,
}

#[cfg(any(feature = "async-io-runtime", feature = "tokio-runtime"))]
impl Session {
    /// new a fuse filesystem session.
    pub fn new(mount_options: MountOptions) -> Self {
        Self { mount_options }
    }

    #[cfg(feature = "unprivileged")]
    /// mount the filesystem without root permission.
    pub async fn mount_with_unprivileged<P, FS>(
        self,
        fs: FS,
        mount_path: P,
    ) -> io::Result<raw::MountHandle>
    where
        P: AsRef<Path>,
        FS: PathFilesystem + Send + Sync + 'static,
    {
        let bridge = InodePathBridge::new(fs);

        raw::Session::new(self.mount_options)
            .mount_with_unprivileged(bridge, mount_path)
            .await
    }

    /// mount the filesystem with root permission.
    pub async fn mount<P, FS>(self, fs: FS, mount_path: P) -> io::Result<raw::MountHandle>
    where
        P: AsRef<Path>,
        FS: PathFilesystem + Send + Sync + 'static,
    {
        let bridge = InodePathBridge::new(fs);

        raw::Session::new(self.mount_options)
            .mount(bridge, mount_path)
            .await
    }
}
