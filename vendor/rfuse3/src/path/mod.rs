//! path based
//!
//! it is recommend to use path based [`PathFilesystem`] first, [`PathFilesystem`] is more simple
//! than inode based [`Filesystem`][crate::raw::Filesystem]. However if you want to control the
//! inode or do the path<->inode map on yourself, use [`Filesystem`][crate::raw::Filesystem].

pub use path_filesystem::PathFilesystem;
pub use session::Session;

pub use crate::raw::Request;

mod inode_generator;
mod inode_path_bridge;
mod path_filesystem;
pub mod reply;
mod session;

pub mod prelude {
    pub use super::reply::FileAttr;
    pub use super::reply::*;
    pub use super::PathFilesystem;
    pub use super::Request;
    pub use super::Session;
    pub use crate::notify::Notify;
    pub use crate::FileType;
    pub use crate::SetAttr;
}
