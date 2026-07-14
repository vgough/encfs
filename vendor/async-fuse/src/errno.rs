use std::error::Error;
use std::fmt::{self, Display, Formatter};
use std::io::Error as IoError;
use std::os::raw::c_int;

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
/// linux errno wrap.
pub struct Errno(c_int);

impl From<Errno> for c_int {
    fn from(errno: Errno) -> Self {
        -errno.0
    }
}

impl From<c_int> for Errno {
    fn from(errno: c_int) -> Self {
        Self(errno)
    }
}

/// When raw os error is undefined, will return Errno(libc::EIO)
impl From<IoError> for Errno {
    fn from(err: IoError) -> Self {
        if let Some(errno) = err.raw_os_error() {
            Self(errno)
        } else {
            Self(libc::EIO)
        }
    }
}

impl From<Errno> for IoError {
    fn from(errno: Errno) -> Self {
        IoError::from_raw_os_error(errno.0)
    }
}

impl Display for Errno {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "errno is {}", self.0)
    }
}

impl Errno {
    pub fn new_not_exist() -> Self {
        Self(libc::ENOENT)
    }

    pub fn new_exist() -> Self {
        Self(libc::EEXIST)
    }

    pub fn new_is_dir() -> Self {
        Self(libc::EISDIR)
    }

    pub fn new_is_not_dir() -> Self {
        Self(libc::ENOTDIR)
    }

    pub fn is_not_exist(&self) -> bool {
        self.0 == libc::ENOENT
    }

    pub fn is_exist(&self) -> bool {
        self.0 == libc::EEXIST
    }

    pub fn is_dir(&self) -> bool {
        self.0 == libc::EISDIR
    }

    pub fn is_not_dir(&self) -> bool {
        self.0 == libc::ENOTDIR
    }
}

impl Error for Errno {}
