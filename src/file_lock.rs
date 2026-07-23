use fuse3::{FileLock, LockKind};
use std::os::fd::RawFd;

fn errno() -> libc::c_int {
    std::io::Error::last_os_error()
        .raw_os_error()
        .unwrap_or(libc::EIO)
}

fn flock_for(lock: FileLock) -> Result<libc::flock, libc::c_int> {
    let FileLock {
        start,
        end,
        kind,
        pid,
    } = lock;
    if end < start {
        return Err(libc::EINVAL);
    }
    let lock_type = match kind {
        LockKind::Read => libc::F_RDLCK,
        LockKind::Write => libc::F_WRLCK,
        LockKind::Unlock => libc::F_UNLCK,
    };

    let l_start = libc::off_t::try_from(start).map_err(|_| libc::EOVERFLOW)?;
    let l_len = if end == u64::MAX {
        0
    } else {
        let length = end
            .checked_sub(start)
            .and_then(|n| n.checked_add(1))
            .ok_or(libc::EOVERFLOW)?;
        libc::off_t::try_from(length).map_err(|_| libc::EOVERFLOW)?
    };

    Ok(libc::flock {
        l_type: lock_type as libc::c_short,
        l_whence: libc::SEEK_SET as libc::c_short,
        l_start,
        l_len,
        l_pid: pid as libc::pid_t,
    })
}

pub(crate) fn getlk(fd: RawFd, requested: FileLock) -> Result<FileLock, libc::c_int> {
    let mut lock = flock_for(requested)?;
    if unsafe { libc::fcntl(fd, libc::F_GETLK, &mut lock) } == -1 {
        return Err(errno());
    }

    let reply_start = u64::try_from(lock.l_start).map_err(|_| libc::EIO)?;
    let reply_end = if lock.l_len == 0 {
        u64::MAX
    } else {
        let length = u64::try_from(lock.l_len).map_err(|_| libc::EIO)?;
        reply_start.checked_add(length - 1).ok_or(libc::EOVERFLOW)?
    };
    let kind = match lock.l_type {
        libc::F_RDLCK => LockKind::Read,
        libc::F_WRLCK => LockKind::Write,
        libc::F_UNLCK => LockKind::Unlock,
        _ => return Err(libc::EIO),
    };
    Ok(FileLock {
        start: reply_start,
        end: reply_end,
        kind,
        pid: u32::try_from(lock.l_pid).unwrap_or(0),
    })
}

pub(crate) fn setlk(fd: RawFd, requested: FileLock, block: bool) -> Result<(), libc::c_int> {
    let lock = flock_for(requested)?;
    let command = if block { libc::F_SETLKW } else { libc::F_SETLK };
    if unsafe { libc::fcntl(fd, command, &lock) } == -1 {
        Err(errno())
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::flock_for;
    use fuse3::{FileLock, LockKind};

    fn lock(kind: LockKind, start: u64, end: u64, pid: u32) -> FileLock {
        FileLock {
            kind,
            start,
            end,
            pid,
        }
    }

    #[test]
    fn converts_inclusive_ranges() {
        let one = flock_for(lock(LockKind::Read, 7, 7, 12)).unwrap();
        assert_eq!((one.l_start, one.l_len), (7, 1));

        let finite = flock_for(lock(LockKind::Write, 7, 16, 12)).unwrap();
        assert_eq!((finite.l_start, finite.l_len), (7, 10));

        let eof = flock_for(lock(LockKind::Unlock, 7, u64::MAX, 12)).unwrap();
        assert_eq!((eof.l_start, eof.l_len), (7, 0));
    }

    #[test]
    fn rejects_invalid_ranges_and_types() {
        assert_eq!(
            flock_for(lock(LockKind::Read, 8, 7, 0)).unwrap_err(),
            libc::EINVAL
        );
        assert_eq!(
            flock_for(lock(LockKind::Read, u64::MAX, u64::MAX, 0)).unwrap_err(),
            libc::EOVERFLOW
        );
    }
}
