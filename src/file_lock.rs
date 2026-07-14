use asyncfuse::path::reply::ReplyLock;
use std::os::fd::RawFd;

fn errno() -> libc::c_int {
    std::io::Error::last_os_error()
        .raw_os_error()
        .unwrap_or(libc::EIO)
}

fn flock_for(start: u64, end: u64, lock_type: u32, pid: u32) -> Result<libc::flock, libc::c_int> {
    if end < start {
        return Err(libc::EINVAL);
    }
    if lock_type != libc::F_RDLCK as u32
        && lock_type != libc::F_WRLCK as u32
        && lock_type != libc::F_UNLCK as u32
    {
        return Err(libc::EINVAL);
    }

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

pub(crate) fn getlk(
    fd: RawFd,
    start: u64,
    end: u64,
    lock_type: u32,
    pid: u32,
) -> Result<ReplyLock, libc::c_int> {
    let mut lock = flock_for(start, end, lock_type, pid)?;
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
    Ok(ReplyLock {
        start: reply_start,
        end: reply_end,
        r#type: lock.l_type as u32,
        pid: u32::try_from(lock.l_pid).unwrap_or(0),
    })
}

pub(crate) fn setlk(
    fd: RawFd,
    start: u64,
    end: u64,
    lock_type: u32,
    pid: u32,
    block: bool,
) -> Result<(), libc::c_int> {
    let lock = flock_for(start, end, lock_type, pid)?;
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

    #[test]
    fn converts_inclusive_ranges() {
        let one = flock_for(7, 7, libc::F_RDLCK as u32, 12).unwrap();
        assert_eq!((one.l_start, one.l_len), (7, 1));

        let finite = flock_for(7, 16, libc::F_WRLCK as u32, 12).unwrap();
        assert_eq!((finite.l_start, finite.l_len), (7, 10));

        let eof = flock_for(7, u64::MAX, libc::F_UNLCK as u32, 12).unwrap();
        assert_eq!((eof.l_start, eof.l_len), (7, 0));
    }

    #[test]
    fn rejects_invalid_ranges_and_types() {
        assert_eq!(
            flock_for(8, 7, libc::F_RDLCK as u32, 0).unwrap_err(),
            libc::EINVAL
        );
        assert_eq!(flock_for(0, 1, u32::MAX, 0).unwrap_err(), libc::EINVAL);
        assert_eq!(
            flock_for(u64::MAX, u64::MAX, libc::F_RDLCK as u32, 0).unwrap_err(),
            libc::EOVERFLOW
        );
    }
}
