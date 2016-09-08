/*****************************************************************************
 * Author:   Valient Gough <vgough@pobox.com>
 *
 *****************************************************************************
 * Copyright (c) 2004, Valient Gough
 *
 * This program is free software: you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as published by the
 * Free Software Foundation, either version 3 of the License, or (at your
 * option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Lesser General Public License
 * for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifdef linux
#define _XOPEN_SOURCE 500  // pick up pread , pwrite
#endif
#include "internal/easylogging++.h"
#include <cerrno>
#include <cstring>
#include <fcntl.h>
#include <inttypes.h>
#include <sys/stat.h>
#include <unistd.h>

#include "Error.h"
#include "FileIO.h"
#include "RawFileIO.h"

using namespace std;

namespace encfs {

static Interface RawFileIO_iface("FileIO/Raw", 1, 0, 0);

FileIO *NewRawFileIO(const Interface &iface) {
  (void)iface;
  return new RawFileIO();
}

inline void swap(int &x, int &y) {
  int tmp = x;
  x = y;
  y = tmp;
}

RawFileIO::RawFileIO()
    : knownSize(false), fileSize(0), fd(-1), oldfd(-1), canWrite(false) {}

RawFileIO::RawFileIO(const std::string &fileName)
    : name(fileName),
      knownSize(false),
      fileSize(0),
      fd(-1),
      oldfd(-1),
      canWrite(false) {}

RawFileIO::~RawFileIO() {
  int _fd = -1;
  int _oldfd = -1;

  swap(_fd, fd);
  swap(_oldfd, oldfd);

  if (_oldfd != -1) close(_oldfd);

  if (_fd != -1) close(_fd);
}

Interface RawFileIO::interface() const { return RawFileIO_iface; }

/*
    Workaround for opening a file for write when permissions don't allow.
    Since the kernel has already checked permissions, we can assume it is ok to
    provide access.  So force it by changing permissions temporarily.  Should
    be called with a lock around it so that there won't be a race condition
    with calls to lstat picking up the wrong permissions.

    This works around the problem described in
   https://github.com/vgough/encfs/issues/181
    Without this, "umask 0777 ; echo foo > bar" fails.
*/
static int open_readonly_workaround(const char *path, int flags) {
  int fd = -1;
  struct stat stbuf;
  memset(&stbuf, 0, sizeof(struct stat));
  if (lstat(path, &stbuf) != -1) {
    // make sure user has read/write permission..
    chmod(path, stbuf.st_mode | 0600);
    fd = ::open(path, flags);
    chmod(path, stbuf.st_mode);
  } else {
    RLOG(INFO) << "can't stat file " << path;
  }

  return fd;
}

/*
    We shouldn't have to support all possible open flags, so untaint the flags
    argument by only taking ones we understand and accept.
    -  Since the kernel has already done permission tests before calling us, we
       shouldn't have to worry about access control.
    -  Basically we just need to distinguish between read and write flags
    -  Also keep the O_LARGEFILE flag, in case the underlying filesystem needs
       it..
*/
int RawFileIO::open(int flags) {
  bool requestWrite = ((flags & O_RDWR) || (flags & O_WRONLY));
  VLOG(1) << "open call, requestWrite = " << requestWrite;

  int result = 0;

  // if we have a descriptor and it is writable, or we don't need writable..
  if ((fd >= 0) && (canWrite || !requestWrite)) {
    VLOG(1) << "using existing file descriptor";
    result = fd;  // success
  } else {
    int finalFlags = requestWrite ? O_RDWR : O_RDONLY;

#if defined(O_LARGEFILE)
    if (flags & O_LARGEFILE) finalFlags |= O_LARGEFILE;
#else
#warning O_LARGEFILE not supported
#endif

    int newFd = ::open(name.c_str(), finalFlags);

    VLOG(1) << "open file with flags " << finalFlags << ", result = " << newFd;

    if ((newFd == -1) && (errno == EACCES)) {
      VLOG(1) << "using readonly workaround for open";
      newFd = open_readonly_workaround(name.c_str(), finalFlags);
    }

    if (newFd >= 0) {
      if (oldfd >= 0) {
        RLOG(ERROR) << "leaking FD?: oldfd = " << oldfd << ", fd = " << fd
                    << ", newfd = " << newFd;
      }

      // the old fd might still be in use, so just keep it around for
      // now.
      canWrite = requestWrite;
      oldfd = fd;
      result = fd = newFd;
    } else {
      result = -errno;
      RLOG(DEBUG) << "::open error: " << strerror(errno);
    }
  }

  return result;
}

int RawFileIO::getAttr(struct stat *stbuf) const {
  int res = lstat(name.c_str(), stbuf);
  int eno = errno;

  if (res < 0) {
    RLOG(DEBUG) << "getAttr error on " << name << ": " << strerror(eno);
  }

  return (res < 0) ? -eno : 0;
}

void RawFileIO::setFileName(const char *fileName) { name = fileName; }

const char *RawFileIO::getFileName() const { return name.c_str(); }

off_t RawFileIO::getSize() const {
  if (!knownSize) {
    struct stat stbuf;
    memset(&stbuf, 0, sizeof(struct stat));
    int res = lstat(name.c_str(), &stbuf);

    if (res == 0) {
      const_cast<RawFileIO *>(this)->fileSize = stbuf.st_size;
      const_cast<RawFileIO *>(this)->knownSize = true;
      return fileSize;
    } else {
      RLOG(ERROR) << "getSize on " << name << " failed: " << strerror(errno);
      return -1;
    }
  } else {
    return fileSize;
  }
}

ssize_t RawFileIO::read(const IORequest &req) const {
  rAssert(fd >= 0);

  ssize_t readSize = pread(fd, req.data, req.dataLen, req.offset);

  if (readSize < 0) {
    RLOG(WARNING) << "read failed at offset " << req.offset << " for "
                  << req.dataLen << " bytes: " << strerror(errno);
  }

  return readSize;
}

bool RawFileIO::write(const IORequest &req) {
  rAssert(fd >= 0);
  rAssert(true == canWrite);

  int retrys = 10;
  void *buf = req.data;
  ssize_t bytes = req.dataLen;
  off_t offset = req.offset;

  while (bytes && retrys > 0) {
    ssize_t writeSize = ::pwrite(fd, buf, bytes, offset);

    if (writeSize < 0) {
      knownSize = false;
      RLOG(WARNING) << "write failed at offset " << offset << " for " << bytes
                    << " bytes: " << strerror(errno);
      return false;
    }

    bytes -= writeSize;
    offset += writeSize;
    buf = (void *)((char *)buf + writeSize);
    --retrys;
  }

  if (bytes != 0) {
    RLOG(ERROR) << "Write error: wrote " << req.dataLen - bytes << " bytes of "
                << req.dataLen << ", max retries reached";
    knownSize = false;
    return false;
  } else {
    if (knownSize) {
      off_t last = req.offset + req.dataLen;
      if (last > fileSize) fileSize = last;
    }

    return true;
  }
}

int RawFileIO::truncate(off_t size) {
  int res;

  if (fd >= 0 && canWrite) {
    res = ::ftruncate(fd, size);
#if !defined(__FreeBSD__) && !defined(__APPLE__)
    ::fdatasync(fd);
#endif
  } else
    res = ::truncate(name.c_str(), size);

  if (res < 0) {
    int eno = errno;
    RLOG(WARNING) << "truncate failed for " << name << " (" << fd << ") size "
                  << size << ", error " << strerror(eno);
    res = -eno;
    knownSize = false;
  } else {
    res = 0;
    fileSize = size;
    knownSize = true;
  }

  return res;
}

bool RawFileIO::isWritable() const { return canWrite; }

}  // namespace encfs
