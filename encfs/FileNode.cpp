/*****************************************************************************
 * Author:   Valient Gough <vgough@pobox.com>
 *
 *****************************************************************************
 * Copyright (c) 2003-2004, Valient Gough
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

#include "FileNode.h"

#include <cerrno>
#include <cinttypes>
#include <cstring>
#include <fcntl.h>
#ifdef __linux__
#include <sys/fsuid.h>
#endif
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "CipherFileIO.h"
#include "Error.h"
#include "FileIO.h"
#include "FileUtils.h"
#include "MACFileIO.h"
#include "Mutex.h"
#include "RawFileIO.h"

using namespace std;

namespace encfs {

/*
   TODO: locking at the FileNode level is inefficient, since this precludes
   multiple IO operations from going on concurrently within the same file.

   There is no reason why simultainous reads cannot be satisfied, or why one
   read has to wait for the decoding of the previous read before it can be
   sent to the IO subsystem!
*/

FileNode::FileNode(DirNode *parent_, const FSConfigPtr &cfg,
                   const char *plaintextName_, const char *cipherName_,
                   uint64_t fuseFh) {

  pthread_mutex_init(&mutex, nullptr);

  Lock _lock(mutex);

  this->canary = CANARY_OK;

  this->_pname = plaintextName_;
  this->_cname = cipherName_;
  this->parent = parent_;

  this->fsConfig = cfg;

  this->fuseFh = fuseFh;

  // chain RawFileIO & CipherFileIO
  std::shared_ptr<FileIO> rawIO(new RawFileIO(_cname));
  io = std::shared_ptr<FileIO>(new CipherFileIO(rawIO, fsConfig));

  if ((cfg->config->blockMACBytes != 0) ||
      (cfg->config->blockMACRandBytes != 0)) {
    io = std::shared_ptr<FileIO>(new MACFileIO(io, fsConfig));
  }
}

FileNode::~FileNode() {
  // FileNode mutex should be locked before the destructor is called
  // pthread_mutex_lock( &mutex );

  canary = CANARY_DESTROYED;
  _pname.assign(_pname.length(), '\0');
  _cname.assign(_cname.length(), '\0');
  io.reset();

  pthread_mutex_destroy(&mutex);
}

const char *FileNode::cipherName() const { return _cname.c_str(); }

const char *FileNode::plaintextName() const { return _pname.c_str(); }

string FileNode::plaintextParent() const { return parentDirectory(_pname); }

static bool setIV(const std::shared_ptr<FileIO> &io, uint64_t iv) {
  struct stat stbuf;
  if ((io->getAttr(&stbuf) < 0) || S_ISREG(stbuf.st_mode)) {
    return io->setIV(iv);
  }
  return true;
}

bool FileNode::setName(const char *plaintextName_, const char *cipherName_,
                       uint64_t iv, bool setIVFirst) {
  // Lock _lock( mutex );
  if (cipherName_ != nullptr) {
    VLOG(1) << "calling setIV on " << cipherName_;
  }

  if (setIVFirst) {
    if (fsConfig->config->externalIVChaining && !setIV(io, iv)) {
      return false;
    }

    // now change the name..
    if (plaintextName_ != nullptr) {
      this->_pname = plaintextName_;
    }
    if (cipherName_ != nullptr) {
      this->_cname = cipherName_;
      io->setFileName(cipherName_);
    }
  } else {
    std::string oldPName = _pname;
    std::string oldCName = _cname;

    if (plaintextName_ != nullptr) {
      this->_pname = plaintextName_;
    }
    if (cipherName_ != nullptr) {
      this->_cname = cipherName_;
      io->setFileName(cipherName_);
    }

    if (fsConfig->config->externalIVChaining && !setIV(io, iv)) {
      _pname = oldPName;
      _cname = oldCName;
      return false;
    }
  }

  return true;
}

int FileNode::mknod(mode_t mode, dev_t rdev, uid_t uid, gid_t gid) {
  Lock _lock(mutex);

  int res;
  int olduid = -1;
  int oldgid = -1;
  if (gid != 0) {
    oldgid = setfsgid(gid);
    if (oldgid == -1) {
      int eno = errno;
      RLOG(DEBUG) << "setfsgid error: " << strerror(eno);
      return -EPERM;
    }
  }
  if (uid != 0) {
    olduid = setfsuid(uid);
    if (olduid == -1) {
      int eno = errno;
      RLOG(DEBUG) << "setfsuid error: " << strerror(eno);
      return -EPERM;
    }
  }

  /*
   * cf. xmp_mknod() in fusexmp.c
   * The regular file stuff could be stripped off if there
   * were a create method (advised to have)
   */
  if (S_ISREG(mode)) {
    res = ::open(_cname.c_str(), O_CREAT | O_EXCL | O_WRONLY, mode);
    if (res >= 0) {
      res = ::close(res);
    }
  } else if (S_ISFIFO(mode)) {
    res = ::mkfifo(_cname.c_str(), mode);
  } else {
    res = ::mknod(_cname.c_str(), mode, rdev);
  }

  if (res == -1) {
    int eno = errno;
    VLOG(1) << "mknod error: " << strerror(eno);
    res = -eno;
  }

  if (olduid >= 0) {
    if(setfsuid(olduid) == -1) {
      int eno = errno;
      RLOG(DEBUG) << "setfsuid back error: " << strerror(eno);
      // does not return error here as initial setfsuid worked
    }
  }
  if (oldgid >= 0) {
    if(setfsgid(oldgid) == -1) {
      int eno = errno;
      RLOG(DEBUG) << "setfsgid back error: " << strerror(eno);
      // does not return error here as initial setfsgid worked
    }
  }

  return res;
}

int FileNode::open(int flags) const {
  Lock _lock(mutex);

  int res = io->open(flags);
  return res;
}

int FileNode::getAttr(struct stat *stbuf) const {
  Lock _lock(mutex);

  int res = io->getAttr(stbuf);
  return res;
}

off_t FileNode::getSize() const {
  Lock _lock(mutex);

  off_t res = io->getSize();
  return res;
}

ssize_t FileNode::read(off_t offset, unsigned char *data, size_t size) const {
  IORequest req;
  req.offset = offset;
  req.dataLen = size;
  req.data = data;

  Lock _lock(mutex);

  return io->read(req);
}

ssize_t FileNode::write(off_t offset, unsigned char *data, size_t size) {
  VLOG(1) << "FileNode::write offset " << offset << ", data size " << size;

  IORequest req;
  req.offset = offset;
  req.dataLen = size;
  req.data = data;

  Lock _lock(mutex);

  ssize_t res = io->write(req);
  // Of course due to encryption we genrally write more than requested
  if (res < 0) {
    return res;
  }
  return size;
}

int FileNode::truncate(off_t size) {
  Lock _lock(mutex);

  return io->truncate(size);
}

int FileNode::sync(bool datasync) {
  Lock _lock(mutex);

  int fh = io->open(O_RDONLY);
  if (fh >= 0) {
    int res = -EIO;
#if defined(HAVE_FDATASYNC)
    if (datasync) {
      res = fdatasync(fh);
    } else {
      res = fsync(fh);
    }
#else
    (void)datasync;
    res = fsync(fh);
#endif

    if (res == -1) {
      res = -errno;
    }

    return res;
  }
  return fh;
}

}  // namespace encfs
