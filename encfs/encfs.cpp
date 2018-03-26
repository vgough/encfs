/*****************************************************************************
 * Author:   Valient Gough <vgough@pobox.com>
 *
 *****************************************************************************
 * Copyright (c) 2003-2007, Valient Gough
 *
 * This program is free software; you can distribute it and/or modify it under
 * the terms of the GNU General Public License (GPL), as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 */

#include "encfs.h"

#include <cerrno>
#include <cinttypes>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <ctime>
#include <fcntl.h>
#include <limits>
#include <memory>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <sys/time.h>
#include <unistd.h>
#include <utime.h>
#ifdef __linux__
#include <sys/fsuid.h>
#endif

#if defined(HAVE_SYS_XATTR_H)
#include <sys/xattr.h>
#elif defined(HAVE_ATTR_XATTR_H)
#include <attr/xattr.h>
#endif

#include "easylogging++.h"
#include <functional>
#include <string>
#include <vector>

#include "Context.h"
#include "DirNode.h"
#include "Error.h"
#include "FileNode.h"
#include "FileUtils.h"
#include "fuse.h"

#ifndef MIN
#define MIN(a, b) (((a) < (b)) ? (a) : (b))
#endif

#define ESUCCESS 0

using namespace std;
using namespace std::placeholders;

namespace encfs {

#define GET_FN(ctx, finfo) (ctx)->getNode((void *)(uintptr_t)(finfo)->fh)

static EncFS_Context *context() {
  return (EncFS_Context *)fuse_get_context()->private_data;
}

/**
 * Helper function - determine if the filesystem is read-only
 * Optionally takes a pointer to the EncFS_Context, will get it from FUSE
 * if the argument is NULL.
 */
static bool isReadOnly(EncFS_Context *ctx) { return ctx->opts->readOnly; }

// helper function -- apply a functor to a cipher path, given the plain path
static int withCipherPath(
    const char *opName, const char *path,
    const function<int(EncFS_Context *, const string &)> &op,
    bool passReturnCode = false) {
  EncFS_Context *ctx = context();

  int res = -EIO;
  std::shared_ptr<DirNode> FSRoot = ctx->getRoot(&res);
  if (!FSRoot) {
    return res;
  }

  try {
    string cyName = FSRoot->cipherPath(path);
    VLOG(1) << "op: " << opName << " : " << cyName;

    res = op(ctx, cyName);

    if (res == -1) {
      int eno = errno;
      VLOG(1) << "op: " << opName << " error: " << strerror(eno);
      res = -eno;
    } else if (!passReturnCode) {
      res = ESUCCESS;
    }
  } catch (encfs::Error &err) {
    RLOG(ERROR) << "withCipherPath: error caught in " << opName << ": "
                << err.what();
  }
  return res;
}

static void checkCanary(const std::shared_ptr<FileNode> &fnode) {
  if (fnode->canary == CANARY_OK) {
    return;
  }
  if (fnode->canary == CANARY_RELEASED) {
    // "fnode" may have been released after it was retrieved by
    // lookupFuseFh. This is not an error. std::shared_ptr will release
    // the memory only when all operations on the FileNode have been
    // completed.
    return;
  }
  if (fnode->canary == CANARY_DESTROYED) {
    RLOG(ERROR)
        << "canary=CANARY_DESTROYED. FileNode accessed after it was destroyed.";
  } else {
    RLOG(ERROR) << "canary=0x" << std::hex << fnode->canary
                << ". Memory corruption?";
  }
  throw Error("dead canary");
}

// helper function -- apply a functor to a node
static int withFileNode(const char *opName, const char *path,
                        struct fuse_file_info *fi,
                        const function<int(FileNode *)> &op) {
  EncFS_Context *ctx = context();

  int res = -EIO;
  bool skipUsageCount = false;
  if (strlen(path) == 1) {
    skipUsageCount = true;
  }
  std::shared_ptr<DirNode> FSRoot = ctx->getRoot(&res, skipUsageCount);
  if (!FSRoot) {
    return res;
  }

  try {

    auto do_op = [&FSRoot, opName, &op](std::shared_ptr<FileNode> fnode) {
      rAssert(fnode != nullptr);
      checkCanary(fnode);
      VLOG(1) << "op: " << opName << " : " << fnode->cipherName();

      // check that we're not recursing into the mount point itself
      if (FSRoot->touchesMountpoint(fnode->cipherName())) {
        VLOG(1) << "op: " << opName << " error: Tried to touch mountpoint: '"
                << fnode->cipherName() << "'";
        return -EIO;
      }
      return op(fnode.get());
    };

    if (fi != nullptr && fi->fh != 0) {
      auto node = ctx->lookupFuseFh(fi->fh);
      if (node == nullptr) {
#ifdef __CYGWIN__
        if (strcmp(opName, "flush") == 0) {
          RLOG(WARNING) << "Filenode to flush not found, file has certainly be renamed: "
                        << path;
          return 0;
        }
#endif
        auto msg = "fh=" + std::to_string(fi->fh) + " not found in fuseFhMap";
        throw Error(msg.c_str());
      }
      res = do_op(node);
    } else {
      res = do_op(FSRoot->lookupNode(path, opName));
    }

    if (res < 0) {
      RLOG(DEBUG) << "op: " << opName << " error: " << strerror(-res);
    }
  } catch (encfs::Error &err) {
    RLOG(ERROR) << "withFileNode: error caught in " << opName << ": "
                << err.what();
  }
  return res;
}

/*
    The log messages below always print encrypted filenames, not
    plaintext.  This avoids possibly leaking information to log files.

    The purpose of this layer of code is to take the FUSE request and dispatch
    to the internal interfaces.  Any marshaling of arguments and return types
    can be done here.
*/

int _do_getattr(FileNode *fnode, struct stat *stbuf) {
  int res = fnode->getAttr(stbuf);
  if (res == ESUCCESS && S_ISLNK(stbuf->st_mode)) {
    EncFS_Context *ctx = context();
    std::shared_ptr<DirNode> FSRoot = ctx->getRoot(&res);
    if (FSRoot) {
      // determine plaintext link size..  Easiest to read and decrypt..
      std::vector<char> buf(stbuf->st_size + 1, '\0');

      res = ::readlink(fnode->cipherName(), buf.data(), stbuf->st_size);
      if (res >= 0) {
        // other functions expect c-strings to be null-terminated, which
        // readlink doesn't provide
        buf[res] = '\0';

        stbuf->st_size = FSRoot->plainPath(buf.data()).length();

        res = ESUCCESS;
      } else {
        res = -errno;
      }
    }
  }

  return res;
}

int encfs_getattr(const char *path, struct stat *stbuf) {
  return withFileNode("getattr", path, nullptr, bind(_do_getattr, _1, stbuf));
}

int encfs_fgetattr(const char *path, struct stat *stbuf,
                   struct fuse_file_info *fi) {
  return withFileNode("fgetattr", path, fi, bind(_do_getattr, _1, stbuf));
}

int encfs_readdir(const char *path, void *buf, fuse_fill_dir_t filler,
                  off_t offset, struct fuse_file_info *finfo) {
  EncFS_Context *ctx = context();

  //unused parameters
  (void)offset;
  (void)finfo;

  int res = ESUCCESS;
  std::shared_ptr<DirNode> FSRoot = ctx->getRoot(&res);
  if (!FSRoot) {
    return res;
  }

  try {

    DirTraverse dt = FSRoot->openDir(path);

    VLOG(1) << "readdir on " << FSRoot->cipherPath(path);

    if (dt.valid()) {
      int fileType = 0;
      ino_t inode = 0;

      std::string name = dt.nextPlaintextName(&fileType, &inode);
      while (!name.empty()) {
        struct stat st;
        st.st_ino = inode;
        st.st_mode = fileType << 12;

// TODO: add offset support.
#if defined(fuse_fill_dir_flags)
        if (filler(buf, name.c_str(), &st, 0, 0)) break;
#else
        if (filler(buf, name.c_str(), &st, 0) != 0) {
          break;
        }
#endif

        name = dt.nextPlaintextName(&fileType, &inode);
      }
    } else {
      VLOG(1) << "readdir request invalid, path: '" << path << "'";
    }

    return res;
  } catch (encfs::Error &err) {
    RLOG(ERROR) << "Error caught in readdir";
    return -EIO;
  }
}

int encfs_mknod(const char *path, mode_t mode, dev_t rdev) {
  EncFS_Context *ctx = context();

  if (isReadOnly(ctx)) {
    return -EROFS;
  }

  int res = -EIO;
  std::shared_ptr<DirNode> FSRoot = ctx->getRoot(&res);
  if (!FSRoot) {
    return res;
  }

  try {
    std::shared_ptr<FileNode> fnode = FSRoot->lookupNode(path, "mknod");

    VLOG(1) << "mknod on " << fnode->cipherName() << ", mode " << mode
            << ", dev " << rdev;

    uid_t uid = 0;
    gid_t gid = 0;
    if (ctx->publicFilesystem) {
      fuse_context *context = fuse_get_context();
      uid = context->uid;
      gid = context->gid;
    }
    res = fnode->mknod(mode, rdev, uid, gid);
    // Is this error due to access problems?
    if (ctx->publicFilesystem && -res == EACCES) {
      // try again using the parent dir's group
      string parent = fnode->plaintextParent();
      VLOG(1) << "trying public filesystem workaround for " << parent;
      std::shared_ptr<FileNode> dnode =
          FSRoot->lookupNode(parent.c_str(), "mknod");

      struct stat st;
      if (dnode->getAttr(&st) == 0) {
        res = fnode->mknod(mode, rdev, uid, st.st_gid);
      }
    }
  } catch (encfs::Error &err) {
    RLOG(ERROR) << "error caught in mknod: " << err.what();
  }
  return res;
}

int encfs_mkdir(const char *path, mode_t mode) {
  fuse_context *fctx = fuse_get_context();
  EncFS_Context *ctx = context();

  if (isReadOnly(ctx)) {
    return -EROFS;
  }

  int res = -EIO;
  std::shared_ptr<DirNode> FSRoot = ctx->getRoot(&res);
  if (!FSRoot) {
    return res;
  }

  try {
    uid_t uid = 0;
    gid_t gid = 0;
    if (ctx->publicFilesystem) {
      uid = fctx->uid;
      gid = fctx->gid;
    }
    res = FSRoot->mkdir(path, mode, uid, gid);
    // Is this error due to access problems?
    if (ctx->publicFilesystem && -res == EACCES) {
      // try again using the parent dir's group
      string parent = parentDirectory(path);
      std::shared_ptr<FileNode> dnode =
          FSRoot->lookupNode(parent.c_str(), "mkdir");

      struct stat st;
      if (dnode->getAttr(&st) == 0) {
        res = FSRoot->mkdir(path, mode, uid, st.st_gid);
      }
    }
  } catch (encfs::Error &err) {
    RLOG(ERROR) << "error caught in mkdir: " << err.what();
  }
  return res;
}

int encfs_unlink(const char *path) {
  EncFS_Context *ctx = context();
  if (isReadOnly(ctx)) {
    return -EROFS;
  }

  int res = -EIO;
  std::shared_ptr<DirNode> FSRoot = ctx->getRoot(&res);
  if (!FSRoot) {
    return res;
  }

  try {
    // let DirNode handle it atomically so that it can handle race
    // conditions
    res = FSRoot->unlink(path);
  } catch (encfs::Error &err) {
    RLOG(ERROR) << "error caught in unlink: " << err.what();
  }
  return res;
}

int _do_rmdir(EncFS_Context *, const string &cipherPath) {
  return rmdir(cipherPath.c_str());
}

int encfs_rmdir(const char *path) {
  EncFS_Context *ctx = context();
  if (isReadOnly(ctx)) {
    return -EROFS;
  }
  return withCipherPath("rmdir", path, bind(_do_rmdir, _1, _2));
}

int _do_readlink(EncFS_Context *ctx, const string &cyName, char *buf,
                 size_t size) {
  int res = ESUCCESS;
  std::shared_ptr<DirNode> FSRoot = ctx->getRoot(&res);
  if (!FSRoot) {
    return res;
  }

  res = ::readlink(cyName.c_str(), buf, size - 1);

  if (res == -1) {
    return -errno;
  }

  buf[res] = '\0';  // ensure null termination
  string decodedName;
  decodedName = FSRoot->plainPath(buf);

  if (!decodedName.empty()) {
    strncpy(buf, decodedName.c_str(), size - 1);
    buf[size - 1] = '\0';

    return ESUCCESS;
  }
  RLOG(WARNING) << "Error decoding link";
  return -1;
}

int encfs_readlink(const char *path, char *buf, size_t size) {
  return withCipherPath("readlink", path,
                        bind(_do_readlink, _1, _2, buf, size));
}

/**
 * Create a symbolic link pointing to "to" named "from"
 */
int encfs_symlink(const char *to, const char *from) {
  EncFS_Context *ctx = context();

  if (isReadOnly(ctx)) {
    return -EROFS;
  }

  int res = -EIO;
  std::shared_ptr<DirNode> FSRoot = ctx->getRoot(&res);
  if (!FSRoot) {
    return res;
  }

  try {
    string fromCName = FSRoot->cipherPath(from);
    // allow fully qualified names in symbolic links.
    string toCName = FSRoot->relativeCipherPath(to);

    VLOG(1) << "symlink " << fromCName << " -> " << toCName;

    // use setfsuid / setfsgid so that the new link will be owned by the
    // uid/gid provided by the fuse_context.
    int olduid = -1;
    int oldgid = -1;
    if (ctx->publicFilesystem) {
      fuse_context *context = fuse_get_context();
      oldgid = setfsgid(context->gid);
      if (oldgid == -1) {
        int eno = errno;
        RLOG(DEBUG) << "setfsgid error: " << strerror(eno);
        return -EPERM;
      }
      olduid = setfsuid(context->uid);
      if (olduid == -1) {
        int eno = errno;
        RLOG(DEBUG) << "setfsuid error: " << strerror(eno);
        return -EPERM;
      }
    }
    res = ::symlink(toCName.c_str(), fromCName.c_str());
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

    if (res == -1) {
      res = -errno;
    } else {
      res = ESUCCESS;
    }
  } catch (encfs::Error &err) {
    RLOG(ERROR) << "error caught in symlink: " << err.what();
  }
  return res;
}

int encfs_link(const char *to, const char *from) {
  EncFS_Context *ctx = context();

  if (isReadOnly(ctx)) {
    return -EROFS;
  }

  int res = -EIO;
  std::shared_ptr<DirNode> FSRoot = ctx->getRoot(&res);
  if (!FSRoot) {
    return res;
  }

  try {
    res = FSRoot->link(to, from);
  } catch (encfs::Error &err) {
    RLOG(ERROR) << "error caught in link: " << err.what();
  }
  return res;
}

int encfs_rename(const char *from, const char *to) {
  EncFS_Context *ctx = context();

  if (isReadOnly(ctx)) {
    return -EROFS;
  }

  int res = -EIO;
  std::shared_ptr<DirNode> FSRoot = ctx->getRoot(&res);
  if (!FSRoot) {
    return res;
  }

  try {
    res = FSRoot->rename(from, to);
  } catch (encfs::Error &err) {
    RLOG(ERROR) << "error caught in rename: " << err.what();
  }
  return res;
}

int _do_chmod(EncFS_Context *, const string &cipherPath, mode_t mode) {
  return chmod(cipherPath.c_str(), mode);
}

int encfs_chmod(const char *path, mode_t mode) {
  EncFS_Context *ctx = context();
  if (isReadOnly(ctx)) {
    return -EROFS;
  }
  return withCipherPath("chmod", path, bind(_do_chmod, _1, _2, mode));
}

int _do_chown(EncFS_Context *, const string &cyName, uid_t u, gid_t g) {
  int res = lchown(cyName.c_str(), u, g);
  return (res == -1) ? -errno : ESUCCESS;
}

int encfs_chown(const char *path, uid_t uid, gid_t gid) {
  EncFS_Context *ctx = context();
  if (isReadOnly(ctx)) {
    return -EROFS;
  }
  return withCipherPath("chown", path, bind(_do_chown, _1, _2, uid, gid));
}

int _do_truncate(FileNode *fnode, off_t size) { return fnode->truncate(size); }

int encfs_truncate(const char *path, off_t size) {
  EncFS_Context *ctx = context();
  if (isReadOnly(ctx)) {
    return -EROFS;
  }
  return withFileNode("truncate", path, nullptr, bind(_do_truncate, _1, size));
}

int encfs_ftruncate(const char *path, off_t size, struct fuse_file_info *fi) {
  EncFS_Context *ctx = context();
  if (isReadOnly(ctx)) {
    return -EROFS;
  }
  return withFileNode("ftruncate", path, fi, bind(_do_truncate, _1, size));
}

int _do_utime(EncFS_Context *, const string &cyName, struct utimbuf *buf) {
  int res = utime(cyName.c_str(), buf);
  return (res == -1) ? -errno : ESUCCESS;
}

int encfs_utime(const char *path, struct utimbuf *buf) {
  EncFS_Context *ctx = context();
  if (isReadOnly(ctx)) {
    return -EROFS;
  }
  return withCipherPath("utime", path, bind(_do_utime, _1, _2, buf));
}

int _do_utimens(EncFS_Context *, const string &cyName,
                const struct timespec ts[2]) {
#ifdef HAVE_UTIMENSAT
  int res = utimensat(AT_FDCWD, cyName.c_str(), ts, AT_SYMLINK_NOFOLLOW);
#else
  struct timeval tv[2];
  tv[0].tv_sec = ts[0].tv_sec;
  tv[0].tv_usec = ts[0].tv_nsec / 1000;
  tv[1].tv_sec = ts[1].tv_sec;
  tv[1].tv_usec = ts[1].tv_nsec / 1000;

  int res = lutimes(cyName.c_str(), tv);
#endif
  return (res == -1) ? -errno : ESUCCESS;
}

int encfs_utimens(const char *path, const struct timespec ts[2]) {
  EncFS_Context *ctx = context();
  if (isReadOnly(ctx)) {
    return -EROFS;
  }
  return withCipherPath("utimens", path, bind(_do_utimens, _1, _2, ts));
}

int encfs_open(const char *path, struct fuse_file_info *file) {
  EncFS_Context *ctx = context();

  if (isReadOnly(ctx) &&
      (((file->flags & O_WRONLY) != 0) || ((file->flags & O_RDWR) != 0))) {
    return -EROFS;
  }

  int res = -EIO;
  std::shared_ptr<DirNode> FSRoot = ctx->getRoot(&res);
  if (!FSRoot) {
    return res;
  }

  try {
    std::shared_ptr<FileNode> fnode =
        FSRoot->openNode(path, "open", file->flags, &res);

    if (fnode) {
      VLOG(1) << "encfs_open for " << fnode->cipherName() << ", flags "
              << file->flags;

      if (res >= 0) {
        ctx->putNode(path, fnode);
        file->fh = fnode->fuseFh;
        res = ESUCCESS;
      }
    }
  } catch (encfs::Error &err) {
    RLOG(ERROR) << "error caught in open: " << err.what();
  }

  return res;
}

int encfs_create(const char *path, mode_t mode, struct fuse_file_info *file) {
  int res = encfs_mknod(path, mode, 0);
  if (res != 0) {
    return res;
  }

  return encfs_open(path, file);
}

int _do_flush(FileNode *fnode) {
  /* Flush can be called multiple times for an open file, so it doesn't
     close the file.  However it is important to call close() for some
     underlying filesystems (like NFS).
  */
  int res = fnode->open(O_RDONLY);
  if (res >= 0) {
    int fh = res;
    int nfh = dup(fh);
    if (nfh == -1) {
      return -errno;
    }
    res = close(nfh);
    if (res == -1) {
      return -errno;
    }
  }

  return res;
}

// Called on each close() of a file descriptor
int encfs_flush(const char *path, struct fuse_file_info *fi) {
  return withFileNode("flush", path, fi, bind(_do_flush, _1));
}

/*
Note: This is advisory -- it might benefit us to keep file nodes around for a
bit after they are released just in case they are reopened soon.  But that
requires a cache layer.
 */
int encfs_release(const char *path, struct fuse_file_info *finfo) {
  EncFS_Context *ctx = context();

  try {
    auto fnode = ctx->lookupFuseFh(finfo->fh);
    ctx->eraseNode(path, fnode);
    return ESUCCESS;
  } catch (encfs::Error &err) {
    RLOG(ERROR) << "error caught in release: " << err.what();
    return -EIO;
  }
}

ssize_t _do_read(FileNode *fnode, unsigned char *ptr, size_t size, off_t off) {
  return fnode->read(off, ptr, size);
}

int encfs_read(const char *path, char *buf, size_t size, off_t offset,
               struct fuse_file_info *file) {
  // Unfortunately we have to convert from ssize_t (pread) to int (fuse), so
  // let's check this will be OK
  if (size > std::numeric_limits<int>::max()) {
    size = std::numeric_limits<int>::max();
  }
  return withFileNode("read", path, file,
                      bind(_do_read, _1, (unsigned char *)buf, size, offset));
}

int _do_fsync(FileNode *fnode, int dataSync) {
  return fnode->sync(dataSync != 0);
}

int encfs_fsync(const char *path, int dataSync, struct fuse_file_info *file) {
  EncFS_Context *ctx = context();
  if (isReadOnly(ctx)) {
    return -EROFS;
  }
  return withFileNode("fsync", path, file, bind(_do_fsync, _1, dataSync));
}

ssize_t _do_write(FileNode *fnode, unsigned char *ptr, size_t size,
                  off_t offset) {
  return fnode->write(offset, ptr, size);
}

int encfs_write(const char *path, const char *buf, size_t size, off_t offset,
                struct fuse_file_info *file) {
  // Unfortunately we have to convert from ssize_t (pwrite) to int (fuse), so
  // let's check this will be OK
  if (size > std::numeric_limits<int>::max()) {
    size = std::numeric_limits<int>::max();
  }
  EncFS_Context *ctx = context();
  if (isReadOnly(ctx)) {
    return -EROFS;
  }
  return withFileNode("write", path, file,
                      bind(_do_write, _1, (unsigned char *)buf, size, offset));
}

// statfs works even if encfs is detached..
int encfs_statfs(const char *path, struct statvfs *st) {
  EncFS_Context *ctx = context();

  int res = -EIO;
  try {
    (void)path;  // path should always be '/' for now..
    rAssert(st != nullptr);
    string cyName = ctx->rootCipherDir;

    VLOG(1) << "doing statfs of " << cyName;
    res = statvfs(cyName.c_str(), st);
    if (res == 0) {
      // adjust maximum name length..
      st->f_namemax = 6 * (st->f_namemax - 2) / 8;  // approx..
    }
    if (res == -1) {
      res = -errno;
    }
  } catch (encfs::Error &err) {
    RLOG(ERROR) << "error caught in statfs: " << err.what();
  }
  return res;
}

#ifdef HAVE_XATTR

#ifdef XATTR_ADD_OPT
int _do_setxattr(EncFS_Context *, const string &cyName, const char *name,
                 const char *value, size_t size, uint32_t pos) {
  int options = XATTR_NOFOLLOW;
  return ::setxattr(cyName.c_str(), name, value, size, pos, options);
}
int encfs_setxattr(const char *path, const char *name, const char *value,
                   size_t size, int flags, uint32_t position) {
  EncFS_Context *ctx = context();
  if (isReadOnly(ctx)) {
    return -EROFS;
  }
  (void)flags;
  return withCipherPath("setxattr", path, bind(_do_setxattr, _1, _2, name,
                                               value, size, position));
}
#else
int _do_setxattr(EncFS_Context *, const string &cyName, const char *name,
                 const char *value, size_t size, int flags) {
  return ::lsetxattr(cyName.c_str(), name, value, size, flags);
}
int encfs_setxattr(const char *path, const char *name, const char *value,
                   size_t size, int flags) {
  EncFS_Context *ctx = context();
  if (isReadOnly(ctx)) {
    return -EROFS;
  }
  return withCipherPath("setxattr", path,
                        bind(_do_setxattr, _1, _2, name, value, size, flags));
}
#endif

#ifdef XATTR_ADD_OPT
int _do_getxattr(EncFS_Context *, const string &cyName, const char *name,
                 void *value, size_t size, uint32_t pos) {
  int options = XATTR_NOFOLLOW;
  return ::getxattr(cyName.c_str(), name, value, size, pos, options);
}
int encfs_getxattr(const char *path, const char *name, char *value, size_t size,
                   uint32_t position) {
  return withCipherPath(
      "getxattr", path,
      bind(_do_getxattr, _1, _2, name, (void *)value, size, position), true);
}
#else
int _do_getxattr(EncFS_Context *, const string &cyName, const char *name,
                 void *value, size_t size) {
  return ::lgetxattr(cyName.c_str(), name, value, size);
}
int encfs_getxattr(const char *path, const char *name, char *value,
                   size_t size) {
  return withCipherPath("getxattr", path,
                        bind(_do_getxattr, _1, _2, name, (void *)value, size),
                        true);
}
#endif

int _do_listxattr(EncFS_Context *, const string &cyName, char *list,
                  size_t size) {
#ifdef XATTR_ADD_OPT
  int options = XATTR_NOFOLLOW;
  int res = ::listxattr(cyName.c_str(), list, size, options);
#else
  int res = ::llistxattr(cyName.c_str(), list, size);
#endif
  return (res == -1) ? -errno : res;
}

int encfs_listxattr(const char *path, char *list, size_t size) {
  return withCipherPath("listxattr", path,
                        bind(_do_listxattr, _1, _2, list, size), true);
}

int _do_removexattr(EncFS_Context *, const string &cyName, const char *name) {
#ifdef XATTR_ADD_OPT
  int options = XATTR_NOFOLLOW;
  int res = ::removexattr(cyName.c_str(), name, options);
#else
  int res = ::lremovexattr(cyName.c_str(), name);
#endif
  return (res == -1) ? -errno : res;
}

int encfs_removexattr(const char *path, const char *name) {
  EncFS_Context *ctx = context();
  if (isReadOnly(ctx)) {
    return -EROFS;
  }

  return withCipherPath("removexattr", path,
                        bind(_do_removexattr, _1, _2, name));
}

#endif  // HAVE_XATTR

}  // namespace encfs
