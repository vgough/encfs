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
#include <cstddef>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fcntl.h>
#include <inttypes.h>
#include <memory>
#include <stdint.h>
#include <string>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>
#include <utility>
#include <utime.h>
#include <vector>

#ifdef linux
#include <sys/fsuid.h>
#endif

#if defined(HAVE_SYS_XATTR_H)
#include <sys/xattr.h>
#elif defined(HAVE_ATTR_XATTR_H)
#include <attr/xattr.h>
#endif

#include <rlog/Error.h>
#include <rlog/rlog.h>

#include "Context.h"
#include "DirNode.h"
#include "FileNode.h"
#include "FileUtils.h"
#include "fuse.h"

namespace rel {
class Lock;
}  // namespace rel
namespace rlog {
class RLogChannel;
}  // namespace rlog

#define ESUCCESS 0

using namespace std;
using namespace std::placeholders;
using namespace rlog;
using rel::Lock;

#define GET_FN(ctx, finfo) ctx->getNode((void *)(uintptr_t)finfo->fh)

// XAttr prefix replacement.
// Replaces "com.apple." with "encfs_apl." when storing xattrs.
// TODO: future versions of encfs should encrypt xattrs, making this
// unnecessary.
static const char _attr_apple[] = "com.apple.";
static const char _attr_apple_internal[] = "encfs_apl.";

static RLogChannel *Info = DEF_CHANNEL("info", Log_Info);

static EncFS_Context *context() {
  return (EncFS_Context *)fuse_get_context()->private_data;
}

/**
 * Helper function - determine if the filesystem is read-only
 * Optionally takes a pointer to the EncFS_Context, will get it from FUSE
 * if the argument is NULL.
 */
static bool isReadOnly(EncFS_Context *ctx) {
  if (ctx == NULL) ctx = (EncFS_Context *)fuse_get_context()->private_data;

  return ctx->opts->readOnly;
}

// helper function -- apply a functor to a cipher path, given the plain path
static int withCipherPath(const char *opName, const char *path,
                          function<int(EncFS_Context *, const string &)> op,
                          bool passReturnCode = false) {
  EncFS_Context *ctx = context();

  int res = -EIO;
  shared_ptr<DirNode> FSRoot = ctx->getRoot(&res);
  if (!FSRoot) return res;

  try {
    string cyName = FSRoot->cipherPath(path);
    rLog(Info, "%s %s", opName, cyName.c_str());

    res = op(ctx, cyName);

    if (res == -1) {
      int eno = errno;
      rInfo("%s error: %s", opName, strerror(eno));
      res = -eno;
    } else if (!passReturnCode)
      res = ESUCCESS;
  } catch (rlog::Error &err) {
    rError("withCipherPath: error caught in %s: %s", opName, err.message());
    err.log(_RLWarningChannel);
  }
  return res;
}

// helper function -- apply a functor to a node
static int withFileNode(const char *opName, const char *path,
                        struct fuse_file_info *fi,
                        function<int(FileNode *)> op) {
  EncFS_Context *ctx = context();

  int res = -EIO;
  shared_ptr<DirNode> FSRoot = ctx->getRoot(&res);
  if (!FSRoot) return res;

  try {
    shared_ptr<FileNode> fnode;

    if (fi != NULL)
      fnode = GET_FN(ctx, fi);
    else
      fnode = FSRoot->lookupNode(path, opName);

    rAssert(fnode.get() != NULL);
    rLog(Info, "%s %s", opName, fnode->cipherName());

    // check that we're not recursing into the mount point itself
    if (FSRoot->touchesMountpoint(fnode->cipherName())) {
      rInfo("%s error: Tried to touch mountpoint: '%s'",
            opName, fnode->cipherName());
      return res; // still -EIO
    }

    res = op(fnode.get());

    if (res < 0) rInfo("%s error: %s", opName, strerror(-res));
  } catch (rlog::Error &err) {
    rError("withFileNode: error caught in %s: %s", opName, err.message());
    err.log(_RLWarningChannel);
  }
  return res;
}

/*
    The rLog messages below always prints out encrypted filenames, not
    plaintext.  The reason is so that it isn't possible to leak information
    about the encrypted data through rlog interfaces.

    The purpose of this layer of code is to take the FUSE request and dispatch
    to the internal interfaces.  Any marshaling of arguments and return types
    can be done here.
*/

int _do_getattr(FileNode *fnode, struct stat *stbuf) {
  int res = fnode->getAttr(stbuf);
  if (res == ESUCCESS && S_ISLNK(stbuf->st_mode)) {
    EncFS_Context *ctx = context();
    shared_ptr<DirNode> FSRoot = ctx->getRoot(&res);
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
      } else
        res = -errno;
    }
  }

  return res;
}

int encfs_getattr(const char *path, struct stat *stbuf) {
  return withFileNode("getattr", path, NULL, bind(_do_getattr, _1, stbuf));
}

int encfs_fgetattr(const char *path, struct stat *stbuf,
                   struct fuse_file_info *fi) {
  return withFileNode("fgetattr", path, fi, bind(_do_getattr, _1, stbuf));
}

int encfs_getdir(const char *path, fuse_dirh_t h, fuse_dirfil_t filler) {
  EncFS_Context *ctx = context();

  int res = ESUCCESS;
  shared_ptr<DirNode> FSRoot = ctx->getRoot(&res);
  if (!FSRoot) return res;

  try {

    DirTraverse dt = FSRoot->openDir(path);

    rLog(Info, "getdir on %s", FSRoot->cipherPath(path).c_str());

    if (dt.valid()) {
      int fileType = 0;
      ino_t inode = 0;

      std::string name = dt.nextPlaintextName(&fileType, &inode);
      while (!name.empty()) {
        res = filler(h, name.c_str(), fileType, inode);

        if (res != ESUCCESS) break;

        name = dt.nextPlaintextName(&fileType, &inode);
      }
    } else {
      rInfo("getdir request invalid, path: '%s'", path);
    }

    return res;
  } catch (rlog::Error &err) {
    rError("Error caught in getdir");
    err.log(_RLWarningChannel);
    return -EIO;
  }
}

int encfs_mknod(const char *path, mode_t mode, dev_t rdev) {
  EncFS_Context *ctx = context();

  if (isReadOnly(ctx)) return -EROFS;

  int res = -EIO;
  shared_ptr<DirNode> FSRoot = ctx->getRoot(&res);
  if (!FSRoot) return res;

  try {
    shared_ptr<FileNode> fnode = FSRoot->lookupNode(path, "mknod");

    rLog(Info, "mknod on %s, mode %i, dev %" PRIi64, fnode->cipherName(), mode,
         (int64_t)rdev);

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
      rInfo("trying public filesystem workaround for %s", parent.c_str());
      shared_ptr<FileNode> dnode = FSRoot->lookupNode(parent.c_str(), "mknod");

      struct stat st;
      if (dnode->getAttr(&st) == 0)
        res = fnode->mknod(mode, rdev, uid, st.st_gid);
    }
  } catch (rlog::Error &err) {
    rError("error caught in mknod");
    err.log(_RLWarningChannel);
  }
  return res;
}

int encfs_mkdir(const char *path, mode_t mode) {
  fuse_context *fctx = fuse_get_context();
  EncFS_Context *ctx = context();

  if (isReadOnly(ctx)) return -EROFS;

  int res = -EIO;
  shared_ptr<DirNode> FSRoot = ctx->getRoot(&res);
  if (!FSRoot) return res;

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
      shared_ptr<FileNode> dnode = FSRoot->lookupNode(parent.c_str(), "mkdir");

      struct stat st;
      if (dnode->getAttr(&st) == 0)
        res = FSRoot->mkdir(path, mode, uid, st.st_gid);
    }
  } catch (rlog::Error &err) {
    rError("error caught in mkdir");
    err.log(_RLWarningChannel);
  }
  return res;
}

int encfs_unlink(const char *path) {
  EncFS_Context *ctx = context();

  if (isReadOnly(ctx)) return -EROFS;

  int res = -EIO;
  shared_ptr<DirNode> FSRoot = ctx->getRoot(&res);
  if (!FSRoot) return res;

  try {
    // let DirNode handle it atomically so that it can handle race
    // conditions
    res = FSRoot->unlink(path);
  } catch (rlog::Error &err) {
    rError("error caught in unlink");
    err.log(_RLWarningChannel);
  }
  return res;
}

int _do_rmdir(EncFS_Context *, const string &cipherPath) {
  return rmdir(cipherPath.c_str());
}

int encfs_rmdir(const char *path) {
  if (isReadOnly(NULL)) return -EROFS;
  return withCipherPath("rmdir", path, bind(_do_rmdir, _1, _2));
}

int _do_readlink(EncFS_Context *ctx, const string &cyName, char *buf,
                 size_t size) {
  int res = ESUCCESS;
  shared_ptr<DirNode> FSRoot = ctx->getRoot(&res);
  if (!FSRoot) return res;

  res = ::readlink(cyName.c_str(), buf, size - 1);

  if (res == -1) return -errno;

  buf[res] = '\0';  // ensure null termination
  string decodedName;
  try {
    decodedName = FSRoot->plainPath(buf);
  } catch (...) {
  }

  if (!decodedName.empty()) {
    strncpy(buf, decodedName.c_str(), size - 1);
    buf[size - 1] = '\0';

    return ESUCCESS;
  } else {
    rWarning("Error decoding link");
    return -1;
  }
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

  if (isReadOnly(ctx)) return -EROFS;

  int res = -EIO;
  shared_ptr<DirNode> FSRoot = ctx->getRoot(&res);
  if (!FSRoot) return res;

  try {
    string fromCName = FSRoot->cipherPath(from);
    // allow fully qualified names in symbolic links.
    string toCName = FSRoot->relativeCipherPath(to);

    rLog(Info, "symlink %s -> %s", fromCName.c_str(), toCName.c_str());

    // use setfsuid / setfsgid so that the new link will be owned by the
    // uid/gid provided by the fuse_context.
    int olduid = -1;
    int oldgid = -1;
    if (ctx->publicFilesystem) {
      fuse_context *context = fuse_get_context();
      olduid = setfsuid(context->uid);
      oldgid = setfsgid(context->gid);
    }
    res = ::symlink(toCName.c_str(), fromCName.c_str());
    if (olduid >= 0) setfsuid(olduid);
    if (oldgid >= 0) setfsgid(oldgid);

    if (res == -1)
      res = -errno;
    else
      res = ESUCCESS;
  } catch (rlog::Error &err) {
    rError("error caught in symlink");
    err.log(_RLWarningChannel);
  }
  return res;
}

int encfs_link(const char *from, const char *to) {
  EncFS_Context *ctx = context();

  if (isReadOnly(ctx)) return -EROFS;

  int res = -EIO;
  shared_ptr<DirNode> FSRoot = ctx->getRoot(&res);
  if (!FSRoot) return res;

  try {
    res = FSRoot->link(from, to);
  } catch (rlog::Error &err) {
    rError("error caught in link");
    err.log(_RLWarningChannel);
  }
  return res;
}

int encfs_rename(const char *from, const char *to) {
  EncFS_Context *ctx = context();

  if (isReadOnly(ctx)) return -EROFS;

  int res = -EIO;
  shared_ptr<DirNode> FSRoot = ctx->getRoot(&res);
  if (!FSRoot) return res;

  try {
    res = FSRoot->rename(from, to);
  } catch (rlog::Error &err) {
    rError("error caught in rename");
    err.log(_RLWarningChannel);
  }
  return res;
}

int _do_chmod(EncFS_Context *, const string &cipherPath, mode_t mode) {
  return chmod(cipherPath.c_str(), mode);
}

int encfs_chmod(const char *path, mode_t mode) {
  if (isReadOnly(NULL)) return -EROFS;
  return withCipherPath("chmod", path, bind(_do_chmod, _1, _2, mode));
}

int _do_chown(EncFS_Context *, const string &cyName, uid_t u, gid_t g) {
  int res = lchown(cyName.c_str(), u, g);
  return (res == -1) ? -errno : ESUCCESS;
}

int encfs_chown(const char *path, uid_t uid, gid_t gid) {
  if (isReadOnly(NULL)) return -EROFS;
  return withCipherPath("chown", path, bind(_do_chown, _1, _2, uid, gid));
}

int _do_truncate(FileNode *fnode, off_t size) { return fnode->truncate(size); }

int encfs_truncate(const char *path, off_t size) {
  if (isReadOnly(NULL)) return -EROFS;
  return withFileNode("truncate", path, NULL, bind(_do_truncate, _1, size));
}

int encfs_ftruncate(const char *path, off_t size, struct fuse_file_info *fi) {
  if (isReadOnly(NULL)) return -EROFS;
  return withFileNode("ftruncate", path, fi, bind(_do_truncate, _1, size));
}

int _do_utime(EncFS_Context *, const string &cyName, struct utimbuf *buf) {
  int res = utime(cyName.c_str(), buf);
  return (res == -1) ? -errno : ESUCCESS;
}

int encfs_utime(const char *path, struct utimbuf *buf) {
  if (isReadOnly(NULL)) return -EROFS;
  return withCipherPath("utime", path, bind(_do_utime, _1, _2, buf));
}

int _do_utimens(EncFS_Context *, const string &cyName,
                const struct timespec ts[2]) {
  struct timeval tv[2];
  tv[0].tv_sec = ts[0].tv_sec;
  tv[0].tv_usec = ts[0].tv_nsec / 1000;
  tv[1].tv_sec = ts[1].tv_sec;
  tv[1].tv_usec = ts[1].tv_nsec / 1000;

  int res = lutimes(cyName.c_str(), tv);
  return (res == -1) ? -errno : ESUCCESS;
}

int encfs_utimens(const char *path, const struct timespec ts[2]) {
  if (isReadOnly(NULL)) return -EROFS;
  return withCipherPath("utimens", path, bind(_do_utimens, _1, _2, ts));
}

int encfs_open(const char *path, struct fuse_file_info *file) {
  EncFS_Context *ctx = context();

  if (isReadOnly(ctx) && (file->flags & O_WRONLY || file->flags & O_RDWR))
    return -EROFS;

  int res = -EIO;
  shared_ptr<DirNode> FSRoot = ctx->getRoot(&res);
  if (!FSRoot) return res;

  try {
    shared_ptr<FileNode> fnode =
        FSRoot->openNode(path, "open", file->flags, &res);

    if (fnode) {
      rLog(Info, "encfs_open for %s, flags %i", fnode->cipherName(),
           file->flags);

      if (res >= 0) {
        file->fh = (uintptr_t)ctx->putNode(path, fnode);
        res = ESUCCESS;
      }
    }
  } catch (rlog::Error &err) {
    rError("error caught in open");
    err.log(_RLWarningChannel);
  }

  return res;
}

int _do_flush(FileNode *fnode) {
  /* Flush can be called multiple times for an open file, so it doesn't
     close the file.  However it is important to call close() for some
     underlying filesystems (like NFS).
  */
  int res = fnode->open(O_RDONLY);
  if (res >= 0) {
    int fh = res;
    res = close(dup(fh));
    if (res == -1) res = -errno;
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
    ctx->eraseNode(path, (void *)(uintptr_t)finfo->fh);
    return ESUCCESS;
  } catch (rlog::Error &err) {
    rError("error caught in release");
    err.log(_RLWarningChannel);
    return -EIO;
  }
}

int _do_read(FileNode *fnode, unsigned char *ptr, size_t size, off_t off) {
  return fnode->read(off, ptr, size);
}

int encfs_read(const char *path, char *buf, size_t size, off_t offset,
               struct fuse_file_info *file) {
  return withFileNode("read", path, file,
                      bind(_do_read, _1, (unsigned char *)buf, size, offset));
}

int _do_fsync(FileNode *fnode, int dataSync) {
  return fnode->sync(dataSync != 0);
}

int encfs_fsync(const char *path, int dataSync, struct fuse_file_info *file) {
  if (isReadOnly(NULL)) return -EROFS;
  return withFileNode("fsync", path, file, bind(_do_fsync, _1, dataSync));
}

int _do_write(FileNode *fnode, unsigned char *ptr, size_t size, off_t offset) {
  if (fnode->write(offset, ptr, size))
    return size;
  else
    return -EIO;
}

int encfs_write(const char *path, const char *buf, size_t size, off_t offset,
                struct fuse_file_info *file) {
  if (isReadOnly(NULL)) return -EROFS;
  return withFileNode("write", path, file,
                      bind(_do_write, _1, (unsigned char *)buf, size, offset));
}

// statfs works even if encfs is detached..
int encfs_statfs(const char *path, struct statvfs *st) {
  EncFS_Context *ctx = context();

  int res = -EIO;
  try {
    (void)path;  // path should always be '/' for now..
    rAssert(st != NULL);
    string cyName = ctx->rootCipherDir;

    rLog(Info, "doing statfs of %s", cyName.c_str());
    res = statvfs(cyName.c_str(), st);
    if (!res) {
      // adjust maximum name length..
      st->f_namemax = 6 * (st->f_namemax - 2) / 8;  // approx..
    }
    if (res == -1) res = -errno;
  } catch (rlog::Error &err) {
    rError("error caught in statfs");
    err.log(_RLWarningChannel);
  }
  return res;
}

#ifdef HAVE_XATTR

typedef std::unique_ptr<const char[], std::function<void(const char *)>>
    AttrPtr;
void NoFree(const char *) {}

AttrPtr extToInternalAttr(const char *attr) {
  if (!strncmp(attr, _attr_apple, sizeof(_attr_apple) - 1)) {
    char *out = strdup(attr);
    memcpy(out, _attr_apple_internal, sizeof(_attr_apple_internal) - 1);
    return AttrPtr(out, (void (*)(const char *))std::free);
  } else {
    return AttrPtr(attr, NoFree);
  }
}

void internalToExtAttr(char *attr) {
  if (!strncmp(attr, _attr_apple_internal, sizeof(_attr_apple_internal) - 1)) {
    memcpy(attr, _attr_apple, sizeof(_attr_apple) - 1);
  }
}

int _do_setxattr(EncFS_Context *, const string &cyName, const char *name,
                 const char *value, size_t size, uint32_t pos) {
#ifdef XATTR_ADD_OPT
  return ::setxattr(cyName.c_str(), name, value, size, pos, XATTR_NOFOLLOW);
#else
  return ::setxattr(cyName.c_str(), name, value, size, 0);
#endif
}
int encfs_setxattr(const char *path, const char *name, const char *value,
                   size_t size, int flags, uint32_t pos) {
  if (isReadOnly(NULL)) return -EROFS;
  (void)flags;

  AttrPtr attr = extToInternalAttr(name);
  return withCipherPath("setxattr", path, bind(_do_setxattr, _1, _2, attr.get(),
                                               value, size, pos));
}
int encfs_setxattr(const char *path, const char *name, const char *value,
                   size_t size, int flags) {
  return encfs_setxattr(path, name, value, size, flags, uint32_t(0));
}

int _do_getxattr(EncFS_Context *, const string &cyName, const char *name,
                 void *value, size_t size, uint32_t pos) {
#ifdef XATTR_ADD_OPT
  return ::getxattr(cyName.c_str(), name, value, size, pos, XATTR_NOFOLLOW);
#else
  return ::getxattr(cyName.c_str(), name, value, size);
#endif
}
int encfs_getxattr(const char *path, const char *name, char *value, size_t size,
                   uint32_t pos) {
  AttrPtr attr = extToInternalAttr(name);
  return withCipherPath(
      "getxattr", path,
      bind(_do_getxattr, _1, _2, attr.get(), (void *)value, size, pos), true);
}
int encfs_getxattr(const char *path, const char *name, char *value,
                   size_t size) {
  return encfs_getxattr(path, name, value, size, uint32_t(0));
}

int _do_listxattr(EncFS_Context *, const string &cyName, char *list,
                  size_t size) {
#ifdef XATTR_ADD_OPT
  return ::listxattr(cyName.c_str(), list, size, XATTR_NOFOLLOW);
#else
  return ::listxattr(cyName.c_str(), list, size);
#endif
}

int encfs_listxattr(const char *path, char *list, size_t size) {
  int res = withCipherPath("listxattr", path,
                           bind(_do_listxattr, _1, _2, list, size), true);
  if (list) {
    size_t len = 0;
    char *curr = list;
    while (len < res) {
      internalToExtAttr(curr);
      size_t el_len = strlen(curr) + 1;
      curr += el_len;
      len += el_len;
    }
  }

  return res;
}

int _do_removexattr(EncFS_Context *, const string &cyName, const char *name) {
#ifdef XATTR_ADD_OPT
  int res = ::removexattr(cyName.c_str(), name, XATTR_NOFOLLOW);
#else
  int res = ::removexattr(cyName.c_str(), name);
#endif
  return (res == -1) ? -errno : res;
}

int encfs_removexattr(const char *path, const char *name) {
  if (isReadOnly(NULL)) return -EROFS;

  AttrPtr attr = extToInternalAttr(name);
  return withCipherPath("removexattr", path,
                        bind(_do_removexattr, _1, _2, attr.get()));
}

#endif  // HAVE_XATTR
