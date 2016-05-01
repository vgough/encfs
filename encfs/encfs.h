/*****************************************************************************
 * Author:   Valient Gough <vgough@pobox.com>
 *
 *****************************************************************************
 * Copyright (c) 2003, Valient Gough
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

#ifndef _encfs_incl_
#define _encfs_incl_

#include "internal/easylogging++.h"
#include <fuse.h>
#include <sys/types.h>
#include <unistd.h>

#include "config.h"

namespace encfs {

#if defined(HAVE_SYS_XATTR_H) | defined(HAVE_ATTR_XATTR_H)
#define HAVE_XATTR
#endif

#ifndef linux
#include <cerrno>

static __inline int setfsuid(uid_t uid) {
  uid_t olduid = geteuid();

  if (seteuid(uid) != 0) {
    VLOG(1) << "seteuid error: " << errno;
  }

  return olduid;
}

static __inline int setfsgid(gid_t gid) {
  gid_t oldgid = getegid();

  if (setegid(gid) != 0) {
    VLOG(1) << "setfsgid error: " << errno;
  }

  return oldgid;
}
#endif

int encfs_getattr(const char *path, struct stat *stbuf);
int encfs_fgetattr(const char *path, struct stat *stbuf,
                   struct fuse_file_info *fi);
int encfs_readlink(const char *path, char *buf, size_t size);
int encfs_readdir(const char *path, void *buf, fuse_fill_dir_t filler,
                  off_t offset, struct fuse_file_info *finfo);
int encfs_mknod(const char *path, mode_t mode, dev_t rdev);
int encfs_mkdir(const char *path, mode_t mode);
int encfs_unlink(const char *path);
int encfs_rmdir(const char *path);
int encfs_symlink(const char *from, const char *to);
int encfs_rename(const char *from, const char *to);
int encfs_link(const char *from, const char *to);
int encfs_chmod(const char *path, mode_t mode);
int encfs_chown(const char *path, uid_t uid, gid_t gid);
int encfs_truncate(const char *path, off_t size);
int encfs_ftruncate(const char *path, off_t size, struct fuse_file_info *fi);
int encfs_utime(const char *path, struct utimbuf *buf);
int encfs_open(const char *path, struct fuse_file_info *info);
int encfs_create(const char *path, mode_t mode, struct fuse_file_info *info);
int encfs_release(const char *path, struct fuse_file_info *info);
int encfs_read(const char *path, char *buf, size_t size, off_t offset,
               struct fuse_file_info *info);
int encfs_write(const char *path, const char *buf, size_t size, off_t offset,
                struct fuse_file_info *info);
int encfs_statfs(const char *, struct statvfs *fst);
int encfs_flush(const char *, struct fuse_file_info *info);
int encfs_fsync(const char *path, int flags, struct fuse_file_info *info);

#ifdef HAVE_XATTR

#ifdef XATTR_ADD_OPT
int encfs_setxattr(const char *path, const char *name, const char *value,
                   size_t size, int flags, uint32_t position);
int encfs_getxattr(const char *path, const char *name, char *value, size_t size,
                   uint32_t position);
#else
int encfs_setxattr(const char *path, const char *name, const char *value,
                   size_t size, int flags);
int encfs_getxattr(const char *path, const char *name, char *value,
                   size_t size);
#endif

int encfs_listxattr(const char *path, char *list, size_t size);
int encfs_removexattr(const char *path, const char *name);
#endif

int encfs_utimens(const char *path, const struct timespec ts[2]);

}  // namespace encfs

#endif
