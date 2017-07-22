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

#ifndef _FileNode_incl_
#define _FileNode_incl_

#include <inttypes.h>
#include <memory>
#include <pthread.h>
#include <stdint.h>
#include <string>
#include <sys/types.h>
#include <atomic>

#include "CipherKey.h"
#include "FSConfig.h"
#include "FileUtils.h"
#include "encfs.h"

#define CANARY_OK 0x46040975
#define CANARY_RELEASED 0x70c5610d
#define CANARY_DESTROYED 0x52cdad90

namespace encfs {

class Cipher;
class DirNode;
class FileIO;

class FileNode {
 public:
  FileNode(DirNode *parent, const FSConfigPtr &cfg, const char *plaintextName,
           const char *cipherName, uint64_t fuseFh);
  ~FileNode();

  // Use an atomic type. The canary is accessed without holding any
  // locks.
  std::atomic<std::uint32_t> canary;

  // FUSE file handle that is passed to the kernel
  uint64_t fuseFh;

  const char *plaintextName() const;
  const char *cipherName() const;

  // directory portion of plaintextName
  std::string plaintextParent() const;

  // if setIVFirst is true, then the IV is changed before the name is changed
  // (default).  The reverse is also supported for special cases..
  bool setName(const char *plaintextName, const char *cipherName, uint64_t iv,
               bool setIVFirst = true);

  // create node
  // If uid/gid are not 0, then chown is used change ownership as specified
  int mknod(mode_t mode, dev_t rdev, uid_t uid = 0, gid_t gid = 0);

  // Returns < 0 on error (-errno), file descriptor on success.
  int open(int flags) const;

  // getAttr returns 0 on success, -errno on failure
  int getAttr(struct stat *stbuf) const;
  off_t getSize() const;

  ssize_t read(off_t offset, unsigned char *data, ssize_t size) const;
  bool write(off_t offset, unsigned char *data, ssize_t size);

  // truncate the file to a particular size
  int truncate(off_t size);

  // datasync or full sync
  int sync(bool dataSync);

 private:
  // doing locking at the FileNode level isn't as efficient as at the
  // lowest level of RawFileIO, since that means locks are held longer
  // (held during CPU intensive crypto operations!).  However it makes it
  // easier to avoid any race conditions with operations such as
  // truncate() which may result in multiple calls down to the FileIO
  // level.
  mutable pthread_mutex_t mutex;

  FSConfigPtr fsConfig;

  std::shared_ptr<FileIO> io;
  std::string _pname;  // plaintext name
  std::string _cname;  // encrypted name
  DirNode *parent;

 private:
  FileNode(const FileNode &src);
  FileNode &operator=(const FileNode &src);
};

}  // namespace encfs

#endif
