/*****************************************************************************
 * Author:   Valient Gough <vgough@pobox.com>
 *
 *****************************************************************************
 * Copyright (c) 2007, Valient Gough
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

#ifndef _Context_incl_
#define _Context_incl_

#include <list>
#include <algorithm>
#include <memory>
#include <pthread.h>
#include <set>
#include <string>
#include <unordered_map>
#include <atomic>

#include "encfs.h"

namespace encfs {

class DirNode;
class FileNode;
struct EncFS_Args;
struct EncFS_Opts;

class EncFS_Context {
 public:
  EncFS_Context();
  ~EncFS_Context();

  std::shared_ptr<FileNode> lookupNode(const char *path);

  void getAndResetUsageCounter(int *usage, int *openCount);
  
  void putNode(const char *path, std::shared_ptr<FileNode> node);

  void eraseNode(const char *path, std::shared_ptr<FileNode> fnode);

  void renameNode(const char *oldName, const char *newName);

  void setRoot(const std::shared_ptr<DirNode> &root);
  std::shared_ptr<DirNode> getRoot(int *err);
  bool isMounted();

  std::shared_ptr<EncFS_Args> args;
  std::shared_ptr<EncFS_Opts> opts;
  bool publicFilesystem;

  // root path to cipher dir
  std::string rootCipherDir;

  // for idle monitor
  bool running;
  pthread_t monitorThread;
  pthread_cond_t wakeupCond;
  pthread_mutex_t wakeupMutex;

  uint64_t nextFuseFh();
  std::shared_ptr<FileNode> lookupFuseFh(uint64_t);

 private:
  /* This placeholder is what is referenced in FUSE context (passed to
   * callbacks).
   *
   * A FileNode may be opened many times, but only one FileNode instance per
   * file is kept.  Rather then doing reference counting in FileNode, we
   * store a unique Placeholder for each open() until the corresponding
   * release() is called.  std::shared_ptr then does our reference counting for
   * us.
   */

  typedef std::unordered_map<std::string,
                             std::list<std::shared_ptr<FileNode>>>
      FileMap;

  mutable pthread_mutex_t contextMutex;
  FileMap openFiles;

  int usageCount;
  std::shared_ptr<DirNode> root;

  std::atomic<std::uint64_t> currentFuseFh;
  std::unordered_map<uint64_t, std::shared_ptr<FileNode>> fuseFhMap;
};

int remountFS(EncFS_Context *ctx);

}  // namespace encfs

#endif
