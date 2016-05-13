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

#include "internal/easylogging++.h"
#include <utility>

#include "Context.h"
#include "DirNode.h"
#include "Error.h"
#include "Mutex.h"

namespace encfs {

EncFS_Context::EncFS_Context() {
  pthread_cond_init(&wakeupCond, 0);
  pthread_mutex_init(&wakeupMutex, 0);
  pthread_mutex_init(&contextMutex, 0);

  usageCount = 0;
}

EncFS_Context::~EncFS_Context() {
  pthread_mutex_destroy(&contextMutex);
  pthread_mutex_destroy(&wakeupMutex);
  pthread_cond_destroy(&wakeupCond);

  // release all entries from map
  openFiles.clear();
}
std::shared_ptr<DirNode> EncFS_Context::getRoot(int *errCode) {
  std::shared_ptr<DirNode> ret;
  do {
    {
      Lock lock(contextMutex);
      ret = root;
      ++usageCount;
    }

    if (!ret) {
      int res = remountFS(this);
      if (res != 0) {
        *errCode = res;
        break;
      }
    }
  } while (!ret);

  return ret;
}

void EncFS_Context::setRoot(const std::shared_ptr<DirNode> &r) {
  Lock lock(contextMutex);

  root = r;
  if (r) rootCipherDir = r->rootDirectory();
}

bool EncFS_Context::isMounted() { return root.get() != nullptr; }

int EncFS_Context::getAndResetUsageCounter() {
  Lock lock(contextMutex);

  int count = usageCount;
  usageCount = 0;

  return count;
}

int EncFS_Context::openFileCount() const {
  Lock lock(contextMutex);

  return openFiles.size();
}
std::shared_ptr<FileNode> EncFS_Context::lookupNode(const char *path) {
  Lock lock(contextMutex);

  FileMap::iterator it = openFiles.find(std::string(path));
  if (it != openFiles.end()) {
    // all the items in the set point to the same node.. so just use the
    // first
    return it->second.front();
  }
  return std::shared_ptr<FileNode>();
}

void EncFS_Context::renameNode(const char *from, const char *to) {
  Lock lock(contextMutex);

  FileMap::iterator it = openFiles.find(std::string(from));
  if (it != openFiles.end()) {
    auto val = it->second;
    openFiles.erase(it);
    openFiles[std::string(to)] = val;
  }
}

FileNode *EncFS_Context::putNode(const char *path,
                                 std::shared_ptr<FileNode> &&node) {
  Lock lock(contextMutex);
  auto &list = openFiles[std::string(path)];
  list.push_front(std::move(node));
  return list.front().get();
}

void EncFS_Context::eraseNode(const char *path, FileNode *pl) {
  Lock lock(contextMutex);

  FileMap::iterator it = openFiles.find(std::string(path));
  rAssert(it != openFiles.end());

  it->second.pop_front();

  // if no more references to this file, remove the record all together
  if (it->second.empty()) {
    openFiles.erase(it);
  }
}

}  // namespace encfs
