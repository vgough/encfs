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

#include "easylogging++.h"
#include <utility>

#include "Context.h"
#include "DirNode.h"
#include "Error.h"
#include "Mutex.h"

namespace encfs {

EncFS_Context::EncFS_Context() {
  pthread_cond_init(&wakeupCond, nullptr);
  pthread_mutex_init(&wakeupMutex, nullptr);
  pthread_mutex_init(&contextMutex, nullptr);

  usageCount = 0;
  idleCount = -1;
  isUnmounting = false;
  currentFuseFh = 1;
}

EncFS_Context::~EncFS_Context() {
  pthread_mutex_destroy(&contextMutex);
  pthread_mutex_destroy(&wakeupMutex);
  pthread_cond_destroy(&wakeupCond);

  // release all entries from map
  openFiles.clear();
}

std::shared_ptr<DirNode> EncFS_Context::getRoot(int *errCode) {
  return getRoot(errCode, false);
}

std::shared_ptr<DirNode> EncFS_Context::getRoot(int *errCode, bool skipUsageCount) {
  std::shared_ptr<DirNode> ret = nullptr;
  do {
    {
      Lock lock(contextMutex);
      if (isUnmounting) {
        *errCode = -EBUSY;
        break;      	
      }
      ret = root;
      // On some system, stat of "/" is allowed even if the calling user is
      // not allowed to list / to go deeper. Do not then count this call.
      if (!skipUsageCount) {
        ++usageCount;
      }
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
  if (r) {
    rootCipherDir = r->rootDirectory();
  }
}

// This function is called periodically by the idle monitoring thread.
// It checks for inactivity and unmount the FS after enough inactive cycles have passed.
// Returns true if FS has really been unmounted, false otherwise.
bool EncFS_Context::usageAndUnmount(int timeoutCycles) {
  Lock lock(contextMutex);

  if (root != nullptr) {

    if (usageCount == 0) {
      ++idleCount;
    }
    else {
      idleCount = 0;
    }
    VLOG(1) << "idle cycle count: " << idleCount << ", timeout at "
            << timeoutCycles;

    usageCount = 0;

    if (idleCount < timeoutCycles) {
      return false;
    }

    if (!openFiles.empty()) {
      if (idleCount % timeoutCycles == 0) {
        RLOG(WARNING) << "Filesystem inactive, but " << openFiles.size()
                      << " files opened: " << this->opts->unmountPoint;
      }
      return false;
    }
    if (!this->opts->mountOnDemand) {
      isUnmounting = true;
    }
    lock.~Lock();
    return unmountFS(this);

  }
  return false;
}

std::shared_ptr<FileNode> EncFS_Context::lookupNode(const char *path) {
  Lock lock(contextMutex);

  auto it = openFiles.find(std::string(path));
  if (it != openFiles.end()) {
    // every entry in the list is fine... so just use the
    // first
    return it->second.front();
  }
  return std::shared_ptr<FileNode>();
}

void EncFS_Context::renameNode(const char *from, const char *to) {
  Lock lock(contextMutex);

  auto it = openFiles.find(std::string(from));
  if (it != openFiles.end()) {
    auto val = it->second;
    openFiles.erase(it);
    openFiles[std::string(to)] = val;
  }
}

// putNode stores "node" under key "path" in the "openFiles" map. It
// increments the reference count if the key already exists.
void EncFS_Context::putNode(const char *path,
                            const std::shared_ptr<FileNode> &node) {
  Lock lock(contextMutex);
  auto &list = openFiles[std::string(path)];
  // The length of "list" serves as the reference count.
  list.push_front(node);
  fuseFhMap[node->fuseFh] = node;
}

// eraseNode is called by encfs_release in response to the RELEASE
// FUSE-command we get from the kernel.
void EncFS_Context::eraseNode(const char *path,
                              const std::shared_ptr<FileNode> &fnode) {
  Lock lock(contextMutex);

  auto it = openFiles.find(std::string(path));
#ifdef __CYGWIN__
  // When renaming a file, Windows first opens it, renames it and then closes it
  // Filenode may have then been renamed too
  if (it == openFiles.end()) {
    RLOG(WARNING) << "Filenode to erase not found, file has certainly be renamed: "
                  << path;
    return;
  }
#endif
  rAssert(it != openFiles.end());
  auto &list = it->second;

  // Find "fnode" in the list of FileNodes registered under this path.
  auto findIter = std::find(list.begin(), list.end(), fnode);
  rAssert(findIter != list.end());
  list.erase(findIter);

  // If no reference to "fnode" remains, drop the entry from fuseFhMap
  // and overwrite the canary.
  findIter = std::find(list.begin(), list.end(), fnode);
  if (findIter == list.end()) {
    fuseFhMap.erase(fnode->fuseFh);
    fnode->canary = CANARY_RELEASED;
  }

  // If no FileNode is registered at this path anymore, drop the entry
  // from openFiles.
  if (list.empty()) {
    openFiles.erase(it);
  }
}

// nextFuseFh returns the next unused uint64 to serve as the FUSE file
// handle for the kernel.
uint64_t EncFS_Context::nextFuseFh() {
  // This is thread-safe because currentFuseFh is declared as std::atomic
  return currentFuseFh++;
}

// lookupFuseFh finds "n" in "fuseFhMap" and returns the FileNode.
std::shared_ptr<FileNode> EncFS_Context::lookupFuseFh(uint64_t n) {
  Lock lock(contextMutex);
  auto it = fuseFhMap.find(n);
  if (it == fuseFhMap.end()) {
    return nullptr;
  }
  return it->second;
}

}  // namespace encfs
