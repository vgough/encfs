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

#include <cerrno>
#include <cstdio>
#include <pthread.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <utime.h>

#include "DirNode.h"
#include "FSConfig.h"
#include "FileNode.h"
#include "FileUtils.h"
#include "NameIO.h"
#ifdef linux
#include <sys/fsuid.h>
#endif

#include "internal/easylogging++.h"
#include <cstring>

#include "Context.h"
#include "Error.h"
#include "Mutex.h"

using namespace std;

namespace encfs {

class DirDeleter {
 public:
  void operator()(DIR *d) { ::closedir(d); }
};

DirTraverse::DirTraverse(const std::shared_ptr<DIR> &_dirPtr, uint64_t _iv,
                         const std::shared_ptr<NameIO> &_naming)
    : dir(_dirPtr), iv(_iv), naming(_naming) {}

DirTraverse::DirTraverse(const DirTraverse &src)
    : dir(src.dir), iv(src.iv), naming(src.naming) {}

DirTraverse &DirTraverse::operator=(const DirTraverse &src) {
  dir = src.dir;
  iv = src.iv;
  naming = src.naming;

  return *this;
}

DirTraverse::~DirTraverse() {
  dir.reset();
  iv = 0;
  naming.reset();
}

static bool _nextName(struct dirent *&de, const std::shared_ptr<DIR> &dir,
                      int *fileType, ino_t *inode) {
  de = ::readdir(dir.get());

  if (de) {
    if (fileType) {
#if defined(_DIRENT_HAVE_D_TYPE) || defined(__FreeBSD__) || defined(__APPLE__)
      *fileType = de->d_type;
#else
#warning "struct dirent.d_type not supported"
      *fileType = 0;
#endif
    }
    if (inode) *inode = de->d_ino;
    return true;
  } else {
    if (fileType) *fileType = 0;
    return false;
  }
}

std::string DirTraverse::nextPlaintextName(int *fileType, ino_t *inode) {
  struct dirent *de = 0;
  while (_nextName(de, dir, fileType, inode)) {
    try {
      uint64_t localIv = iv;
      return naming->decodePath(de->d_name, &localIv);
    } catch (encfs::Error &ex) {
      // .. .problem decoding, ignore it and continue on to next name..
      VLOG(1) << "error decoding filename: " << de->d_name;
    }
  }

  return string();
}

std::string DirTraverse::nextInvalid() {
  struct dirent *de = 0;
  // find the first name which produces a decoding error...
  while (_nextName(de, dir, (int *)0, (ino_t *)0)) {
    try {
      uint64_t localIv = iv;
      naming->decodePath(de->d_name, &localIv);
      continue;
    } catch (encfs::Error &ex) {
      return string(de->d_name);
    }
  }

  return string();
}

struct RenameEl {
  // ciphertext names
  string oldCName;
  string newCName;  // intermediate name (not final cname)

  // plaintext names
  string oldPName;
  string newPName;

  bool isDirectory;
};

class RenameOp {
 private:
  DirNode *dn;
  std::shared_ptr<list<RenameEl> > renameList;
  list<RenameEl>::const_iterator last;

 public:
  RenameOp(DirNode *_dn, const std::shared_ptr<list<RenameEl> > &_renameList)
      : dn(_dn), renameList(_renameList) {
    last = renameList->begin();
  }

  RenameOp(const RenameOp &src)
      : dn(src.dn), renameList(src.renameList), last(src.last) {}

  ~RenameOp();

  operator bool() const { return renameList.get() != nullptr; }

  bool apply();
  void undo();
};

RenameOp::~RenameOp() {
  if (renameList) {
    // got a bunch of decoded filenames sitting in memory..  do a little
    // cleanup before leaving..
    list<RenameEl>::iterator it;
    for (it = renameList->begin(); it != renameList->end(); ++it) {
      it->oldPName.assign(it->oldPName.size(), ' ');
      it->newPName.assign(it->newPName.size(), ' ');
    }
  }
}

bool RenameOp::apply() {
  try {
    while (last != renameList->end()) {
      // backing store rename.
      VLOG(1) << "renaming " << last->oldCName << " -> " << last->newCName;

      struct stat st;
      bool preserve_mtime = ::stat(last->oldCName.c_str(), &st) == 0;

      // internal node rename..
      dn->renameNode(last->oldPName.c_str(), last->newPName.c_str());

      // rename on disk..
      if (::rename(last->oldCName.c_str(), last->newCName.c_str()) == -1) {
        RLOG(WARNING) << "Error renaming " << last->oldCName << ": "
                      << strerror(errno);
        dn->renameNode(last->newPName.c_str(), last->oldPName.c_str(), false);
        return false;
      }

      if (preserve_mtime) {
        struct utimbuf ut;
        ut.actime = st.st_atime;
        ut.modtime = st.st_mtime;
        ::utime(last->newCName.c_str(), &ut);
      }

      ++last;
    }

    return true;
  } catch (encfs::Error &err) {
    RLOG(WARNING) << err.what();
    return false;
  }
}

void RenameOp::undo() {
  VLOG(1) << "in undoRename";

  if (last == renameList->begin()) {
    VLOG(1) << "nothing to undo";
    return;  // nothing to undo
  }

  // list has to be processed backwards, otherwise we may rename
  // directories and directory contents in the wrong order!
  int undoCount = 0;
  list<RenameEl>::const_iterator it = last;

  while (it != renameList->begin()) {
    --it;

    VLOG(1) << "undo: renaming " << it->newCName << " -> " << it->oldCName;

    ::rename(it->newCName.c_str(), it->oldCName.c_str());
    try {
      dn->renameNode(it->newPName.c_str(), it->oldPName.c_str(), false);
    } catch (encfs::Error &err) {
      RLOG(WARNING) << err.what();
      // continue on anyway...
    }
    ++undoCount;
  };

  RLOG(WARNING) << "Undo rename count: " << undoCount;
}

DirNode::DirNode(EncFS_Context *_ctx, const string &sourceDir,
                 const FSConfigPtr &_config) {
  pthread_mutex_init(&mutex, 0);

  Lock _lock(mutex);

  ctx = _ctx;
  rootDir = sourceDir;  // .. and fsConfig->opts->mountPoint have trailing slash
  fsConfig = _config;

  naming = fsConfig->nameCoding;
}

DirNode::~DirNode() {}

bool DirNode::hasDirectoryNameDependency() const {
  return naming ? naming->getChainedNameIV() : false;
}

string DirNode::rootDirectory() {
  // don't update last access here, otherwise 'du' would cause lastAccess to
  // be reset.
  // chop off '/' terminator from root dir.
  return string(rootDir, 0, rootDir.length() - 1);
}

bool DirNode::touchesMountpoint(const char *realPath) const {
  const string &mountPoint = fsConfig->opts->mountPoint;
  // compare mountPoint up to the leading slash.
  // examples:
  //   mountPoint      = /home/user/Junk/experiment/
  //   realPath        = /home/user/Junk/experiment
  //   realPath        = /home/user/Junk/experiment/abc
  const ssize_t len = mountPoint.length() - 1;

  if (mountPoint.compare(0, len, realPath, len) == 0) {
    // if next character is a NUL or a slash, then we're referencing our
    // mount point:
    //   .../experiment => true
    //   .../experiment/... => true
    //   .../experiment2/abc => false
    return realPath[len] == '\0' || realPath[len] == '/';
  }

  return false;
}

/**
 * Encrypt a plain-text file path to the ciphertext path with the
 * ciphertext root directory name prefixed.
 *
 * Example:
 * $ encfs -f -v cipher plain
 * $ cd plain
 * $ touch foobar
 * cipherPath: /foobar encoded to cipher/NKAKsn2APtmquuKPoF4QRPxS
 */
string DirNode::cipherPath(const char *plaintextPath) {
  return rootDir + naming->encodePath(plaintextPath);
}

/**
 * Same as cipherPath(), but does not prefix the ciphertext root directory
 */
string DirNode::cipherPathWithoutRoot(const char *plaintextPath) {
  return naming->encodePath(plaintextPath);
}

/**
 * Return the decrypted version of cipherPath
 *
 * In reverse mode, returns the encrypted version of cipherPath
 */
string DirNode::plainPath(const char *cipherPath_) {
  try {
    // Handle special absolute path encodings.
    char mark = '+';
    string prefix = "/";
    if (fsConfig->reverseEncryption) {
      mark = '/';
      prefix = "+";
    }
    if (cipherPath_[0] == mark) {
      return prefix +
             naming->decodeName(cipherPath_ + 1, strlen(cipherPath_ + 1));
    }

    // Default.
    return naming->decodePath(cipherPath_);
  } catch (encfs::Error &err) {
    RLOG(ERROR) << "decode err: " << err.what();
    return string();
  }
}

string DirNode::relativeCipherPath(const char *plaintextPath) {
  try {
    // use '+' prefix to indicate special decoding.
    char mark = fsConfig->reverseEncryption ? '+' : '/';
    if (plaintextPath[0] == mark) {
      return string(fsConfig->reverseEncryption ? "/" : "+") +
             naming->encodeName(plaintextPath + 1, strlen(plaintextPath + 1));
    }

    return naming->encodePath(plaintextPath);
  } catch (encfs::Error &err) {
    RLOG(ERROR) << "encode err: " << err.what();
    return string();
  }
}

DirTraverse DirNode::openDir(const char *plaintextPath) {
  string cyName = rootDir + naming->encodePath(plaintextPath);

  DIR *dir = ::opendir(cyName.c_str());
  if (dir == NULL) {
    VLOG(1) << "opendir error " << strerror(errno);
    return DirTraverse(shared_ptr<DIR>(), 0, std::shared_ptr<NameIO>());
  } else {
    std::shared_ptr<DIR> dp(dir, DirDeleter());

    uint64_t iv = 0;
    // if we're using chained IV mode, then compute the IV at this
    // directory level..
    try {
      if (naming->getChainedNameIV()) naming->encodePath(plaintextPath, &iv);
    } catch (encfs::Error &err) {
      RLOG(ERROR) << "encode err: " << err.what();
    }
    return DirTraverse(dp, iv, naming);
  }
}

bool DirNode::genRenameList(list<RenameEl> &renameList, const char *fromP,
                            const char *toP) {
  uint64_t fromIV = 0, toIV = 0;

  // compute the IV for both paths
  string fromCPart = naming->encodePath(fromP, &fromIV);
  string toCPart = naming->encodePath(toP, &toIV);

  // where the files live before the rename..
  string sourcePath = rootDir + fromCPart;

  // ok..... we wish it was so simple.. should almost never happen
  if (fromIV == toIV) return true;

  // generate the real destination path, where we expect to find the files..
  VLOG(1) << "opendir " << sourcePath;
  std::shared_ptr<DIR> dir =
      std::shared_ptr<DIR>(opendir(sourcePath.c_str()), DirDeleter());
  if (!dir) return false;

  struct dirent *de = NULL;
  while ((de = ::readdir(dir.get())) != NULL) {
    // decode the name using the oldIV
    uint64_t localIV = fromIV;
    string plainName;

    if ((de->d_name[0] == '.') &&
        ((de->d_name[1] == '\0') ||
         ((de->d_name[1] == '.') && (de->d_name[2] == '\0')))) {
      // skip "." and ".."
      continue;
    }

    try {
      plainName = naming->decodePath(de->d_name, &localIV);
    } catch (encfs::Error &ex) {
      // if filename can't be decoded, then ignore it..
      continue;
    }

    // any error in the following will trigger a rename failure.
    try {
      // re-encode using the new IV..
      localIV = toIV;
      string newName = naming->encodePath(plainName.c_str(), &localIV);

      // store rename information..
      string oldFull = sourcePath + '/' + de->d_name;
      string newFull = sourcePath + '/' + newName;

      RenameEl ren;
      ren.oldCName = oldFull;
      ren.newCName = newFull;
      ren.oldPName = string(fromP) + '/' + plainName;
      ren.newPName = string(toP) + '/' + plainName;

      bool isDir;
#if defined(_DIRENT_HAVE_D_TYPE)
      if (de->d_type != DT_UNKNOWN) {
        isDir = (de->d_type == DT_DIR);
      } else
#endif
      {
        isDir = isDirectory(oldFull.c_str());
      }

      ren.isDirectory = isDir;

      if (isDir) {
        // recurse..  We want to add subdirectory elements before the
        // parent, as that is the logical rename order..
        if (!genRenameList(renameList, ren.oldPName.c_str(),
                           ren.newPName.c_str())) {
          return false;
        }
      }

      VLOG(1) << "adding file " << oldFull << " to rename list";

      renameList.push_back(ren);
    } catch (encfs::Error &err) {
      // We can't convert this name, because we don't have a valid IV for
      // it (or perhaps a valid key).. It will be inaccessible..
      RLOG(WARNING) << "Aborting rename: error on file: "
                    << fromCPart.append(1, '/').append(de->d_name);
      RLOG(WARNING) << err.what();

      // abort.. Err on the side of safety and disallow rename, rather
      // then loosing files..
      return false;
    }
  }

  return true;
}

/*
    A bit of a pain.. If a directory is renamed in a filesystem with
    directory initialization vector chaining, then we have to recursively
    rename every descendent of this directory, as all initialization vectors
    will have changed..

    Returns a list of renamed items on success, a null list on failure.
*/ std::shared_ptr<RenameOp> DirNode::newRenameOp(const char *fromP,
                                                  const char *toP) {
  // Do the rename in two stages to avoid chasing our tail
  // Undo everything if we encounter an error!
  std::shared_ptr<list<RenameEl> > renameList(new list<RenameEl>);
  if (!genRenameList(*renameList.get(), fromP, toP)) {
    RLOG(WARNING) << "Error during generation of recursive rename list";
    return std::shared_ptr<RenameOp>();
  } else
    return std::shared_ptr<RenameOp>(new RenameOp(this, renameList));
}

int DirNode::mkdir(const char *plaintextPath, mode_t mode, uid_t uid,
                   gid_t gid) {
  string cyName = rootDir + naming->encodePath(plaintextPath);
  rAssert(!cyName.empty());

  VLOG(1) << "mkdir on " << cyName;

  // if uid or gid are set, then that should be the directory owner
  int olduid = -1;
  int oldgid = -1;
  if (uid != 0) olduid = setfsuid(uid);
  if (gid != 0) oldgid = setfsgid(gid);

  int res = ::mkdir(cyName.c_str(), mode);

  if (olduid >= 0) setfsuid(olduid);
  if (oldgid >= 0) setfsgid(oldgid);

  if (res == -1) {
    int eno = errno;
    RLOG(WARNING) << "mkdir error on " << cyName << " mode " << mode << ": "
                  << strerror(eno);
    res = -eno;
  } else
    res = 0;

  return res;
}

int DirNode::rename(const char *fromPlaintext, const char *toPlaintext) {
  Lock _lock(mutex);

  string fromCName = rootDir + naming->encodePath(fromPlaintext);
  string toCName = rootDir + naming->encodePath(toPlaintext);
  rAssert(!fromCName.empty());
  rAssert(!toCName.empty());

  VLOG(1) << "rename " << fromCName << " -> " << toCName;

  std::shared_ptr<FileNode> toNode = findOrCreate(toPlaintext);

  std::shared_ptr<RenameOp> renameOp;
  if (hasDirectoryNameDependency() && isDirectory(fromCName.c_str())) {
    VLOG(1) << "recursive rename begin";
    renameOp = newRenameOp(fromPlaintext, toPlaintext);

    if (!renameOp || !renameOp->apply()) {
      if (renameOp) renameOp->undo();

      RLOG(WARNING) << "rename aborted";
      return -EACCES;
    }
    VLOG(1) << "recursive rename end";
  }

  int res = 0;
  try {
    struct stat st;
    bool preserve_mtime = ::stat(fromCName.c_str(), &st) == 0;

    renameNode(fromPlaintext, toPlaintext);
    res = ::rename(fromCName.c_str(), toCName.c_str());

    if (res == -1) {
      // undo
      res = -errno;
      renameNode(toPlaintext, fromPlaintext, false);

      if (renameOp) renameOp->undo();
    } else if (preserve_mtime) {
      struct utimbuf ut;
      ut.actime = st.st_atime;
      ut.modtime = st.st_mtime;
      ::utime(toCName.c_str(), &ut);
    }
  } catch (encfs::Error &err) {
    // exception from renameNode, just show the error and continue..
    RLOG(WARNING) << err.what();
    res = -EIO;
  }

  if (res != 0) {
    VLOG(1) << "rename failed: " << strerror(errno);
    res = -errno;
  }

  return res;
}

int DirNode::link(const char *from, const char *to) {
  Lock _lock(mutex);

  string fromCName = rootDir + naming->encodePath(from);
  string toCName = rootDir + naming->encodePath(to);

  rAssert(!fromCName.empty());
  rAssert(!toCName.empty());

  VLOG(1) << "link " << fromCName << " -> " << toCName;

  int res = -EPERM;
  if (fsConfig->config->externalIVChaining) {
    VLOG(1) << "hard links not supported with external IV chaining!";
  } else {
    res = ::link(fromCName.c_str(), toCName.c_str());
    if (res == -1)
      res = -errno;
    else
      res = 0;
  }

  return res;
}

/*
    The node is keyed by filename, so a rename means the internal node names
    must be changed.
*/ std::shared_ptr<FileNode> DirNode::renameNode(const char *from,
                                                 const char *to) {
  return renameNode(from, to, true);
}
std::shared_ptr<FileNode> DirNode::renameNode(const char *from, const char *to,
                                              bool forwardMode) {
  std::shared_ptr<FileNode> node = findOrCreate(from);

  if (node) {
    uint64_t newIV = 0;
    string cname = rootDir + naming->encodePath(to, &newIV);

    VLOG(1) << "renaming internal node " << node->cipherName() << " -> "
            << cname;

    if (node->setName(to, cname.c_str(), newIV, forwardMode)) {
      if (ctx) ctx->renameNode(from, to);
    } else {
      // rename error! - put it back
      RLOG(ERROR) << "renameNode failed";
      throw Error("Internal node name change failed!");
    }
  }

  return node;
}
std::shared_ptr<FileNode> DirNode::findOrCreate(const char *plainName) {
  std::shared_ptr<FileNode> node;
  if (ctx) node = ctx->lookupNode(plainName);
  if (!node) {
    uint64_t iv = 0;
    string cipherName = naming->encodePath(plainName, &iv);
    node.reset(new FileNode(this, fsConfig, plainName,
                            (rootDir + cipherName).c_str()));

    if (fsConfig->config->externalIVChaining) node->setName(0, 0, iv);

    VLOG(1) << "created FileNode for " << node->cipherName();
  }

  return node;
}

shared_ptr<FileNode> DirNode::lookupNode(const char *plainName,
                                         const char * /* requestor */) {
  Lock _lock(mutex);
  return findOrCreate(plainName);
}

/*
    Similar to lookupNode, except that we also call open() and only return a
    node on sucess..  This is done in one step to avoid any race conditions
    with the stored state of the file.
*/ std::shared_ptr<FileNode> DirNode::openNode(const char *plainName,
                                               const char *requestor, int flags,
                                               int *result) {
  (void)requestor;
  rAssert(result != NULL);
  Lock _lock(mutex);

  std::shared_ptr<FileNode> node = findOrCreate(plainName);

  if (node && (*result = node->open(flags)) >= 0)
    return node;
  else
    return std::shared_ptr<FileNode>();
}

int DirNode::unlink(const char *plaintextName) {
  string cyName = naming->encodePath(plaintextName);
  VLOG(1) << "unlink " << cyName;

  Lock _lock(mutex);

  int res = 0;
  if (ctx && ctx->lookupNode(plaintextName)) {
    // If FUSE is running with "hard_remove" option where it doesn't
    // hide open files for us, then we can't allow an unlink of an open
    // file..
    RLOG(WARNING) << "Refusing to unlink open file: " << cyName
                  << ", hard_remove option "
                     "is probably in effect";
    res = -EBUSY;
  } else {
    string fullName = rootDir + cyName;
    res = ::unlink(fullName.c_str());
    if (res == -1) {
      res = -errno;
      VLOG(1) << "unlink error: " << strerror(errno);
    }
  }

  return res;
}

}  // namespace encfs
