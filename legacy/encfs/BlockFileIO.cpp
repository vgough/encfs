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

#include "BlockFileIO.h"

#include <cstring>  // for memset, memcpy, NULL

#include "Error.h"
#include "FSConfig.h"    // for FSConfigPtr
#include "FileIO.h"      // for IORequest, FileIO
#include "FileUtils.h"   // for EncFS_Opts
#include "MemoryPool.h"  // for MemBlock, release, allocation

namespace encfs {

template <typename Type>
inline Type min(Type A, Type B) {
  return (B < A) ? B : A;
}

static void clearCache(IORequest &req, unsigned int blockSize) {
  memset(req.data, 0, blockSize);
  req.dataLen = 0;
}

BlockFileIO::BlockFileIO(unsigned int blockSize, const FSConfigPtr &cfg)
    : _blockSize(blockSize), _allowHoles(cfg->config->allowHoles) {
  CHECK(_blockSize > 1);
  _cache.data = new unsigned char[_blockSize];
  _noCache = cfg->opts->noCache;
}

BlockFileIO::~BlockFileIO() {
  clearCache(_cache, _blockSize);
  delete[] _cache.data;
}

/**
 * Serve a read request for the size of one block or less,
 * at block-aligned offsets.
 * Always requests full blocks form the lower layer, truncates the
 * returned data as neccessary.
 */
ssize_t BlockFileIO::cacheReadOneBlock(const IORequest &req) const {
  CHECK(req.dataLen <= _blockSize);
  CHECK(req.offset % _blockSize == 0);

  /* we can satisfy the request even if _cache.dataLen is too short, because
   * we always request a full block during reads. This just means we are
   * in the last block of a file, which may be smaller than the blocksize.
   * For reverse encryption, the cache must not be used at all, because
   * the lower file may have changed behind our back. */
  if ((!_noCache) && (req.offset == _cache.offset) && (_cache.dataLen != 0)) {
    // satisfy request from cache
    size_t len = req.dataLen;
    if (_cache.dataLen < len) {
      len = _cache.dataLen;  // Don't read past EOF
    }
    memcpy(req.data, _cache.data, len);
    return len;
  }
  if (_cache.dataLen > 0) {
    clearCache(_cache, _blockSize);
  }

  // cache results of read -- issue reads for full blocks
  IORequest tmp;
  tmp.offset = req.offset;
  tmp.data = _cache.data;
  tmp.dataLen = _blockSize;
  ssize_t result = readOneBlock(tmp);
  if (result > 0) {
    _cache.offset = req.offset;
    _cache.dataLen = result;  // the amount we really have
    if ((size_t)result > req.dataLen) {
      result = req.dataLen;  // only as much as requested
    }
    memcpy(req.data, _cache.data, result);
  }
  return result;
}

ssize_t BlockFileIO::cacheWriteOneBlock(const IORequest &req) {
  // Let's point request buffer to our own buffer, as it may be modified by
  // encryption : originating process may not like to have its buffer modified
  memcpy(_cache.data, req.data, req.dataLen);
  IORequest tmp;
  tmp.offset = req.offset;
  tmp.data = _cache.data;
  tmp.dataLen = req.dataLen;
  ssize_t res = writeOneBlock(tmp);
  if (res < 0) {
    clearCache(_cache, _blockSize);
  }
  else {
    // And now we can cache the write buffer from the request
    memcpy(_cache.data, req.data, req.dataLen);
    _cache.offset = req.offset;
    _cache.dataLen = req.dataLen;
  }
  return res;
}

/**
 * Serve a read request of arbitrary size at an arbitrary offset.
 * Stitches together multiple blocks to serve large requests, drops
 * data from the front of the first block if the request is not aligned.
 * Always requests aligned data of the size of one block or less from the
 * lower layer.
 * Returns the number of bytes read, or -errno in case of failure.
 */
ssize_t BlockFileIO::read(const IORequest &req) const {
  CHECK(_blockSize != 0);

  int partialOffset =
      req.offset % _blockSize;  // can be int as _blockSize is int
  off_t blockNum = req.offset / _blockSize;
  ssize_t result = 0;

  if (partialOffset == 0 && req.dataLen <= _blockSize) {
    // read completely within a single block -- can be handled as-is by
    // readOneBlock().
    return cacheReadOneBlock(req);
  }
  size_t size = req.dataLen;

  // if the request is larger then a block, then request each block
  // individually
  MemBlock mb;         // in case we need to allocate a temporary block..
  IORequest blockReq;  // for requests we may need to make
  blockReq.dataLen = _blockSize;
  blockReq.data = nullptr;

  unsigned char *out = req.data;
  while (size != 0u) {
    blockReq.offset = blockNum * _blockSize;

    // if we're reading a full block, then read directly into the
    // result buffer instead of using a temporary
    if (partialOffset == 0 && size >= _blockSize) {
      blockReq.data = out;
    } else {
      if (mb.data == nullptr) {
        mb = MemoryPool::allocate(_blockSize);
      }
      blockReq.data = mb.data;
    }

    ssize_t readSize = cacheReadOneBlock(blockReq);
    if (readSize < 0) {
      result = readSize;
      break;
    }
    if (readSize <= partialOffset) {
      break;  // didn't get enough bytes
    }

    size_t cpySize = min((size_t)readSize - (size_t)partialOffset, size);
    CHECK(cpySize <= (size_t)readSize);

    // if we read to a temporary buffer, then move the data
    if (blockReq.data != out) {
      memcpy(out, blockReq.data + partialOffset, cpySize);
    }

    result += cpySize;
    size -= cpySize;
    out += cpySize;
    ++blockNum;
    partialOffset = 0;

    if ((size_t)readSize < _blockSize) {
      break;
    }
  }

  if (mb.data != nullptr) {
    MemoryPool::release(mb);
  }

  return result;
}

/**
 * Returns the number of bytes written, or -errno in case of failure.
 */
ssize_t BlockFileIO::write(const IORequest &req) {
  CHECK(_blockSize != 0);

  off_t fileSize = getSize();
  if (fileSize < 0) {
    return fileSize;
  }

  // where write request begins
  off_t blockNum = req.offset / _blockSize;
  int partialOffset =
      req.offset % _blockSize;  // can be int as _blockSize is int

  // last block of file (for testing write overlaps with file boundary)
  off_t lastFileBlock = fileSize / _blockSize;
  size_t lastBlockSize = fileSize % _blockSize;

  off_t lastNonEmptyBlock = lastFileBlock;
  if (lastBlockSize == 0) {
    --lastNonEmptyBlock;
  }

  if (req.offset > fileSize) {
    // extend file first to fill hole with 0's..
    const bool forceWrite = false;
    int res = padFile(fileSize, req.offset, forceWrite);
    if (res < 0) {
      return res;
    }
  }

  // check against edge cases where we can just let the base class handle the
  // request as-is..
  if (partialOffset == 0 && req.dataLen <= _blockSize) {
    // if writing a full block.. pretty safe..
    if (req.dataLen == _blockSize) {
      return cacheWriteOneBlock(req);
    }

    // if writing a partial block, but at least as much as what is
    // already there..
    if (blockNum == lastFileBlock && req.dataLen >= lastBlockSize) {
      return cacheWriteOneBlock(req);
    }
  }

  // have to merge data with existing block(s)..
  MemBlock mb;

  IORequest blockReq;
  blockReq.data = nullptr;
  blockReq.dataLen = _blockSize;

  ssize_t res = 0;
  size_t size = req.dataLen;
  unsigned char *inPtr = req.data;
  while (size != 0u) {
    blockReq.offset = blockNum * _blockSize;
    size_t toCopy = min((size_t)_blockSize - (size_t)partialOffset, size);

    // if writing an entire block, or writing a partial block that requires
    // no merging with existing data..
    if ((toCopy == _blockSize) ||
        (partialOffset == 0 && blockReq.offset + (off_t)toCopy >= fileSize)) {
      // write directly from buffer
      blockReq.data = inPtr;
      blockReq.dataLen = toCopy;
    } else {
      // need a temporary buffer, since we have to either merge or pad
      // the data.
      if (mb.data == nullptr) {
        mb = MemoryPool::allocate(_blockSize);
      }
      memset(mb.data, 0, _blockSize);
      blockReq.data = mb.data;

      if (blockNum > lastNonEmptyBlock) {
        // just pad..
        blockReq.dataLen = partialOffset + toCopy;
      } else {
        // have to merge with existing block data..
        blockReq.dataLen = _blockSize;
        ssize_t readSize = cacheReadOneBlock(blockReq);
        if (readSize < 0) {
          res = readSize;
          break;
        }
        blockReq.dataLen = readSize;

        // extend data if necessary..
        if (partialOffset + toCopy > blockReq.dataLen) {
          blockReq.dataLen = partialOffset + toCopy;
        }
      }
      // merge in the data to be written..
      memcpy(blockReq.data + partialOffset, inPtr, toCopy);
    }

    // Finally, write the damn thing!
    res = cacheWriteOneBlock(blockReq);
    if (res < 0) {
      break;
    }

    // prepare to start all over with the next block..
    size -= toCopy;
    inPtr += toCopy;
    ++blockNum;
    partialOffset = 0;
  }

  if (mb.data != nullptr) {
    MemoryPool::release(mb);
  }

  if (res < 0) {
    return res;
  }
  return req.dataLen;
}

unsigned int BlockFileIO::blockSize() const { return _blockSize; }

/**
 * Returns 0 in case of success, or -errno in case of failure.
 */
int BlockFileIO::padFile(off_t oldSize, off_t newSize, bool forceWrite) {
  off_t oldLastBlock = oldSize / _blockSize;
  off_t newLastBlock = newSize / _blockSize;
  int newBlockSize = newSize % _blockSize;  // can be int as _blockSize is int
  ssize_t res = 0;

  IORequest req;
  MemBlock mb;

  if (oldLastBlock == newLastBlock) {
    // when the real write occurs, it will have to read in the existing
    // data and pad it anyway, so we won't do it here (unless we're
    // forced).
    if (forceWrite) {
      mb = MemoryPool::allocate(_blockSize);
      req.data = mb.data;

      req.offset = oldLastBlock * _blockSize;
      req.dataLen = oldSize % _blockSize;
      int outSize = newSize % _blockSize;  // outSize > req.dataLen

      if (outSize != 0) {
        memset(mb.data, 0, outSize);
        if ((res = cacheReadOneBlock(req)) >= 0) {
          req.dataLen = outSize;
          res = cacheWriteOneBlock(req);
        }
      }
    } else
      VLOG(1) << "optimization: not padding last block";
  } else {
    mb = MemoryPool::allocate(_blockSize);
    req.data = mb.data;

    // 1. extend the first block to full length
    // 2. write the middle empty blocks
    // 3. write the last block

    req.offset = oldLastBlock * _blockSize;
    req.dataLen = oldSize % _blockSize;

    // 1. req.dataLen == 0, iff oldSize was already a multiple of blocksize
    if (req.dataLen != 0) {
      VLOG(1) << "padding block " << oldLastBlock;
      memset(mb.data, 0, _blockSize);
      if ((res = cacheReadOneBlock(req)) >= 0) {
        req.dataLen = _blockSize;  // expand to full block size
        res = cacheWriteOneBlock(req);
      }
      ++oldLastBlock;
    }

    // 2, pad zero blocks unless holes are allowed
    if (!_allowHoles) {
      for (; (res >= 0) && (oldLastBlock != newLastBlock); ++oldLastBlock) {
        VLOG(1) << "padding block " << oldLastBlock;
        req.offset = oldLastBlock * _blockSize;
        req.dataLen = _blockSize;
        memset(mb.data, 0, req.dataLen);
        res = cacheWriteOneBlock(req);
      }
    }

    // 3. only necessary if write is forced and block is non 0 length
    if ((res >= 0) && forceWrite && (newBlockSize != 0)) {
      req.offset = newLastBlock * _blockSize;
      req.dataLen = newBlockSize;
      memset(mb.data, 0, req.dataLen);
      res = cacheWriteOneBlock(req);
    }
  }

  if (mb.data != nullptr) {
    MemoryPool::release(mb);
  }

  if (res < 0) {
    return res;
  }
  return 0;
}

/**
 * Returns 0 in case of success, or -errno in case of failure.
 */
int BlockFileIO::truncateBase(off_t size, FileIO *base) {
  int partialBlock = size % _blockSize;  // can be int as _blockSize is int
  int res = 0;

  off_t oldSize = getSize();

  if (size > oldSize) {
    // truncate can be used to extend a file as well.  truncate man page
    // states that it will pad with 0's.
    // do the truncate so that the underlying filesystem can allocate
    // the space, and then we'll fill it in padFile..
    if (base != nullptr) {
      res = base->truncate(size);
    }

    const bool forceWrite = true;
    if (res == 0) {
      res = padFile(oldSize, size, forceWrite);
    }
  } else if (size == oldSize) {
    // the easiest case, but least likely....
  } else if (partialBlock != 0) {
    // partial block after truncate.  Need to read in the block being
    // truncated before the truncate.  Then write it back out afterwards,
    // since the encoding will change..
    off_t blockNum = size / _blockSize;
    MemBlock mb = MemoryPool::allocate(_blockSize);

    IORequest req;
    req.offset = blockNum * _blockSize;
    req.dataLen = _blockSize;
    req.data = mb.data;

    ssize_t readSize = cacheReadOneBlock(req);
    if (readSize < 0) {
      res = readSize;
    }

    else if (base != nullptr) {
      // do the truncate
      res = base->truncate(size);
    }

    // write back out partial block
    req.dataLen = partialBlock;
    if (res == 0) {
      ssize_t writeSize = cacheWriteOneBlock(req);
      if (writeSize < 0) {
        res = writeSize;
      }
    }

    MemoryPool::release(mb);
  } else {
    // truncating on a block bounday.  No need to re-encode the last
    // block..
    if (base != nullptr) {
      res = base->truncate(size);
    }
  }

  return res;
}

}  // namespace encfs
