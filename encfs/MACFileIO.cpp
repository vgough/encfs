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

#include "MACFileIO.h"

#include "internal/easylogging++.h"
#include <cstring>
#include <inttypes.h>
#include <sys/stat.h>

#include "BlockFileIO.h"
#include "Cipher.h"
#include "Error.h"
#include "FileIO.h"
#include "FileUtils.h"
#include "MemoryPool.h"
#include "i18n.h"

using namespace std;

namespace encfs {

// Version 1.0 worked on blocks of size (blockSize + headerSize).
//   That is, it took [blockSize] worth of user data and added headers.
// Version 2.0 takes [blockSize - headerSize] worth of user data and writes
//   [blockSize] bytes.  That way the size going into the crypto engine is
//   valid from what was selected based on the crypto module allowed ranges!
// Version 2.1 allows per-block rand bytes to be used without enabling MAC.
//
// The information about MACFileIO currently does not make its way into the
// configuration file, so there is no easy way to make this backward
// compatible, except at a high level by checking a revision number for the
// filesystem...
//
static Interface MACFileIO_iface("FileIO/MAC", 2, 1, 0);

int dataBlockSize(const FSConfigPtr &cfg) {
  return cfg->config->blockSize - cfg->config->blockMACBytes -
         cfg->config->blockMACRandBytes;
}

MACFileIO::MACFileIO(const std::shared_ptr<FileIO> &_base,
                     const FSConfigPtr &cfg)
    : BlockFileIO(dataBlockSize(cfg), cfg),
      base(_base),
      cipher(cfg->cipher),
      key(cfg->key),
      macBytes(cfg->config->blockMACBytes),
      randBytes(cfg->config->blockMACRandBytes),
      warnOnly(cfg->opts->forceDecode) {
  rAssert(macBytes >= 0 && macBytes <= 8);
  rAssert(randBytes >= 0);
  VLOG(1) << "fs block size = " << cfg->config->blockSize
          << ", macBytes = " << cfg->config->blockMACBytes
          << ", randBytes = " << cfg->config->blockMACRandBytes;
}

MACFileIO::~MACFileIO() {}

Interface MACFileIO::interface() const { return MACFileIO_iface; }

int MACFileIO::open(int flags) { return base->open(flags); }

void MACFileIO::setFileName(const char *fileName) {
  base->setFileName(fileName);
}

const char *MACFileIO::getFileName() const { return base->getFileName(); }

bool MACFileIO::setIV(uint64_t iv) { return base->setIV(iv); }

inline static off_t roundUpDivide(off_t numerator, int denominator) {
  // integer arithmetic always rounds down, so we can round up by adding
  // enough so that any value other then a multiple of denominator gets
  // rouned to the next highest value.
  return (numerator + denominator - 1) / denominator;
}

// Convert from a location in the raw file to a location when MAC headers are
// interleved with the data.
// So, if the filesystem stores/encrypts [blockSize] bytes per block, then
//  [blockSize - headerSize] of those bytes will contain user-supplied data,
//  and the rest ([headerSize]) will contain the MAC header for this block.
// Example, offset points to second block (of user-data)
//   offset = blockSize - headerSize
//   ... blockNum = 1
//   ... partialBlock = 0
//   ... adjLoc = 1 * blockSize
static off_t locWithHeader(off_t offset, int blockSize, int headerSize) {
  off_t blockNum = roundUpDivide(offset, blockSize - headerSize);
  return offset + blockNum * headerSize;
}

// convert from a given location in the stream containing headers, and return a
// location in the user-data stream (which doesn't contain MAC headers)..
// The output value will always be less then the input value, because the
// headers are stored at the beginning of the block, so even the first data is
// offset by the size of the header.
static off_t locWithoutHeader(off_t offset, int blockSize, int headerSize) {
  off_t blockNum = roundUpDivide(offset, blockSize);
  return offset - blockNum * headerSize;
}

int MACFileIO::getAttr(struct stat *stbuf) const {
  int res = base->getAttr(stbuf);

  if (res == 0 && S_ISREG(stbuf->st_mode)) {
    // have to adjust size field..
    int headerSize = macBytes + randBytes;
    int bs = blockSize() + headerSize;
    stbuf->st_size = locWithoutHeader(stbuf->st_size, bs, headerSize);
  }

  return res;
}

off_t MACFileIO::getSize() const {
  // adjust the size to hide the header overhead we tack on..
  int headerSize = macBytes + randBytes;
  int bs = blockSize() + headerSize;

  off_t size = base->getSize();
  if (size > 0) size = locWithoutHeader(size, bs, headerSize);

  return size;
}

ssize_t MACFileIO::readOneBlock(const IORequest &req) const {
  int headerSize = macBytes + randBytes;

  int bs = blockSize() + headerSize;

  MemBlock mb = MemoryPool::allocate(bs);

  IORequest tmp;
  tmp.offset = locWithHeader(req.offset, bs, headerSize);
  tmp.data = mb.data;
  tmp.dataLen = headerSize + req.dataLen;

  // get the data from the base FileIO layer
  ssize_t readSize = base->read(tmp);

  // don't store zeros if configured for zero-block pass-through
  bool skipBlock = true;
  if (_allowHoles) {
    for (int i = 0; i < readSize; ++i)
      if (tmp.data[i] != 0) {
        skipBlock = false;
        break;
      }
  } else if (macBytes > 0)
    skipBlock = false;

  if (readSize > headerSize) {
    if (!skipBlock) {
      // At this point the data has been decoded.  So, compute the MAC of
      // the block and check against the checksum stored in the header..
      uint64_t mac =
          cipher->MAC_64(tmp.data + macBytes, readSize - macBytes, key);

      // Constant time comparision to prevent timing attacks
      unsigned char fail = 0;
      for (int i = 0; i < macBytes; ++i, mac >>= 8) {
        int test = mac & 0xff;
        int stored = tmp.data[i];

        fail |= (test ^ stored);
      }

      if (fail > 0) {
        // uh oh..
        long blockNum = req.offset / bs;
        RLOG(WARNING) << "MAC comparison failure in block " << blockNum;
        if (!warnOnly) {
          MemoryPool::release(mb);
          throw Error(_("MAC comparison failure, refusing to read"));
        }
      }
    }

    // now copy the data to the output buffer
    readSize -= headerSize;
    memcpy(req.data, tmp.data + headerSize, readSize);
  } else {
    VLOG(1) << "readSize " << readSize << " at offset " << req.offset;
    if (readSize > 0) readSize = 0;
  }

  MemoryPool::release(mb);

  return readSize;
}

bool MACFileIO::writeOneBlock(const IORequest &req) {
  int headerSize = macBytes + randBytes;

  int bs = blockSize() + headerSize;

  // we have the unencrypted data, so we need to attach a header to it.
  MemBlock mb = MemoryPool::allocate(bs);

  IORequest newReq;
  newReq.offset = locWithHeader(req.offset, bs, headerSize);
  newReq.data = mb.data;
  newReq.dataLen = headerSize + req.dataLen;

  memset(newReq.data, 0, headerSize);
  memcpy(newReq.data + headerSize, req.data, req.dataLen);
  if (randBytes > 0) {
    if (!cipher->randomize(newReq.data + macBytes, randBytes, false))
      return false;
  }

  if (macBytes > 0) {
    // compute the mac (which includes the random data) and fill it in
    uint64_t mac =
        cipher->MAC_64(newReq.data + macBytes, req.dataLen + randBytes, key);

    for (int i = 0; i < macBytes; ++i) {
      newReq.data[i] = mac & 0xff;
      mac >>= 8;
    }
  }

  // now, we can let the next level have it..
  bool ok = base->write(newReq);

  MemoryPool::release(mb);

  return ok;
}

int MACFileIO::truncate(off_t size) {
  int headerSize = macBytes + randBytes;
  int bs = blockSize() + headerSize;

  int res = BlockFileIO::truncateBase(size, 0);

  if (res == 0) base->truncate(locWithHeader(size, bs, headerSize));

  return res;
}

bool MACFileIO::isWritable() const { return base->isWritable(); }

}  // namespace encfs
