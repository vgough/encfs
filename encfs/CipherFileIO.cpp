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

#include "CipherFileIO.h"

#include "easylogging++.h"
#include <cerrno>
#include <cinttypes>
#include <cstring>
#include <fcntl.h>
#include <memory>
#include <openssl/sha.h>
#include <sys/stat.h>
#include <utility>

#include "BlockFileIO.h"
#include "Cipher.h"
#include "CipherKey.h"
#include "Error.h"
#include "FileIO.h"

namespace encfs {

/*
    - Version 2:0 adds support for a per-file initialization vector with a
      fixed 8 byte header.  The headers are enabled globally within a
      filesystem at the filesystem configuration level.
      When headers are disabled, 2:0 is compatible with version 1:0.
*/
static Interface CipherFileIO_iface("FileIO/Cipher", 2, 0, 1);

const int HEADER_SIZE = 8;  // 64 bit initialization vector..

CipherFileIO::CipherFileIO(std::shared_ptr<FileIO> _base,
                           const FSConfigPtr &cfg)
    : BlockFileIO(cfg->config->blockSize, cfg),
      base(std::move(_base)),
      haveHeader(cfg->config->uniqueIV),
      externalIV(0),
      fileIV(0),
      lastFlags(0) {
  fsConfig = cfg;
  cipher = cfg->cipher;
  key = cfg->key;

  CHECK_EQ(fsConfig->config->blockSize % fsConfig->cipher->cipherBlockSize(), 0)
      << "FS block size must be multiple of cipher block size";
}

CipherFileIO::~CipherFileIO() = default;

Interface CipherFileIO::interface() const { return CipherFileIO_iface; }

int CipherFileIO::open(int flags) {
  int res = base->open(flags);

  if (res >= 0) {
    lastFlags = flags;
  }

  return res;
}

void CipherFileIO::setFileName(const char *fileName) {
  base->setFileName(fileName);
}

const char *CipherFileIO::getFileName() const { return base->getFileName(); }

bool CipherFileIO::setIV(uint64_t iv) {
  VLOG(1) << "in setIV, current IV = " << externalIV << ", new IV = " << iv
          << ", fileIV = " << fileIV;
  if (externalIV == 0) {
    // we're just being told about which IV to use.  since we haven't
    // initialized the fileIV, there is no need to just yet..
    externalIV = iv;
    if (fileIV != 0) {
      RLOG(WARNING) << "fileIV initialized before externalIV: " << fileIV
                    << ", " << externalIV;
    }
  } else if (haveHeader) {
    // we have an old IV, and now a new IV, so we need to update the fileIV
    // on disk.
    // ensure the file is open for read/write..
    int newFlags = lastFlags | O_RDWR;
    int res = base->open(newFlags);
    if (res < 0) {
      if (res == -EISDIR) {
        // duh -- there are no file headers for directories!
        externalIV = iv;
        return base->setIV(iv);
      }
      VLOG(1) << "setIV failed to re-open for write";
      return false;
    }
    if (fileIV == 0) {
      if (initHeader() < 0) {
        return false;
      }
    }

    uint64_t oldIV = externalIV;
    externalIV = iv;
    if (!writeHeader()) {
      externalIV = oldIV;
      return false;
    }
  }

  return base->setIV(iv);
}

/**
 * Get file attributes (FUSE-speak for "stat()") for an upper file
 * Upper file   = file we present to the user via FUSE
 * Backing file = file that is actually on disk
 */
int CipherFileIO::getAttr(struct stat *stbuf) const {

  // stat() the backing file
  int res = base->getAttr(stbuf);

  // adjust size if we have a file header
  if ((res == 0) && haveHeader && S_ISREG(stbuf->st_mode) &&
      (stbuf->st_size > 0)) {
    if (!fsConfig->reverseEncryption) {
      /* In normal mode, the upper file (plaintext) is smaller
       * than the backing ciphertext file */
      rAssert(stbuf->st_size >= HEADER_SIZE);
      stbuf->st_size -= HEADER_SIZE;
    } else {
      /* In reverse mode, the upper file (ciphertext) is larger than
       * the backing plaintext file */
      stbuf->st_size += HEADER_SIZE;
    }
  }

  return res;
}

/**
 * Get the size for an upper file
 * See getAttr() for an explaination of the reverse handling
 */
off_t CipherFileIO::getSize() const {
  off_t size = base->getSize();
  // No check on S_ISREG here -- don't call getSize over getAttr unless this
  // is a normal file!
  if (haveHeader && size > 0) {
    if (!fsConfig->reverseEncryption) {
      rAssert(size >= HEADER_SIZE);
      size -= HEADER_SIZE;
    } else {
      size += HEADER_SIZE;
    }
  }
  return size;
}

int CipherFileIO::initHeader() {
  // check if the file has a header, and read it if it does..  Otherwise,
  // create one.
  off_t rawSize = base->getSize();
  if (rawSize >= HEADER_SIZE) {
    VLOG(1) << "reading existing header, rawSize = " << rawSize;
    // has a header.. read it
    unsigned char buf[8] = {0};

    IORequest req;
    req.offset = 0;
    req.data = buf;
    req.dataLen = 8;
    ssize_t readSize = base->read(req);
    if (readSize < 0) {
      return readSize;
    }

    if (!cipher->streamDecode(buf, sizeof(buf), externalIV, key)) {
      return -EBADMSG;
    }

    fileIV = 0;
    for (int i = 0; i < 8; ++i) {
      fileIV = (fileIV << 8) | (uint64_t)buf[i];
    }

    rAssert(fileIV != 0);  // 0 is never used..
  } else {
    VLOG(1) << "creating new file IV header";

    unsigned char buf[8] = {0};
    do {
      if (!cipher->randomize(buf, 8, false)) {
        RLOG(ERROR) << "Unable to generate a random file IV";
        return -EBADMSG;
      }

      fileIV = 0;
      for (int i = 0; i < 8; ++i) {
        fileIV = (fileIV << 8) | (uint64_t)buf[i];
      }

      if (fileIV == 0) {
        RLOG(WARNING) << "Unexpected result: randomize returned 8 null bytes!";
      }
    } while (fileIV == 0);  // don't accept 0 as an option..

    if (base->isWritable()) {
      if (!cipher->streamEncode(buf, sizeof(buf), externalIV, key)) {
        return -EBADMSG;
      }

      IORequest req;
      req.offset = 0;
      req.data = buf;
      req.dataLen = 8;

      ssize_t writeSize = base->write(req);
      if (writeSize < 0) {
        return writeSize;
      }
    } else {
      VLOG(1) << "base not writable, IV not written..";
    }
  }
  VLOG(1) << "initHeader finished, fileIV = " << fileIV;
  return 0;
}

bool CipherFileIO::writeHeader() {
  if (fileIV == 0) {
    RLOG(ERROR) << "Internal error: fileIV == 0 in writeHeader!!!";
  }
  VLOG(1) << "writing fileIV " << fileIV;

  unsigned char buf[8] = {0};
  for (int i = 0; i < 8; ++i) {
    buf[sizeof(buf) - 1 - i] = (unsigned char)(fileIV & 0xff);
    fileIV >>= 8;
  }

  if (!cipher->streamEncode(buf, sizeof(buf), externalIV, key)) {
    return false;
  }

  IORequest req;
  req.offset = 0;
  req.data = buf;
  req.dataLen = 8;

  return (base->write(req) >= 0);
}

/**
 * Generate the file IV header bytes for reverse mode
 * (truncated SHA1 hash of the inode number)
 *
 * The kernel guarantees that the inode number is unique for one file
 * system. SHA1 spreads out the values over the whole 64-bit space.
 * Without this step, the XOR with the block number (see readOneBlock)
 * may lead to duplicate IVs.
 * SSL_Cipher::setIVec does an additional HMAC before using
 * the IV. This guarantees unpredictability and prevents watermarking
 * attacks.
 */
int CipherFileIO::generateReverseHeader(unsigned char *headerBuf) {

  struct stat stbuf;
  int res = getAttr(&stbuf);
  rAssert(res == 0);
  ino_t ino = stbuf.st_ino;
  rAssert(ino != 0);

  VLOG(1) << "generating reverse file IV header from ino=" << ino;

  // Serialize the inode number into inoBuf
  unsigned char inoBuf[sizeof(ino_t)];
  for (unsigned int i = 0; i < sizeof(ino_t); ++i) {
    inoBuf[i] = (unsigned char)(ino & 0xff);
    ino >>= 8;
  }

  /* Take the SHA1 hash of the inode number so the values are spread out
   * over the whole 64-bit space. Otherwise, the XOR with the block number
   * may lead to duplicate IVs (see readOneBlock) */
  unsigned char md[20];
  SHA1(inoBuf, sizeof(ino), md);
  rAssert(HEADER_SIZE <= 20);
  memcpy(headerBuf, md, HEADER_SIZE);

  // Save the IV in fileIV for internal use
  fileIV = 0;
  for (int i = 0; i < HEADER_SIZE; ++i) {
    fileIV = (fileIV << 8) | (uint64_t)headerBuf[i];
  }

  VLOG(1) << "fileIV=" << fileIV;

  // Encrypt externally-visible header
  if (!cipher->streamEncode(headerBuf, HEADER_SIZE, externalIV, key)) {
    return -EBADMSG;
  }
  return 0;
}

/**
 * Read block from backing ciphertext file, decrypt it (normal mode)
 * or
 * Read block from backing plaintext file, then encrypt it (reverse mode)
 */
ssize_t CipherFileIO::readOneBlock(const IORequest &req) const {
  int bs = blockSize();
  off_t blockNum = req.offset / bs;

  IORequest tmpReq = req;

  // adjust offset if we have a file header
  if (haveHeader && !fsConfig->reverseEncryption) {
    tmpReq.offset += HEADER_SIZE;
  }
  ssize_t readSize = base->read(tmpReq);

  bool ok;
  if (readSize > 0) {
    if (haveHeader && fileIV == 0) {
      int res = const_cast<CipherFileIO *>(this)->initHeader();
      if (res < 0) {
        return res;
      }
    }

    if (readSize != bs) {
      VLOG(1) << "streamRead(data, " << readSize << ", IV)";
      ok = streamRead(tmpReq.data, (int)readSize,
                      blockNum ^ fileIV);  // cast works because we work on a
                                           // block and blocksize fit an int
    } else {
      ok = blockRead(tmpReq.data, (int)readSize,
                     blockNum ^ fileIV);  // cast works because we work on a
                                          // block and blocksize fit an int
    }

    if (!ok) {
      VLOG(1) << "decodeBlock failed for block " << blockNum << ", size "
              << readSize;
      readSize = -EBADMSG;
    }
  } else if (readSize == 0) {
    VLOG(1) << "readSize zero for offset " << req.offset;
  }

  return readSize;
}

ssize_t CipherFileIO::writeOneBlock(const IORequest &req) {

  if (haveHeader && fsConfig->reverseEncryption) {
    VLOG(1)
        << "writing to a reverse mount with per-file IVs is not implemented";
    return -EPERM;
  }

  unsigned int bs = blockSize();
  off_t blockNum = req.offset / bs;

  if (haveHeader && fileIV == 0) {
    int res = initHeader();
    if (res < 0) {
      return res;
    }
  }

  bool ok;
  if (req.dataLen != bs) {
    ok = streamWrite(req.data, (int)req.dataLen,
                     blockNum ^ fileIV);  // cast works because we work on a
                                          // block and blocksize fit an int
  } else {
    ok = blockWrite(req.data, (int)req.dataLen,
                    blockNum ^ fileIV);  // cast works because we work on a
                                         // block and blocksize fit an int
  }

  ssize_t res = 0;
  if (ok) {
    if (haveHeader) {
      IORequest tmpReq = req;
      tmpReq.offset += HEADER_SIZE;
      res = base->write(tmpReq);
    } else {
      res = base->write(req);
    }
  } else {
    VLOG(1) << "encodeBlock failed for block " << blockNum << ", size "
            << req.dataLen;
    res = -EBADMSG;
  }
  return res;
}

bool CipherFileIO::blockWrite(unsigned char *buf, int size,
                              uint64_t _iv64) const {
  VLOG(1) << "Called blockWrite";
  if (!fsConfig->reverseEncryption) {
    return cipher->blockEncode(buf, size, _iv64, key);
  }
  return cipher->blockDecode(buf, size, _iv64, key);
}

bool CipherFileIO::streamWrite(unsigned char *buf, int size,
                               uint64_t _iv64) const {
  VLOG(1) << "Called streamWrite";
  if (!fsConfig->reverseEncryption) {
    return cipher->streamEncode(buf, size, _iv64, key);
  }
  return cipher->streamDecode(buf, size, _iv64, key);
}

bool CipherFileIO::blockRead(unsigned char *buf, int size,
                             uint64_t _iv64) const {
  if (fsConfig->reverseEncryption) {
    return cipher->blockEncode(buf, size, _iv64, key);
  }
  if (_allowHoles) {
    // special case - leave all 0's alone
    for (int i = 0; i < size; ++i) {
      if (buf[i] != 0) {
        return cipher->blockDecode(buf, size, _iv64, key);
      }
    }

    return true;
  }
  return cipher->blockDecode(buf, size, _iv64, key);
}

bool CipherFileIO::streamRead(unsigned char *buf, int size,
                              uint64_t _iv64) const {
  if (fsConfig->reverseEncryption) {
    return cipher->streamEncode(buf, size, _iv64, key);
  }
  return cipher->streamDecode(buf, size, _iv64, key);
}

int CipherFileIO::truncate(off_t size) {
  int res = 0;
  int reopen = 0;
  // well, we will truncate, so we need a write access to the file
  if (!base->isWritable()) {
    int newFlags = lastFlags | O_RDWR;
    int res = base->open(newFlags);
    if (res < 0) {
      VLOG(1) << "truncate failed to re-open for write";
      base->open(lastFlags);
      return res;
    }
    reopen = 1;
  }
  if (!haveHeader) {
    res = BlockFileIO::truncateBase(size, base.get());
  } else {
    if (0 == fileIV) {
      // empty file.. create the header..
      res = initHeader();
    }
    // can't let BlockFileIO call base->truncate(), since it would be using
    // the wrong size..
    if (res == 0) {
      res = BlockFileIO::truncateBase(size, nullptr);
    }
    if (res == 0) {
      res = base->truncate(size + HEADER_SIZE);
    }
  }
  if (reopen == 1) {
    reopen = base->open(lastFlags);
    if (res < 0) {
      res = reopen;
    }
  }
  return res;
}

/**
 * Handle reads for reverse mode with uniqueIV
 */
ssize_t CipherFileIO::read(const IORequest &origReq) const {

  /* if reverse mode is not active with uniqueIV,
   * the read request is handled by the base class */
  if (!(fsConfig->reverseEncryption && haveHeader)) {
    VLOG(1) << "relaying request to base class: offset=" << origReq.offset
            << ", dataLen=" << origReq.dataLen;
    return BlockFileIO::read(origReq);
  }

  VLOG(1) << "handling reverse unique IV read: offset=" << origReq.offset
          << ", dataLen=" << origReq.dataLen;

  // generate the file IV header
  // this is needed in any case - without IV the file cannot be decoded
  unsigned char headerBuf[HEADER_SIZE];
  int res = const_cast<CipherFileIO *>(this)->generateReverseHeader(headerBuf);
  if (res < 0) {
    return res;
  }

  // Copy the request so we can modify it without affecting the caller
  IORequest req = origReq;

  /* An offset x in the ciphertext file maps to x-8 in the
   * plain text file. Values below zero are the header. */
  req.offset -= HEADER_SIZE;

  int headerBytes = 0;  // number of header bytes to add

  /* The request contains (a part of) the header, so we prefix that part
   * to the data. */
  if (req.offset < 0) {
    headerBytes = -req.offset;
    if (req.dataLen < (size_t)headerBytes) {
      headerBytes = req.dataLen;  // only up to the number of bytes requested
    }
    VLOG(1) << "Adding " << headerBytes << " header bytes";

    // copy the header bytes into the data
    int headerOffset =
        HEADER_SIZE - headerBytes;  // can be int as HEADER_SIZE is int
    memcpy(req.data, &headerBuf[headerOffset], headerBytes);

    // the read does not want data beyond the header
    if ((size_t)headerBytes == req.dataLen) {
      return headerBytes;
    }

    /* The rest of the request will be read from the backing file.
     * As we have already generated n=headerBytes bytes, the request is
     * shifted by headerBytes */
    req.offset += headerBytes;
    rAssert(req.offset == 0);
    req.data += headerBytes;
    req.dataLen -= headerBytes;
  }

  // read the payload
  ssize_t readBytes = BlockFileIO::read(req);
  VLOG(1) << "read " << readBytes << " bytes from backing file";
  if (readBytes < 0) {
    return readBytes;  // Return error code
  }
  ssize_t sum =
      headerBytes + readBytes;  // could be size_t, but as we return ssize_t...
  VLOG(1) << "returning sum=" << sum;
  return sum;
}

bool CipherFileIO::isWritable() const { return base->isWritable(); }

}  // namespace encfs
