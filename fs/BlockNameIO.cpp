/*****************************************************************************
 * Author:   Valient Gough <vgough@pobox.com>
 *
 *****************************************************************************
 * Copyright (c) 2004-2011, Valient Gough
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

#include "fs/BlockNameIO.h"

#include "base/base64.h"
#include "base/Error.h"
#include "base/i18n.h"
#include "cipher/CipherV1.h"

#include <cstring>
#include <vector>

#include <glog/logging.h>

namespace encfs {

using std::string;
using std::vector;

static shared_ptr<NameIO> NewBlockNameIO(const Interface &iface,
                                         const shared_ptr<CipherV1> &cipher) {
  return shared_ptr<NameIO>(new BlockNameIO(iface, cipher, false));
}

static shared_ptr<NameIO> NewBlockNameIO32(const Interface &iface,
                                           const shared_ptr<CipherV1> &cipher) {
  return shared_ptr<NameIO>(new BlockNameIO(iface, cipher, true));
}

static bool BlockIO_registered = NameIO::Register(
    "Block",
    // description of block name encoding algorithm..
    // xgroup(setup)
    gettext_noop("Block encoding, hides file name size somewhat"),
    BlockNameIO::CurrentInterface(false), NewBlockNameIO, false);

static bool BlockIO32_registered = NameIO::Register(
    "Block32",
    // description of block name encoding algorithm..
    // xgroup(setup)
    gettext_noop(
        "Block encoding with base32 output for case-sensitive systems"),
    BlockNameIO::CurrentInterface(true), NewBlockNameIO32, false);

/*
    - Version 1.0 computed MAC over the filename, but not the padding bytes.
    This version was from pre-release 1.1, never publically released, so no
    backward compatibility necessary.

    - Version 2.0 includes padding bytes in MAC computation.  This way the MAC
    computation uses the same number of bytes regardless of the number of
    padding bytes.

    - Version 3.0 uses full 64 bit initialization vector during IV chaining.
    Prior versions used only the output from the MAC_16 call, giving a 1 in
    2^16 chance of the same name being produced.  Using the full 64 bit IV
    reduces to a 1 in 2^64 chance..

    - Version 4.0 adds support for base32, creating names better suited to
    case-insensitive filesystems (eg Mac).
 */
Interface BlockNameIO::CurrentInterface(bool caseSensitive) {
  // implement major version 4 plus support for prior versions
  if (caseSensitive)
    return makeInterface("nameio/block32", 4, 0, 2);
  else
    return makeInterface("nameio/block", 4, 0, 2);
}

BlockNameIO::BlockNameIO(const Interface &iface,
                         const shared_ptr<CipherV1> &cipher,
                         bool caseSensitiveEncoding)
    : _interface(iface.major()),
      _bs(cipher->cipherBlockSize()),
      _cipher(cipher),
      _caseSensitive(caseSensitiveEncoding) {
  rAssert(_bs < 128);
}

BlockNameIO::~BlockNameIO() {}

Interface BlockNameIO::interface() const {
  return CurrentInterface(_caseSensitive);
}

int BlockNameIO::maxEncodedNameLen(int plaintextNameLen) const {
  // number of blocks, rounded up.. Only an estimate at this point, err on
  // the size of too much space rather then too little.
  int numBlocks = (plaintextNameLen + _bs) / _bs;
  int encodedNameLen = numBlocks * _bs + 2;  // 2 checksum bytes
  if (_caseSensitive)
    return B256ToB32Bytes(encodedNameLen);
  else
    return B256ToB64Bytes(encodedNameLen);
}

int BlockNameIO::maxDecodedNameLen(int encodedNameLen) const {
  int decLen256 = _caseSensitive ? B32ToB256Bytes(encodedNameLen)
                                 : B64ToB256Bytes(encodedNameLen);
  return decLen256 - 2;  // 2 checksum bytes removed..
}

string BlockNameIO::encodeName(const string &plaintextName,
                               uint64_t *iv) const {
  int length = plaintextName.length();
  // Pad encryption buffer to block boundary..
  int padding = _bs - length % _bs;
  int encodedStreamLen = length + 2 + padding;
  int encLen = _caseSensitive ? B256ToB32Bytes(encodedStreamLen)
                              : B256ToB64Bytes(encodedStreamLen);

  vector<byte> tmpBuf(encLen);

  // copy the data into the encoding buffer..
  memcpy(tmpBuf.data() + 2, plaintextName.data(), length);
  memset(tmpBuf.data() + length + 2, (unsigned char)padding, padding);

  // store the IV before it is modified by the MAC call.
  uint64_t tmpIV = 0;
  if (iv && _interface >= 3) tmpIV = *iv;

  // include padding in MAC computation
  unsigned int mac = _cipher->reduceMac16(
      _cipher->MAC_64(tmpBuf.data() + 2, length + padding, iv));
  tmpIV ^= (uint64_t)mac;

  // add checksum bytes
  tmpBuf[0] = (mac >> 8) & 0xff;
  tmpBuf[1] = (mac) & 0xff;

  _cipher->blockEncode(tmpBuf.data() + 2, length + padding, tmpIV);

  // convert to base 32 or 64 ascii
  if (_caseSensitive) {
    changeBase2Inline(tmpBuf.data(), encodedStreamLen, 8, 5, true);
    B32ToAscii(tmpBuf.data(), encLen);
  } else {
    changeBase2Inline(tmpBuf.data(), encodedStreamLen, 8, 6, true);
    B64ToAscii(tmpBuf.data(), encLen);
  }

  return string(reinterpret_cast<char*>(tmpBuf.data()), encLen);
}

string BlockNameIO::decodeName(const string &encodedName, uint64_t *iv) const {
  int length = encodedName.length();
  int decLen256 =
      _caseSensitive ? B32ToB256Bytes(length) : B64ToB256Bytes(length);
  int decodedStreamLen = decLen256 - 2;

  // don't bother trying to decode files which are too small
  if (decodedStreamLen < _bs) throw Error("Filename too small to decode");

  vector<byte> tmpBuf(length, 0);
  memcpy(tmpBuf.data(), encodedName.data(), length);

  // decode into tmpBuf,
  if (_caseSensitive) {
    AsciiToB32(tmpBuf.data(), length);
    changeBase2Inline(tmpBuf.data(), length, 5, 8, false);
  } else {
    AsciiToB64(tmpBuf.data(), length);
    changeBase2Inline(tmpBuf.data(), length, 6, 8, false);
  }

  // pull out the header information
  unsigned int mac = ((unsigned int)tmpBuf[0]) << 8 |
                     ((unsigned int)tmpBuf[1]);

  uint64_t tmpIV = 0;
  if (iv && _interface >= 3) tmpIV = *iv;
  tmpIV ^= (uint64_t)mac;

  _cipher->blockDecode(&tmpBuf.at(2), decodedStreamLen, tmpIV);

  // find out true string length
  int padding = tmpBuf[2 + decodedStreamLen - 1];
  int finalSize = decodedStreamLen - padding;

  // might happen if there is an error decoding..
  if (padding > _bs || finalSize < 0) {
    VLOG(1) << "padding, _bx, finalSize = " << padding << ", " << _bs << ", "
            << finalSize;
    throw Error("invalid padding size");
  }

  // check the mac
  unsigned int mac2 = _cipher->reduceMac16(
      _cipher->MAC_64(&tmpBuf.at(2), decodedStreamLen, iv));

  if (mac2 != mac) {
    LOG(INFO) << "checksum mismatch: expected " << mac << ", got " << mac2
              << " on decode of " << finalSize << " bytes";
    throw Error("checksum mismatch in filename decode");
  }

  return string(reinterpret_cast<char*>(&tmpBuf.at(2)), finalSize);
}

bool BlockNameIO::Enabled() { return true; }

}  // namespace encfs
