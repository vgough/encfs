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

#include "base/base64.h"
#include "base/Error.h"
#include "base/i18n.h"
#include "cipher/CipherV1.h"
#include "fs/StreamNameIO.h"

#include <glog/logging.h>

#include <cstring>
#include <string>
#include <vector>

namespace encfs {

using std::string;
using std::vector;

static shared_ptr<NameIO> NewStreamNameIO(const Interface &iface,
                                          const shared_ptr<CipherV1> &cipher) {
  return shared_ptr<NameIO>(new StreamNameIO(iface, cipher));
}

static bool StreamIO_registered = NameIO::Register(
    "Stream",
    gettext_noop("Stream encoding, keeps filenames as short as possible"),
    StreamNameIO::CurrentInterface(), NewStreamNameIO, true);

/*
    - Version 0.1 is for EncFS 0.x support.  The difference to 1.0 is that 0.x
      stores the file checksums at the end of the encoded name, where 1.0
      stores them at the beginning.

    - Version 1.0 is the basic stream encoding mode used since the beginning of
      EncFS.  There is a slight difference in filename encodings from EncFS 0.x
      to 1.0.x.  This implements just the 1.0.x method.

    - Version 1.1 adds support for IV chaining.  This is transparently
      backward compatible, since older filesystems do not use IV chaining.

    - Version 2.0 uses full 64 bit IV during IV chaining mode.  Prior versions
      used only the 16 bit output from MAC_16.  This reduces the theoretical
      possibility (unlikely to make any difference in practice) of two files
      with the same name in different directories ending up with the same
      encrypted name.  Added because there is no good reason to chop to 16
      bits.

    - Version 2.1 adds support for version 0 for EncFS 0.x compatibility.

    - Version 3.0 drops Encfs 0.x support.
*/
Interface StreamNameIO::CurrentInterface() {
  // implements support for version 3, 2, and 1.
  return makeInterface("nameio/stream", 3, 0, 2);
}

StreamNameIO::StreamNameIO(const Interface &iface,
                           const shared_ptr<CipherV1> &cipher)
    : _interface(iface.major()), _cipher(cipher) {}

StreamNameIO::~StreamNameIO() {}

Interface StreamNameIO::interface() const { return CurrentInterface(); }

int StreamNameIO::maxEncodedNameLen(int plaintextStreamLen) const {
  int encodedStreamLen = 2 + plaintextStreamLen;
  return B256ToB64Bytes(encodedStreamLen);
}

int StreamNameIO::maxDecodedNameLen(int encodedStreamLen) const {
  int decLen256 = B64ToB256Bytes(encodedStreamLen);
  return decLen256 - 2;
}

string StreamNameIO::encodeName(const string &plaintextName,
                                uint64_t *iv) const {
  uint64_t tmpIV = 0;
  int length = plaintextName.length();
  if (iv && _interface >= 2) tmpIV = *iv;

  unsigned int mac = _cipher->reduceMac16(_cipher->MAC_64(
      reinterpret_cast<const byte *>(plaintextName.data()), length, iv));
  tmpIV ^= (uint64_t)mac;

  int encodedStreamLen = length + 2;
  int encLen64 = B256ToB64Bytes(encodedStreamLen);

  // add on checksum bytes
  vector<byte> encoded(encLen64);
  encoded[0] = static_cast<byte>((mac >> 8) & 0xff);
  encoded[1] = static_cast<byte>((mac) & 0xff);

  // stream encode the plaintext bytes
  memcpy(&encoded[2], plaintextName.data(), length);
  _cipher->streamEncode(&encoded[2], length, tmpIV);

  // convert the entire thing to base 64 ascii..
  changeBase2Inline(encoded.data(), encodedStreamLen, 8, 6, true);
  B64ToAscii(encoded.data(), encLen64);

  return string(encoded.begin(), encoded.end());
}

string StreamNameIO::decodeName(const string &encodedName,
                                uint64_t *iv) const {
  int length = encodedName.length();
  rAssert(length > 2);
  int decLen256 = B64ToB256Bytes(length);
  int decodedStreamLen = decLen256 - 2;

  if (decodedStreamLen <= 0) throw Error("Filename too small to decode");

  vector<byte> tmpBuf(length, 0);

  // decode into tmpBuf, because this step produces more data then we can fit
  // into the result buffer..
  memcpy(tmpBuf.data(), encodedName.data(), length);
  AsciiToB64(tmpBuf.data(), length);
  changeBase2Inline(tmpBuf.data(), length, 6, 8, false);

  // pull out the checksum value which is used as an initialization vector
  uint64_t tmpIV = 0;
  unsigned int mac = ((unsigned int)tmpBuf[0]) << 8 | ((unsigned int)tmpBuf[1]);

  // version 2 adds support for IV chaining..
  if (iv && _interface >= 2) tmpIV = *iv;

  tmpIV ^= (uint64_t)mac;
  _cipher->streamDecode(&tmpBuf.at(2), decodedStreamLen, tmpIV);

  // compute MAC to check with stored value
  unsigned int mac2 = _cipher->reduceMac16(
      _cipher->MAC_64(&tmpBuf.at(2), decodedStreamLen, iv));

  if (mac2 != mac) {
    VLOG(1) << "checksum mismatch: expected " << mac << ", got " << mac2
            << "on decode of " << decodedStreamLen << " bytes";
    throw Error("checksum mismatch in filename decode");
  }

  return string(reinterpret_cast<char*>(&tmpBuf.at(2)), decodedStreamLen);
}

bool StreamNameIO::Enabled() { return true; }

}  // namespace encfs
