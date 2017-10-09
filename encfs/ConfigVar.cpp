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

#include "ConfigVar.h"

#include "easylogging++.h"
#include <cstring>

#include "Error.h"

namespace encfs {

#ifndef MIN
inline int MIN(int a, int b) { return (a < b) ? a : b; }
#endif

ConfigVar::ConfigVar() : pd(new ConfigVarData) { pd->offset = 0; }

ConfigVar::ConfigVar(const std::string &buf) : pd(new ConfigVarData) {
  pd->buffer = buf;
  pd->offset = 0;
}

ConfigVar::ConfigVar(const ConfigVar &src) { pd = src.pd; }

ConfigVar::~ConfigVar() { pd.reset(); }

ConfigVar &ConfigVar::operator=(const ConfigVar &src) {
  if (src.pd == pd) {
    return *this;
  }
  pd = src.pd;

  return *this;
}

void ConfigVar::resetOffset() { pd->offset = 0; }

int ConfigVar::read(unsigned char *buffer_, int bytes) const {
  int toCopy = MIN(bytes, pd->buffer.size() - pd->offset);

  if (toCopy > 0) {
    memcpy(buffer_, pd->buffer.data() + pd->offset, toCopy);
  }

  pd->offset += toCopy;

  return toCopy;
}

int ConfigVar::write(const unsigned char *data, int bytes) {
  if (pd->buffer.size() == (unsigned int)pd->offset) {
    pd->buffer.append((const char *)data, bytes);
  } else {
    pd->buffer.insert(pd->offset, (const char *)data, bytes);
  }

  pd->offset += bytes;

  return bytes;
}

int ConfigVar::size() const { return pd->buffer.size(); }

const char *ConfigVar::buffer() const { return pd->buffer.data(); }

int ConfigVar::at() const { return pd->offset; }

void ConfigVar::writeString(const char *data, int bytes) {
  writeInt(bytes);
  write((const unsigned char *)data, bytes);
}

// convert integer to BER encoded integer
void ConfigVar::writeInt(int val) {
  // we can represent 7 bits per char output, so a 32bit number may take up
  // to 5 bytes.
  // first byte:    0x0000007f                                   0111,1111
  // second byte:   0x00003f80                         0011,1111 1000,0000
  // third byte:    0x001fb000     0000,0000 0001,1111 1100,0000 0000,0000
  // fourth byte:   0x0fe00000     0000,1111 1110,0000
  // fifth byte:    0xf0000000     1111,0000
  unsigned char digit[5];

  digit[4] = (unsigned char)((val & 0x0000007f));
  digit[3] = 0x80 | (unsigned char)((val & 0x00003f80) >> 7);
  digit[2] = 0x80 | (unsigned char)((val & 0x001fc000) >> 14);
  digit[1] = 0x80 | (unsigned char)((val & 0x0fe00000) >> 21);
  digit[0] = 0x80 | (unsigned char)((val & 0xf0000000) >> 28);

  // find the starting point - we only need to output starting at the most
  // significant non-zero digit..
  int start = 0;
  while (digit[start] == 0x80) {
    ++start;
  }

  write(digit + start, 5 - start);
}

int ConfigVar::readInt() const {
  const auto *buf = (const unsigned char *)buffer();
  int bytes = this->size();
  int offset = at();
  int value = 0;
  bool highBitSet;

  rAssert(offset < bytes);

  do {
    unsigned char tmp = buf[offset++];
    highBitSet = ((tmp & 0x80) != 0);

    value = (value << 7) | (int)(tmp & 0x7f);
  } while (highBitSet && offset < bytes);

  pd->offset = offset;

  // should never end up with a negative number..
  rAssert(value >= 0);

  return value;
}

int ConfigVar::readInt(int defaultValue) const {
  int bytes = this->size();
  int offset = at();

  if (offset >= bytes) {
    return defaultValue;
  }
  return readInt();
}

bool ConfigVar::readBool(bool defaultValue) const {
  int tmp = readInt(defaultValue ? 1 : 0);
  return (tmp != 0);
}

ConfigVar &operator<<(ConfigVar &src, bool value) {
  src.writeInt(value ? 1 : 0);
  return src;
}

ConfigVar &operator<<(ConfigVar &src, int var) {
  src.writeInt(var);
  return src;
}

ConfigVar &operator<<(ConfigVar &src, const std::string &str) {
  src.writeString(str.data(), str.length());
  return src;
}

const ConfigVar &operator>>(const ConfigVar &src, bool &result) {
  int tmp = src.readInt();
  result = (tmp != 0);
  return src;
}

const ConfigVar &operator>>(const ConfigVar &src, int &result) {
  result = src.readInt();
  return src;
}

const ConfigVar &operator>>(const ConfigVar &src, std::string &result) {
  int length = src.readInt();
  // rAssert(length > 0);

  int readLen;

  unsigned char tmpBuf[32] = {};
  if (length > (int)sizeof(tmpBuf)) {
    auto *ptr = new unsigned char[length];
    readLen = src.read(ptr, length);
    result.assign((char *)ptr, length);
    delete[] ptr;
  } else {
    readLen = src.read(tmpBuf, length);
    result.assign((char *)tmpBuf, length);
  }

  if (readLen != length) {
    VLOG(1) << "string encoded as size " << length << " bytes, read "
            << readLen;
  }
  rAssert(readLen == length);

  return src;
}

}  // namespace encfs
