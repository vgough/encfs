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

#include "NullNameIO.h"

#include <cstring>
#include <memory>

#include "CipherKey.h"
#include "Error.h"
#include "NameIO.h"

namespace encfs {

class Cipher;

static std::shared_ptr<NameIO> NewNNIO(const Interface &,
                                       const std::shared_ptr<Cipher> &,
                                       const CipherKey &) {
  return std::shared_ptr<NameIO>(new NullNameIO());
}

static Interface NNIOIface("nameio/null", 1, 0, 0);
static bool NullNameIO_registered =
    NameIO::Register("Null", "No encryption of filenames", NNIOIface, NewNNIO);

NullNameIO::NullNameIO() {}

NullNameIO::~NullNameIO() {}

Interface NullNameIO::interface() const { return NNIOIface; }

Interface NullNameIO::CurrentInterface() { return NNIOIface; }

int NullNameIO::maxEncodedNameLen(int plaintextNameLen) const {
  return plaintextNameLen;
}

int NullNameIO::maxDecodedNameLen(int encodedNameLen) const {
  return encodedNameLen;
}

int NullNameIO::encodeName(const char *plaintextName, int length, uint64_t *iv,
                           char *encodedName, int bufferLength) const {
  (void)iv;

  rAssert(length <= bufferLength);
  memcpy(encodedName, plaintextName, length);

  return length;
}

int NullNameIO::decodeName(const char *encodedName, int length, uint64_t *iv,
                           char *plaintextName, int bufferLength) const {
  (void)iv;

  rAssert(length <= bufferLength);
  memcpy(plaintextName, encodedName, length);

  return length;
}

bool NullNameIO::Enabled() { return true; }

}  // namespace encfs
