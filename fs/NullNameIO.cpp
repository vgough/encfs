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
#include "cipher/CipherV1.h"
#include "fs/NullNameIO.h"

#include <cstring>
#include <string>

namespace encfs {

using std::string;

static shared_ptr<NameIO> NewNNIO(const Interface &,
                                  const shared_ptr<CipherV1> &) {
  return shared_ptr<NameIO>(new NullNameIO());
}

static Interface NNIOIface = makeInterface("nameio/null", 1, 0, 0);
static bool NullNameIO_registered = NameIO::Register(
    "Null", "No encryption of filenames", NNIOIface, NewNNIO, false);

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

string NullNameIO::encodeName(const string &plaintextName, uint64_t *iv) const {
  return plaintextName;
}

string NullNameIO::decodeName(const string &encodedName, uint64_t *iv) const {
  return encodedName;
}

bool NullNameIO::Enabled() { return true; }

}  // namespace encfs
