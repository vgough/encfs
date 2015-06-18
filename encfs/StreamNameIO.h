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

#ifndef _StreamNameIO_incl_
#define _StreamNameIO_incl_

#include <memory>
#include <stdint.h>

#include "CipherKey.h"
#include "Interface.h"
#include "NameIO.h"

namespace encfs {

class Cipher;

class StreamNameIO : public NameIO {
 public:
  static Interface CurrentInterface();

  StreamNameIO(const Interface &iface, const std::shared_ptr<Cipher> &cipher,
               const CipherKey &key);
  virtual ~StreamNameIO();

  virtual Interface interface() const;

  virtual int maxEncodedNameLen(int plaintextNameLen) const;
  virtual int maxDecodedNameLen(int encodedNameLen) const;

  // hack to help with static builds
  static bool Enabled();

 protected:
  virtual int encodeName(const char *plaintextName, int length, uint64_t *iv,
                         char *encodedName, int bufferLength) const;
  virtual int decodeName(const char *encodedName, int length, uint64_t *iv,
                         char *plaintextName, int bufferLength) const;

 private:
  int _interface;
  std::shared_ptr<Cipher> _cipher;
  CipherKey _key;
};

}  // namespace encfs

#endif
