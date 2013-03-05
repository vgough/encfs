
/*****************************************************************************
 * Author:   Valient Gough <vgough@pobox.com>
 *
 *****************************************************************************
 * Copyright (c) 2013 Valient Gough
 *
 * This program is free software: you can redistribute it and/or modify it under
 * the terms of the GNU Lesser General Public License as published by the Free
 * Software Foundation, either version 3 of the License, or (at your option) any
 * later version.  
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE.  See the GNU Lesser General Public License for more
 * details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "cipher/NullCiphers.h"

#include "cipher/BlockCipher.h"
#include "cipher/StreamCipher.h"

namespace encfs {

class NullCipher : public BlockCipher {
 public:
  virtual ~NullCipher() {}

  virtual int blockSize() const {
    return 8;
  }

  virtual bool setKey(const CipherKey &key) {
    return true;
  }

  virtual bool encrypt(const byte *iv, const byte *in,
                       byte *out, int numBytes) {
    if (in != out)
      memcpy(out, in, numBytes);
    return true;
  }
  
  virtual bool decrypt(const byte *iv, const byte *in,
                       byte *out, int numBytes) {
    if (in != out)
      memcpy(out, in, numBytes);
    return true;
  }

  static Properties GetProperties() {
    Properties props;
    props.keySize = Range(0);
    props.cipher = "NullCipher";
    props.mode = "ECB";
    props.library = "internal";
    return props;
  }
};

REGISTER_CLASS(NullCipher, BlockCipher);
REGISTER_CLASS(NullCipher, StreamCipher);

void NullCiphers::registerCiphers() {
  // Nothing required. 
}

} //  namespace encfs

