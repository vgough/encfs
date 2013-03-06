
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

#include "cipher/botan.h"
#include "base/config.h"

#include <glog/logging.h>
#include <botan/botan.h>

#include "base/Error.h"
#include "base/Mutex.h"
#include "base/Range.h"

#include "cipher/BlockCipher.h"
#include "cipher/MAC.h"
#include "cipher/MemoryPool.h"
#include "cipher/PBKDF.h"
#include "cipher/StreamCipher.h"

#include <string>

using namespace Botan;

namespace encfs {
namespace botan {

class PbkdfPkcs5Hmac : public PBKDF {
  Botan::PBKDF* pbkdf_;

 public:
  PbkdfPkcs5Hmac(Botan::PBKDF* pbkdf) : pbkdf_(pbkdf) {}
  virtual ~PbkdfPkcs5Hmac() {
      delete pbkdf_;
  }

  virtual bool makeKey(const char *password, int passwordLength,
                       const byte *salt, int saltLength,
                       int numIterations,
                       CipherKey *outKey) {
    if (pbkdf_ == NULL) {
      // TODO: error message
      return false;
    }

    std::string pass;
    pass.assign(password, passwordLength);
    OctetString key = pbkdf_->derive_key(outKey->size(),
                                        pass,
                                        salt, saltLength,
                                        numIterations);
    memcpy(outKey->data(), key.begin(), outKey->size());
    return true;
  }

  virtual CipherKey randomKey(int length) {
    CipherKey key(length);
    rng.randomize(key.data(), key.size());
    return key;
  }

  virtual bool pseudoRandom(byte *out, int length) {
    rng.randomize(out, length);
    return true;
  }

  AutoSeeded_RNG rng;
};
   
class PbkdfPkcs5HmacSha1 : public PbkdfPkcs5Hmac {
 public:
 PbkdfPkcs5HmacSha1() 
     : PbkdfPkcs5Hmac( get_pbkdf("PBKDF2(SHA-1)")) { }
 ~PbkdfPkcs5HmacSha1() {}

  static Properties GetProperties() {
    Properties props;
    props.mode = NAME_PBKDF2_HMAC_SHA1;
    props.library = "Botan";
    return props;
  }
};
REGISTER_CLASS(PbkdfPkcs5HmacSha1, PBKDF);

class PbkdfPkcs5HmacSha256 : public PbkdfPkcs5Hmac {
 public:
 PbkdfPkcs5HmacSha256() 
     : PbkdfPkcs5Hmac( get_pbkdf("PBKDF2(SHA-256)")) { }
 ~PbkdfPkcs5HmacSha256() {}

  static Properties GetProperties() {
    Properties props;
    props.mode = NAME_PBKDF2_HMAC_SHA256;
    props.library = "Botan";
    return props;
  }
};
REGISTER_CLASS(PbkdfPkcs5HmacSha256, PBKDF);



}  // namespace botan

static Botan::LibraryInitializer* initializer;

void Botan_init(bool threaded) {
  if (threaded) {
    initializer = new Botan::LibraryInitializer("thread_safe=true");
  } else {
    initializer = new Botan::LibraryInitializer();
  }
}

void Botan_shutdown() {
  delete initializer;
  initializer = NULL;
}

void Botan_registerCiphers() {
  // Just a reference to ensure static initializers are linked.
}

}  // namespace encfs

