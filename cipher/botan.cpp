
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
#include "base/shared_ptr.h"

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

#ifdef HAVE_VALGRIND_MEMCHECK_H
#include <valgrind/memcheck.h>
#endif

#include <string>

using namespace Botan;
using std::string;

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


class BotanBlockCipher : public BlockCipher {
  Keyed_Filter *encryption;  // Not owned.
  Keyed_Filter *decryption;  // Not owned.
  shared_ptr<Pipe> encryptor;
  shared_ptr<Pipe> decryptor;
 public:
  BotanBlockCipher() {}
  virtual ~BotanBlockCipher() {}

  bool rekey(const CipherKey& key, const string& cipherMode) {
    SymmetricKey bkey(key.data(), key.size());
    OctetString iv;
    encryption = Botan::get_cipher(cipherMode, bkey, iv, Botan::ENCRYPTION);
    decryption = Botan::get_cipher(cipherMode, bkey, iv, Botan::DECRYPTION);
    if (encryption == nullptr || decryption == nullptr) {
      return false;
    }
    encryptor.reset(new Pipe(encryption));
    decryptor.reset(new Pipe(decryption));
    return true;
  }

  virtual bool encrypt(const byte* iv, const byte* in, byte* out, int size) {
#ifdef HAVE_VALGRIND_MEMCHECK_H
    if (VALGRIND_CHECK_MEM_IS_ADDRESSABLE(in, size) != 0 ||
        VALGRIND_CHECK_MEM_IS_ADDRESSABLE(out, size) != 0 || 
        VALGRIND_CHECK_MEM_IS_ADDRESSABLE(iv, blockSize())) {
      return false;
    }
#endif
    encryption->set_iv(OctetString(iv, blockSize()));
    encryptor->process_msg(in, size);
    auto written = encryptor->read(out, size, Pipe::LAST_MESSAGE);
    LOG_IF(ERROR, (int)written != size) << "expected output size " << size
        << ", got " << written;
    LOG_IF(ERROR, encryptor->remaining() > 0) << "unread bytes in pipe: " 
        << encryptor->remaining();
    return true;
  }

  virtual bool decrypt(const byte* iv, const byte* in, byte* out, int size) {
#ifdef HAVE_VALGRIND_MEMCHECK_H
    if (VALGRIND_CHECK_MEM_IS_ADDRESSABLE(in, size) != 0 ||
        VALGRIND_CHECK_MEM_IS_ADDRESSABLE(out, size) != 0 ||
        VALGRIND_CHECK_MEM_IS_ADDRESSABLE(iv, blockSize())) {
      return false;
    }
#endif
    decryption->set_iv(OctetString(iv, blockSize()));
    decryptor->process_msg(in, size);
    auto written = decryptor->read(out, size, Pipe::LAST_MESSAGE);
    LOG_IF(ERROR, (int)written != size) << "expected output size " << size
        << ", got " << written;
    LOG_IF(ERROR, encryptor->remaining() > 0) << "unread bytes in pipe: " 
        << encryptor->remaining();
    return true;
  }
};

class BotanAesCbc : public BotanBlockCipher {
 public:
  BotanAesCbc() {}
  virtual ~BotanAesCbc() {}

  virtual bool setKey(const CipherKey& key) {
    std::ostringstream ss;
    ss << "AES-" << (key.size() * 8) << "/CBC/NoPadding";
    return rekey(key, ss.str());
  }

  virtual int blockSize() const {
    return 128 >> 3;
  }

  static Properties GetProperties() {
    return Properties(Range(128,256,64), "AES", "CBC", "Botan");
  }
};
REGISTER_CLASS(BotanAesCbc, BlockCipher);

class BotanAesCfb : public BotanBlockCipher {
 public:
  BotanAesCfb() {}
  virtual ~BotanAesCfb() {}

  virtual bool setKey(const CipherKey& key) {
    std::ostringstream ss;
    ss << "AES-" << (key.size() * 8) << "/CFB";
    return rekey(key, ss.str());
  }

  virtual int blockSize() const {
    return 128 >> 3;
  }

  static Properties GetProperties() {
    return Properties(Range(128,256,64), "AES", "CFB", "Botan");
  }
};
REGISTER_CLASS(BotanAesCfb, StreamCipher);

class BotanBlowfishCbc : public BotanBlockCipher {
 public:
  BotanBlowfishCbc() {}
  virtual ~BotanBlowfishCbc() {}

  virtual bool setKey(const CipherKey& key) {
    std::ostringstream ss;
    ss << "Blowfish" << "/CBC/NoPadding";
    return rekey(key, ss.str());
  }

  virtual int blockSize() const {
    return 64 >> 3;
  }

  static Properties GetProperties() {
    return Properties(Range(128,256,32), "Blowfish", "CBC", "Botan");
  }
};
REGISTER_CLASS(BotanBlowfishCbc, BlockCipher);

class BotanBlowfishCfb : public BotanBlockCipher {
 public:
  BotanBlowfishCfb() {}
  virtual ~BotanBlowfishCfb() {}

  virtual bool setKey(const CipherKey& key) {
    std::ostringstream ss;
    ss << "Blowfish" << "/CFB";
    return rekey(key, ss.str());
  }

  virtual int blockSize() const {
    return 64 >> 3;
  }

  static Properties GetProperties() {
    return Properties(Range(128,256,32), "Blowfish", "CFB", "Botan");
  }
};
REGISTER_CLASS(BotanBlowfishCfb, StreamCipher);


class Sha1HMac : public MAC {
  MessageAuthenticationCode *mac;

 public:
  Sha1HMac() : mac(Botan::get_mac("HMAC(SHA-1)")) {}
  virtual ~Sha1HMac() {
    delete mac;
  }

  virtual int outputSize() const {
    return mac->output_length();
  }

  virtual bool setKey(const CipherKey &key) {
    SymmetricKey bkey(key.data(), key.size());
    mac->set_key(bkey);
    return true;
  }

  virtual void init() {
  }

  virtual bool update(const byte *in, int length) {
    mac->update(in, length);
    return true;
  }

  virtual bool write(byte *out) {
#ifdef HAVE_VALGRIND_MEMCHECK_H
    if (VALGRIND_CHECK_MEM_IS_ADDRESSABLE(out, outputSize()) != 0) {
      return false;
    }
#endif
    mac->final(out);
    return true;
  }

  static Properties GetProperties() {
    Properties props;
    props.blockSize = 160 >> 3;
    props.hashFunction = "SHA-1";
    props.mode = "HMAC";
    props.library = "Botan";
    return props;
  }
};
REGISTER_CLASS(Sha1HMac, MAC);

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

