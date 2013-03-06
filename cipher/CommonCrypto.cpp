
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

#include "cipher/CommonCrypto.h"

#include <glog/logging.h>

#include <CommonCrypto/CommonCryptor.h>
#include <CommonCrypto/CommonDigest.h>
#include <CommonCrypto/CommonHMAC.h>
#include <CommonCrypto/CommonKeyDerivation.h>

#include "base/config.h"
#include "cipher/BlockCipher.h"
#include "cipher/MAC.h"
#include "cipher/PBKDF.h"

#ifdef HAVE_SEC_RANDOM_H
#include <Security/SecRandom.h>
#endif

namespace encfs {
namespace commoncrypto {

class PbkdfPkcs5Hmac : public PBKDF {
  CCPseudoRandomAlgorithm prf_;
public:
  PbkdfPkcs5Hmac(CCPseudoRandomAlgorithm prf)
      : prf_(prf) {}
  virtual ~PbkdfPkcs5Hmac() {}
  
  virtual bool makeKey(const char *password, int passwordLength,
                       const byte *salt, int saltLength,
                       int numIterations,
                       CipherKey *outKey) {
    int ret = CCKeyDerivationPBKDF(kCCPBKDF2, password, passwordLength,
                                   salt, saltLength, prf_,
                                   numIterations,
                                   outKey->data(), outKey->size());
    if (ret != 0) {
      PLOG(ERROR) << "CCKeyDerivationPBKDF failed";
      return false;
    }
    return true;
  }

  virtual CipherKey randomKey(int length) {
    CipherKey key(length);
    if (length == 0) return key;
#ifdef HAVE_SEC_RANDOM_H
    if (SecRandomCopyBytes(kSecRandomDefault, key.size(), key.data()) < 0) {
      PLOG(ERROR) << "random key generation failure for length " << length;
      key.reset();
    }
#else
#error No random number generator provided.
#endif
    return key;
  }
  
  virtual bool pseudoRandom(byte *out, int length) {
    if (length == 0) return true;
#ifdef HAVE_SEC_RANDOM_H
    if (SecRandomCopyBytes(kSecRandomDefault, length, out) < 0) {
      PLOG(ERROR) << "random key generation failure for length " << length;
      return false;
    }
#else
#error No random number generator provided.
#endif
    return true;
  }
};

  
class PbkdfPkcs5HmacSha1CC : public PbkdfPkcs5Hmac {
public:
  PbkdfPkcs5HmacSha1CC() : PbkdfPkcs5Hmac(kCCPRFHmacAlgSHA1) {}
  ~PbkdfPkcs5HmacSha1CC() {}

  static Properties GetProperties() {
    Properties props;
    props.mode = NAME_PBKDF2_HMAC_SHA1;
    props.library = "CommonCrypto";
    return props;
  }
};
REGISTER_CLASS(PbkdfPkcs5HmacSha1CC, PBKDF);

class PbkdfPkcs5HmacSha256CC : public PbkdfPkcs5Hmac {
public:
  PbkdfPkcs5HmacSha256CC() : PbkdfPkcs5Hmac(kCCPRFHmacAlgSHA256) {}
  ~PbkdfPkcs5HmacSha256CC() {}

  static Properties GetProperties() {
    Properties props;
    props.mode = NAME_PBKDF2_HMAC_SHA256;
    props.library = "CommonCrypto";
    return props;
  }
};
REGISTER_CLASS(PbkdfPkcs5HmacSha256CC, PBKDF);

class CCCipher : public BlockCipher {
  CipherKey key;
  CCAlgorithm algorithm;
  CCMode mode;
 public:
  CCCipher() { }
  virtual ~CCCipher() { }

  bool rekey(const CipherKey &key, CCAlgorithm algorithm, CCMode mode) {
    this->key = key;
    this->algorithm = algorithm;
    this->mode = mode;
    return true;
  }

  virtual bool encrypt(const byte *iv, const byte *in, byte *out, int size) {
    CCCryptorRef cryptor;
    CCCryptorCreateWithMode(kCCEncrypt, mode, algorithm, 0, 
                            iv, key.data(), key.size(),
                            NULL, 0, 0, 0, &cryptor);
    size_t updateLength = 0;
    CCCryptorUpdate(cryptor, in, size, out, size, &updateLength);
    CCCryptorRelease(cryptor);
    return true;
  }
  
  virtual bool decrypt(const byte *iv, const byte *in, byte *out, int size) {
    CCCryptorRef cryptor;
    CCCryptorCreateWithMode(kCCDecrypt, mode, algorithm, 0, 
                            iv, key.data(), key.size(),
                            NULL, 0, 0, 0, &cryptor);
    size_t updateLength = 0;
    CCCryptorUpdate(cryptor, in, size, out, size, &updateLength);
    CCCryptorRelease(cryptor);
    return true;
  }
};

class BfCbc : public CCCipher {
 public:
  BfCbc() {}
  virtual ~BfCbc() {}

  virtual bool setKey(const CipherKey &key) {
    return CCCipher::rekey(key, kCCAlgorithmBlowfish, kCCModeCBC);
  }

  virtual int blockSize() const {
    return kCCBlockSizeBlowfish;
  }

  static Properties GetProperties() {
    return Properties(Range(128,256,32), "Blowfish", "CBC", "CommonCrypto");
  }
};
REGISTER_CLASS(BfCbc, BlockCipher);

class AesCbc : public CCCipher {
 public:
  AesCbc() {}
  virtual ~AesCbc() {}

  virtual bool setKey(const CipherKey &key) {
    return CCCipher::rekey(key, kCCAlgorithmAES128, kCCModeCBC);
  }
  
  virtual int blockSize() const {
    return kCCBlockSizeAES128;
  }
  
  static Properties GetProperties() {
    return Properties(Range(128,256,64), "AES", "CBC", "CommonCrypto");
  }
};
REGISTER_CLASS(AesCbc, BlockCipher);

class BfCfb : public CCCipher {
 public:
  BfCfb() {}
  virtual ~BfCfb() {}

  virtual bool setKey(const CipherKey &key) {
    return CCCipher::rekey(key, kCCAlgorithmBlowfish, kCCModeCFB);
  }

  virtual int blockSize() const { return 1; }

  static Properties GetProperties() {
    return Properties(Range(128,256,32), "Blowfish", "CFB", "CommonCrypto");
  }
};
REGISTER_CLASS(BfCfb, StreamCipher);

class AesCfb : public CCCipher {
 public:
  AesCfb() {}
  virtual ~AesCfb() {}

  virtual bool setKey(const CipherKey &key) {
    return CCCipher::rekey(key, kCCAlgorithmAES128, kCCModeCFB);
  }
 
  virtual int blockSize() const { return 1; }

  static Properties GetProperties() {
    return Properties(Range(128,256,64), "AES", "CFB", "CommonCrypto");
  }
};
REGISTER_CLASS(AesCfb, StreamCipher);

class Sha1HMac : public MAC {
 public:
  Sha1HMac() {}
  virtual ~Sha1HMac() {}

  virtual int outputSize() const {
    return CC_SHA1_DIGEST_LENGTH;
  }

  virtual bool setKey(const CipherKey &key) {
    this->key = key;
    return true;
  }

  virtual void init() {
    if (key.size() > 0) {
      CCHmacInit(&ctx, kCCHmacAlgSHA1, key.data(), key.size());
    } else {
      // CommonCrypto will segfault later on if a null key is passed, even if
      // key length is 0.
      CCHmacInit(&ctx, kCCHmacAlgSHA1, &ctx, 0);
    }
  }

  virtual bool update (const byte *in, int length) {
    CCHmacUpdate(&ctx, in, length);
    return true;
  }

  virtual bool write(byte *out) {
    CCHmacFinal(&ctx, out);
    return true;
  }

  static Properties GetProperties() {
    Properties props;
    props.blockSize = CC_SHA1_DIGEST_LENGTH;
    props.hashFunction = "SHA-1";
    props.mode = "HMAC";
    props.library = "CommonCrypto";
    return props;
  }

 private:
  CipherKey key;
  CCHmacContext ctx;
};
REGISTER_CLASS(Sha1HMac, MAC);

}  // namespace commoncrypto

void CommonCrypto::registerCiphers() {
}

}  //  namespace encfs
