/*****************************************************************************
 * Author:   Valient Gough <vgough@pobox.com>
 *           danim7 (https://github.com/danim7)
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

#include "internal/easylogging++.h"
#include <cstring>
#include <pthread.h>
#include <string>
#include <sys/mman.h>
#include <sys/time.h>

#include "Cipher.h"
#include "Error.h"
#include "Interface.h"
#include "Mutex.h"
#include "Range.h"
#include "intl/gettext.h"
#include "GCrypt_Cipher.h"

using namespace std;

namespace encfs {

const int MAX_KEYLENGTH = 32;  // in bytes (256 bit)
const int MAX_IVLENGTH = 16;   // 128 bit (AES block size, Blowfish has 64)
const int KEY_CHECKSUM_BYTES = 4;

#ifndef MIN
inline int MIN(int a, int b) { return (a < b) ? a : b; }
#endif

/**
    This produces the same result as OpenSSL's EVP_BytesToKey.  The difference
    is that here we can explicitly specify the key size, instead of relying on
    the state of EVP_CIPHER struct.  EVP_BytesToKey will only produce 128 bit
    keys for the EVP Blowfish interface, which is not what we want.

    Eliminated the salt code, since we don't use it..  Reason is that we're
    using the derived key to encode random data.  Since there is no known
    plaintext, there is no ability for an attacker to pre-compute known
    password->data mappings, which is what the salt is meant to frustrate.
*/
//TODO: tests non-reg against version SSL
int BytesToKey(int keyLen, int ivLen,
               const unsigned char *data, int dataLen, unsigned int rounds,
               unsigned char *key, unsigned char *iv) {
  if (data == NULL || dataLen == 0)
    return 0;  // OpenSSL returns nkey here, but why?  It is a failure..

  unsigned char mdBuf[gcry_md_get_algo_dlen (GCRY_MD_SHA1)];
  unsigned int mds = gcry_md_get_algo_dlen (GCRY_MD_SHA1);;
  int addmd = 0;
  int nkey = key ? keyLen : 0;
  int niv = iv ? ivLen : 0;

  gcry_md_hd_t hd;
  gcry_md_open(&hd, GCRY_MD_SHA1, 0);

  for (;;) {
    gcry_md_reset(hd);
    if (addmd++) gcry_md_write(hd, mdBuf, mds);
    gcry_md_write(hd, data, dataLen);
    memcpy(mdBuf, gcry_md_read (hd, GCRY_MD_SHA1), mds);




    for (unsigned int i = 1; i < rounds; ++i) {
      gcry_md_reset(hd);
      gcry_md_write(hd, mdBuf, mds);
      memcpy(mdBuf, gcry_md_read (hd, GCRY_MD_SHA1), mds);

    }

    int offset = 0;
    int toCopy = MIN(nkey, mds - offset);
    if (toCopy) {
      memcpy(key, mdBuf + offset, toCopy);
      key += toCopy;
      nkey -= toCopy;
      offset += toCopy;
    }
    toCopy = MIN(niv, mds - offset);
    if (toCopy) {
      memcpy(iv, mdBuf + offset, toCopy);
      iv += toCopy;
      niv -= toCopy;
      offset += toCopy;
    }
    if ((nkey == 0) && (niv == 0)) break;
  }

  memset(mdBuf, 0, sizeof(mdBuf));

  return keyLen;
}


long gcrypt_time_diff(const timeval &end, const timeval &start) {
  return (end.tv_sec - start.tv_sec) * 1000 * 1000 +
         (end.tv_usec - start.tv_usec);
}

int gcrypt_TimedPBKDF2(const char *pass, int passlen, const unsigned char *salt,
                int saltlen, int keylen, unsigned char *out,
                long desiredPDFTime) {
  int iter = 1000;
  timeval start, end;

  for (;;) {
    gettimeofday(&start, 0);

    if (gcry_kdf_derive(pass, passlen, GCRY_KDF_PBKDF2, GCRY_MD_SHA1, salt, saltlen, iter, keylen, out) != 0)
      RLOG(WARNING) << "Error gcry_kdf_derive";

    gettimeofday(&end, 0);

    long delta = gcrypt_time_diff(end, start);
    if (delta < desiredPDFTime / 8) {
      iter *= 4;
    } else if (delta < (5 * desiredPDFTime / 6)) {
      // estimate number of iterations to get close to desired time
      iter = (int)((double)iter * (double)desiredPDFTime / (double)delta);
    } else
      return iter;
  }
}

// - Version 1:0 used EVP_BytesToKey, which didn't do the right thing for
// Blowfish key lengths > 128 bit.
// - Version 2:0 uses BytesToKey.
// We support both 2:0 and 1:0, hence current:revision:age = 2:0:1
// - Version 2:1 adds support for Message Digest function interface
// - Version 2:2 adds PBKDF2 for password derivation
// - Version 3:0 adds a new IV mechanism
static Interface BlowfishInterface("ssl/blowfish", 3, 0, 2);
static Interface AESInterface("ssl/aes", 3, 0, 2);

#ifndef GCRYPT_NO_BF

static Range BFKeyRange(128, 128, 32);
static Range BFBlockRange(64, 4096, 8);

static std::shared_ptr<Cipher> NewBFCipher(const Interface &iface, int keyLen) {
  if (keyLen <= 0) keyLen = 160;

  keyLen = BFKeyRange.closest(keyLen);

  int algo = GCRY_CIPHER_BLOWFISH;
  keyLen = 128;
  RLOG(WARNING) << "The blowfish algorithm. The current implementation allows only for a key size of 128 bits.";

  return std::shared_ptr<Cipher>(new GCrypt_Cipher(
      iface, BlowfishInterface, keyLen / 8, algo));
}

static bool BF_Cipher_registered =
    Cipher::Register("Blowfish",
                     // xgroup(setup)
                     gettext_noop("8 byte block cipher"), BlowfishInterface,
                     BFKeyRange, BFBlockRange, NewBFCipher);
#endif

#ifndef GCRYPT_NO_AES

static Range AESKeyRange(128, 256, 64);
static Range AESBlockRange(64, 4096, 16);

static std::shared_ptr<Cipher> NewAESCipher(const Interface &iface,
                                            int keyLen) {
  if (keyLen <= 0) keyLen = 192;

  keyLen = AESKeyRange.closest(keyLen);

  int algo = 0;

  switch (keyLen) {
    case 128:
      algo = GCRY_CIPHER_AES128;
      break;

    case 192:
      algo = GCRY_CIPHER_AES192;
      break;

    case 256:
    default:
      algo = GCRY_CIPHER_AES256;
      break;
  }

  return std::shared_ptr<Cipher>(new GCrypt_Cipher(
      iface, AESInterface, keyLen / 8, algo));
}

static bool AES_Cipher_registered =
    Cipher::Register("AES", "16 byte block cipher", AESInterface, AESKeyRange,
                     AESBlockRange, NewAESCipher);
#endif

class GCryptKey : public AbstractCipherKey {
 public:
  pthread_mutex_t mutex;

  unsigned int keySize;  // in bytes
  unsigned int ivLength;

  // key data is first _keySize bytes,
  // followed by iv of _ivLength bytes,
  unsigned char *buffer;

  gcry_cipher_hd_t gcryptStreamCipher;
  gcry_cipher_hd_t gcryptBlockCipher;
  gcry_mac_hd_t gcryptMAC;

  unsigned int gcrypt_keySize;  // in bytes
  unsigned int gcrypt_ivLength;


  GCryptKey(int keySize, int ivLength);
  ~GCryptKey();
};

GCryptKey::GCryptKey(int keySize_, int ivLength_) {
  gcrypt_keySize = this->keySize = keySize_;
  gcrypt_ivLength = this->ivLength = ivLength_;
  pthread_mutex_init(&mutex, 0);


  gcryptStreamCipher = 0;
  gcryptBlockCipher = 0;
  gcryptMAC = 0;
  buffer = (unsigned char *) gcry_malloc_secure(gcrypt_keySize + gcrypt_ivLength);

  memset(buffer, 0, gcrypt_keySize + gcrypt_ivLength);

  // most likely fails unless we're running as root, or a user-page-lock
  // kernel patch is applied..
  mlock(buffer, gcrypt_keySize + gcrypt_ivLength);

}

GCryptKey::~GCryptKey() {

  keySize = 0;
  ivLength = 0;


  memset(buffer, 0, gcrypt_keySize + gcrypt_ivLength);
  gcry_free (buffer);
  munlock(buffer, gcrypt_keySize + gcrypt_ivLength);

  gcrypt_keySize = 0;
  gcrypt_ivLength = 0;
  buffer = 0;

  gcry_cipher_close(gcryptStreamCipher);
  gcry_cipher_close(gcryptBlockCipher);
  gcry_mac_close(gcryptMAC);

  pthread_mutex_destroy(&mutex);
}

inline unsigned char *KeyData(const std::shared_ptr<GCryptKey> &key) {
  return key->buffer;
}
inline unsigned char *IVData(const std::shared_ptr<GCryptKey> &key) {
  return key->buffer + key->keySize;
}

void initKey(const std::shared_ptr<GCryptKey> &key , int _keySize, int gcryptAlgo_) {
  Lock lock(key->mutex);
  // initialize the cipher context once so that we don't have to do it for
  // every block..

  gcry_error_t error;

  if (gcry_cipher_open(&(key->gcryptStreamCipher), gcryptAlgo_, GCRY_CIPHER_MODE_CFB, 0) != 0)
    RLOG(WARNING) << "Error gcry_cipher_open";

  if (gcry_cipher_setkey(key->gcryptStreamCipher, KeyData(key), key->keySize) != 0)
    RLOG(WARNING) << "Error gcry_cipher_setkey";

  if (gcry_cipher_open(&(key->gcryptBlockCipher), gcryptAlgo_, GCRY_CIPHER_MODE_CBC, 0) != 0)
    RLOG(WARNING) << "Error gcry_cipher_open";

  if (gcry_cipher_setkey(key->gcryptBlockCipher, KeyData(key), key->keySize) != 0)
    RLOG(WARNING) << "Error gcry_cipher_setkey";

  if ((error = gcry_mac_open (&(key->gcryptMAC), GCRY_MAC_HMAC_SHA1, 0, NULL)) != 0)
    RLOG(WARNING) << "Error in gcry_mac_open";

  if ((error = gcry_mac_setkey (key->gcryptMAC, KeyData(key), key->keySize)) != 0)
    RLOG(WARNING) << "Error in gcry_mac_setkey";


}

GCrypt_Cipher::GCrypt_Cipher(const Interface &iface_, const Interface &realIface_,
                             int keySize_, int gcryptAlgo_) {
  this->iface = iface_;
  this->realIface = realIface_;
  this->_keySize = keySize_;
  this->_gcryptAlgo = gcryptAlgo_;
  this->_ivLength = gcry_cipher_get_algo_blklen(gcryptAlgo_); //EVP_CIPHER_iv_length(_blockCipher);

  rAssert(_ivLength == 8 || _ivLength == 16);

  VLOG(1) << "allocated cipher " << iface.name() << ", keySize " << _keySize
          << ", ivlength " << _ivLength;

  if ((gcry_cipher_get_algo_keylen(gcryptAlgo_) != (int)_keySize) &&
      iface.current() == 1) {
    RLOG(WARNING) << "Running in backward compatibilty mode for 1.0 - "
                     "key is really "
                  << gcry_cipher_get_algo_keylen(gcryptAlgo_) * 8 << " bits, not "
                  << _keySize * 8;
  }

}

GCrypt_Cipher::~GCrypt_Cipher() {}

Interface GCrypt_Cipher::interface() const { return realIface; }




/**
    create a key from the password.
    Use SHA to distribute entropy from the password into the key.

    This algorithm must remain constant for backward compatibility, as this key
    is used to encipher/decipher the master key.
*/
CipherKey GCrypt_Cipher::newKey(const char *password, int passwdLength,
                             int &iterationCount, long desiredDuration,
                             const unsigned char *salt, int saltLen) {
  std::shared_ptr<GCryptKey> key(new GCryptKey(_keySize, _ivLength));

  if (iterationCount == 0) {
    // timed run, fills in iteration count
    int res =
        gcrypt_TimedPBKDF2(password, passwdLength, salt, saltLen, _keySize + _ivLength,
                    KeyData(key), 1000 * desiredDuration);
    if (res <= 0) {
      RLOG(WARNING) << "gcrypt_TimedPBKDF2 error, PBKDF2 failed";
      return CipherKey();
    } else
      iterationCount = res;
  } else {
    // known iteration length
    if (gcry_kdf_derive(password, passwdLength, GCRY_KDF_PBKDF2, GCRY_MD_SHA1, salt, saltLen, iterationCount, _keySize + _ivLength, KeyData(key)) != 0)
      RLOG(WARNING) << "Error gcry_kdf_derive";
  }

  initKey(key, _keySize, _gcryptAlgo);

  return key;
}

CipherKey GCrypt_Cipher::newKey(const char *password, int passwdLength) {
  std::shared_ptr<GCryptKey> key(new GCryptKey(_keySize, _ivLength));

  int bytes = 0;
  if (iface.current() > 1) {
    // now we use BytesToKey, which can deal with Blowfish keys larger then
    // 128 bits.
    bytes =
        BytesToKey(_keySize, _ivLength, (unsigned char *)password,
                   passwdLength, 16, KeyData(key), IVData(key));

    // the reason for moving from EVP_BytesToKey to BytesToKey function..
    if (bytes != (int)_keySize) {
      RLOG(WARNING) << "newKey: BytesToKey returned " << bytes << ", expecting "
                    << _keySize << " key bytes";
    }
  } else {
    RLOG(WARNING) << "GCrypt_Cipher::newKey: Old interface not supported";
    return NULL;
    //use BytesToKey instead of EVP_BytesToKey??
    //also, gcrypt does not currently support blowfish keys different than 128 bits
    // for backward compatibility with filesystems created with 1:0
/*    bytes = EVP_BytesToKey(_blockCipher, EVP_sha1(), NULL,
                           (unsigned char *)password, passwdLength, 16,
                           KeyData(key), IVData(key));*/
  }

  initKey(key, _keySize, _gcryptAlgo);

  return key;
}

/**
    Create a random key.
    We use the OpenSSL library to generate random bytes, then take the hash of
    those bytes to use as the key.

    This algorithm can change at any time without affecting backward
    compatibility.
*/
CipherKey GCrypt_Cipher::newRandomKey() {
  const int bufLen = MAX_KEYLENGTH;
  unsigned char tmpBuf[bufLen];
  int saltLen = 20;
  unsigned char saltBuf[saltLen];

  if (!randomize(tmpBuf, bufLen, true) || !randomize(saltBuf, saltLen, true))
    return CipherKey();

  std::shared_ptr<GCryptKey> key(new GCryptKey(_keySize, _ivLength));

  // doesn't need to be versioned, because a random key is a random key..
  // Doesn't need to be reproducable..
  if (gcry_kdf_derive(tmpBuf, bufLen, GCRY_KDF_PBKDF2, GCRY_MD_SHA1, saltBuf, saltLen, 1000, _keySize + _ivLength, KeyData(key)) != 0)
    RLOG(WARNING) << "Error gcry_kdf_derive";

  memset(tmpBuf, 0, bufLen);

  initKey(key, _keySize, _gcryptAlgo);

  return key;
}

/**
    compute a 64-bit check value for the data using HMAC.
*/
static uint64_t _checksum_64(GCryptKey *key, const unsigned char *data,
                             int dataLen, uint64_t *chainedIV) {
  rAssert(dataLen > 0);
  Lock lock(key->mutex);

  unsigned char md[gcry_mac_get_algo_maclen(GCRY_MAC_HMAC_SHA1)];
  unsigned long int mdLen = gcry_mac_get_algo_maclen(GCRY_MAC_HMAC_SHA1);

  gcry_error_t error;
  if ((error = gcry_mac_reset(key->gcryptMAC)) != 0)
    cout << "Error in gcry_mac_reset";
  if ((error = gcry_mac_write (key->gcryptMAC, data, dataLen)) != 0)
    RLOG(WARNING) << "Error in gcry_mac_write";

  if (chainedIV) {
    // toss in the chained IV as well
    uint64_t tmp = *chainedIV;
    unsigned char h[8];
    for (unsigned int i = 0; i < 8; ++i) {
      h[i] = tmp & 0xff;
      tmp >>= 8;
    }

    if ((error = gcry_mac_write (key->gcryptMAC, h, 8)) != 0)
      RLOG(WARNING) << "Error in gcry_mac_write";
  }

  if ((error = gcry_mac_read (key->gcryptMAC, md, &mdLen)) != 0)
    RLOG(WARNING) << "Error in gcry_mac_write";


  rAssert(mdLen >= 8);

  // chop this down to a 64bit value..
  unsigned char h[8] = {0, 0, 0, 0, 0, 0, 0, 0};
  for (unsigned int i = 0; i < (mdLen - 1); ++i)
    h[i % 8] ^= (unsigned char)(md[i]);

  uint64_t value = (uint64_t)h[0];
  for (int i = 1; i < 8; ++i) value = (value << 8) | (uint64_t)h[i];

  return value;
}

/**
 * Write "len" bytes of random data into "buf"
 *
 * We ignore the @strongRandom parameter because OpenSSL
 * does not * offer a "weak" random generator
 */
bool GCrypt_Cipher::randomize(unsigned char *buf, int len,
                           bool strongRandom) const {
  // to avoid warnings of uninitialized data from valgrind
  memset(buf, 0, len);

  if (strongRandom) {
    //gcry_create_nonce(buf, len);
    //return true;
    gcry_randomize (buf, len, GCRY_VERY_STRONG_RANDOM);
    //RLOG(WARNING) << "gcrypt generated " << len << " very strong random bytes";
    return true;

  } else {
    gcry_create_nonce(buf, len);
    //RLOG(WARNING) << "gcrypt generated " << len << " nonce random bytes";
    return true;

  }

  return false;

}

uint64_t GCrypt_Cipher::MAC_64(const unsigned char *data, int len,
                            const CipherKey &key, uint64_t *chainedIV) const {
  std::shared_ptr<GCryptKey> mk = dynamic_pointer_cast<GCryptKey>(key);
  uint64_t tmp = _checksum_64(mk.get(), data, len, chainedIV/*, gcrypt_init , gcryptMAC*/);

  if (chainedIV) *chainedIV = tmp;

  return tmp;
}

CipherKey GCrypt_Cipher::readKey(const unsigned char *data,
                              const CipherKey &masterKey, bool checkKey) {
  //RLOG(WARNING) << "GCrypt_Cipher::readKey";
  std::shared_ptr<GCryptKey> mk = dynamic_pointer_cast<GCryptKey>(masterKey);
  rAssert(mk->keySize == _keySize);

  unsigned char tmpBuf[MAX_KEYLENGTH + MAX_IVLENGTH];

  // First N bytes are checksum bytes.
  unsigned int checksum = 0;
  for (int i = 0; i < KEY_CHECKSUM_BYTES; ++i)
    checksum = (checksum << 8) | (unsigned int)data[i];

  memcpy(tmpBuf, data + KEY_CHECKSUM_BYTES, _keySize + _ivLength);
  streamDecode(tmpBuf, _keySize + _ivLength, checksum, masterKey);

  // check for success
  unsigned int checksum2 = MAC_32(tmpBuf, _keySize + _ivLength, masterKey);
  if (checksum2 != checksum && checkKey) {
    VLOG(1) << "checksum mismatch: expected " << checksum << ", got "
            << checksum2;
    VLOG(1) << "on decode of " << _keySize + _ivLength << " bytes";
    memset(tmpBuf, 0, sizeof(tmpBuf));
    return CipherKey();
  }

  std::shared_ptr<GCryptKey> key(new GCryptKey(_keySize, _ivLength));

  memcpy(key->buffer, tmpBuf, _keySize + _ivLength);
  memset(tmpBuf, 0, sizeof(tmpBuf));

  initKey(key, _keySize, _gcryptAlgo);

  return key;
}

void GCrypt_Cipher::writeKey(const CipherKey &ckey, unsigned char *data,
                          const CipherKey &masterKey) {
  std::shared_ptr<GCryptKey> key = dynamic_pointer_cast<GCryptKey>(ckey);
  rAssert(key->keySize == _keySize);
  rAssert(key->ivLength == _ivLength);

  std::shared_ptr<GCryptKey> mk = dynamic_pointer_cast<GCryptKey>(masterKey);
  rAssert(mk->keySize == _keySize);
  rAssert(mk->ivLength == _ivLength);

  unsigned char tmpBuf[MAX_KEYLENGTH + MAX_IVLENGTH];

  int bufLen = _keySize + _ivLength;
  memcpy(tmpBuf, key->buffer, bufLen);

  unsigned int checksum = MAC_32(tmpBuf, bufLen, masterKey);

  streamEncode(tmpBuf, bufLen, checksum, masterKey);
  memcpy(data + KEY_CHECKSUM_BYTES, tmpBuf, bufLen);

  // first N bytes contain HMAC derived checksum..
  for (int i = 1; i <= KEY_CHECKSUM_BYTES; ++i) {
    data[KEY_CHECKSUM_BYTES - i] = checksum & 0xff;
    checksum >>= 8;
  }

  memset(tmpBuf, 0, sizeof(tmpBuf));
}

bool GCrypt_Cipher::compareKey(const CipherKey &A, const CipherKey &B) const {
  std::shared_ptr<GCryptKey> key1 = dynamic_pointer_cast<GCryptKey>(A);
  std::shared_ptr<GCryptKey> key2 = dynamic_pointer_cast<GCryptKey>(B);

  rAssert(key1->keySize == _keySize);
  rAssert(key2->keySize == _keySize);

  if (memcmp(key1->buffer, key2->buffer, _keySize + _ivLength) != 0)
    return false;
  else
    return true;
}

int GCrypt_Cipher::encodedKeySize() const {
  return _keySize + _ivLength + KEY_CHECKSUM_BYTES;
}

int GCrypt_Cipher::keySize() const { return _keySize; }

int GCrypt_Cipher::cipherBlockSize() const {

  return gcry_cipher_get_algo_blklen(_gcryptAlgo);
}

/**
 * Generate the initialization vector that will actually be used for
 * AES/Blowfish encryption and decryption in {stream,block}{Encode,Decode}
 *
 * It is derived from
 *  1) a "seed" value that is passed from the higher layer, for the default
 *     configuration it is "block_number XOR per_file_IV_header" from
 *     CipherFileIO
 *  2) The IV that is used for encrypting the master key, "IVData(key)"
 *  3) The master key
 * using
 *  ivec = HMAC(master_key, IVData(key) CONCAT seed)
 *
 * As an HMAC is unpredictable as long as the key is secret, the only
 * requirement for "seed" is that is must be unique.
 */
void GCrypt_Cipher::setIVec(unsigned char *ivec, uint64_t seed,
                         const std::shared_ptr<GCryptKey> &key) const {
  if (iface.current() >= 3) {
    memcpy(ivec, IVData(key), _ivLength);

    unsigned char md[gcry_mac_get_algo_maclen(GCRY_MAC_HMAC_SHA1)];
    unsigned long int mdLen = gcry_mac_get_algo_maclen(GCRY_MAC_HMAC_SHA1);

    for (int i = 0; i < 8; ++i) {
      md[i] = (unsigned char)(seed & 0xff);
      seed >>= 8;
    }

    gcry_error_t error;

    if ((error = gcry_mac_reset(key->gcryptMAC)) != 0)
      cout << "Error in gcry_mac_reset";

    if ((error = gcry_mac_write (key->gcryptMAC, (void *) ivec, _ivLength)) != 0)
      RLOG(WARNING) << "Error in gcry_mac_write";

    if ((error = gcry_mac_write (key->gcryptMAC, md, 8)) != 0)
      RLOG(WARNING) << "Error in gcry_mac_write";

    if ((error = gcry_mac_read (key->gcryptMAC, md, &mdLen)) != 0)
      RLOG(WARNING) << "Error in gcry_mac_write";


    rAssert(mdLen >= _ivLength);

    memcpy(ivec, md, _ivLength);
  } else {
    setIVec_old(ivec, seed, key);
  }
}

/** For backward compatibility.
    A watermark attack was discovered against this IV setup.  If an attacker
    could get a victim to store a carefully crafted file, they could later
    determine if the victim had the file in encrypted storage (without
    decrypting the file).
  */
void GCrypt_Cipher::setIVec_old(unsigned char *ivec, unsigned int seed,
                             const std::shared_ptr<GCryptKey> &key) const {
  /* These multiplication constants chosen as they represent (non optimal)
     Golumb rulers, the idea being to spread around the information in the
     seed.

     0x060a4011 : ruler length 26, 7 marks, 21 measurable lengths
     0x0221040d : ruler length 25, 7 marks, 21 measurable lengths
  */
  unsigned int var1 = 0x060a4011 * seed;
  unsigned int var2 = 0x0221040d * (seed ^ 0xD3FEA11C);

  memcpy(ivec, IVData(key), _ivLength);

  ivec[0] ^= (var1 >> 24) & 0xff;
  ivec[1] ^= (var2 >> 16) & 0xff;
  ivec[2] ^= (var1 >> 8) & 0xff;
  ivec[3] ^= (var2)&0xff;
  ivec[4] ^= (var2 >> 24) & 0xff;
  ivec[5] ^= (var1 >> 16) & 0xff;
  ivec[6] ^= (var2 >> 8) & 0xff;
  ivec[7] ^= (var1)&0xff;

  if (_ivLength > 8) {
    ivec[8 + 0] ^= (var1)&0xff;
    ivec[8 + 1] ^= (var2 >> 8) & 0xff;
    ivec[8 + 2] ^= (var1 >> 16) & 0xff;
    ivec[8 + 3] ^= (var2 >> 24) & 0xff;
    ivec[8 + 4] ^= (var1 >> 24) & 0xff;
    ivec[8 + 5] ^= (var2 >> 16) & 0xff;
    ivec[8 + 6] ^= (var1 >> 8) & 0xff;
    ivec[8 + 7] ^= (var2)&0xff;
  }
}

static void flipBytes(unsigned char *buf, int size) {
  unsigned char revBuf[64];

  int bytesLeft = size;
  while (bytesLeft) {
    int toFlip = MIN(sizeof(revBuf), bytesLeft);

    for (int i = 0; i < toFlip; ++i) revBuf[i] = buf[toFlip - (i + 1)];

    memcpy(buf, revBuf, toFlip);
    bytesLeft -= toFlip;
    buf += toFlip;
  }
  memset(revBuf, 0, sizeof(revBuf));
}

static void shuffleBytes(unsigned char *buf, int size) {
  for (int i = 0; i < size - 1; ++i) buf[i + 1] ^= buf[i];
}

static void unshuffleBytes(unsigned char *buf, int size) {
  for (int i = size - 1; i; --i) buf[i] ^= buf[i - 1];
}



/** Partial blocks are encoded with a stream cipher.  We make multiple passes on
 the data to ensure that the ends of the data depend on each other.
*/
bool GCrypt_Cipher::streamEncode(unsigned char *buf, int size, uint64_t iv64,
                              const CipherKey &ckey) const {
  rAssert(size > 0);
  std::shared_ptr<GCryptKey> key = dynamic_pointer_cast<GCryptKey>(ckey);
  rAssert(key->keySize == _keySize);
  rAssert(key->ivLength == _ivLength);

  Lock lock(key->mutex);

  unsigned char ivec[MAX_IVLENGTH];
  int dstLen = 0, tmpLen = 0;

  shuffleBytes(buf, size);

  setIVec(ivec, iv64, key);

  const void * iv_gc = ivec;

  if (gcry_cipher_setiv(key->gcryptStreamCipher, iv_gc, MAX_IVLENGTH) != 0)
    RLOG(WARNING) << "Error gcry_cipher_setiv";

  if (gcry_cipher_encrypt(key->gcryptStreamCipher, buf, size, NULL, 0) != 0)
    RLOG(WARNING) << "Error gcry_cipher_encrypt";


  dstLen = size;

  flipBytes(buf, size);
  shuffleBytes(buf, size);

  setIVec(ivec, iv64 + 1, key);
  iv_gc = ivec;

  if (gcry_cipher_setiv(key->gcryptStreamCipher, iv_gc, MAX_IVLENGTH) != 0)
    RLOG(WARNING) << "Error gcry_cipher_setiv";

  if (gcry_cipher_encrypt(key->gcryptStreamCipher, buf, size, NULL, 0) != 0)
    RLOG(WARNING) << "Error gcry_cipher_encrypt";

  dstLen = size;

  if (dstLen != size) {
    RLOG(ERROR) << "encoding " << size << " bytes, got back " << dstLen << " ("
                << tmpLen << " in final_ex)";
  }

  return true;
}

bool GCrypt_Cipher::streamDecode(unsigned char *buf, int size, uint64_t iv64,
                              const CipherKey &ckey) const {
  rAssert(size > 0);
  std::shared_ptr<GCryptKey> key = dynamic_pointer_cast<GCryptKey>(ckey);
  rAssert(key->keySize == _keySize);
  rAssert(key->ivLength == _ivLength);

  Lock lock(key->mutex);

  unsigned char ivec[MAX_IVLENGTH];
  int dstLen = 0, tmpLen = 0;

  setIVec(ivec, iv64 + 1, key);
  const void * iv_gc = ivec;


  if (gcry_cipher_setiv(key->gcryptStreamCipher, iv_gc, MAX_IVLENGTH) != 0)
      RLOG(WARNING) << "Error gcry_cipher_setiv";

  if (gcry_cipher_decrypt(key->gcryptStreamCipher, buf, size, NULL, 0) != 0)
      RLOG(WARNING) << "Error gcry_cipher_decrypt";


  unshuffleBytes(buf, size);
  flipBytes(buf, size);

  setIVec(ivec, iv64, key);
  iv_gc = ivec;


  if (gcry_cipher_setiv(key->gcryptStreamCipher, iv_gc, MAX_IVLENGTH) != 0)
    RLOG(WARNING) << "Error gcry_cipher_setiv";

  if (gcry_cipher_decrypt(key->gcryptStreamCipher, buf, size, NULL, 0) != 0)
    RLOG(WARNING) << "Error gcry_cipher_decrypt";


  unshuffleBytes(buf, size);

  dstLen = size;

  if (dstLen != size) {
    RLOG(ERROR) << "decoding " << size << " bytes, got back " << dstLen << " ("
                << tmpLen << " in final_ex)";
  }

  return true;
}

bool GCrypt_Cipher::blockEncode(unsigned char *buf, int size, uint64_t iv64,
                             const CipherKey &ckey) const {
  rAssert(size > 0);
  std::shared_ptr<GCryptKey> key = dynamic_pointer_cast<GCryptKey>(ckey);

  rAssert(key->keySize == _keySize);
  rAssert(key->ivLength == _ivLength);

  // data must be integer number of blocks
  const int blockMod = size % gcry_cipher_get_algo_blklen(_gcryptAlgo);
  if (blockMod != 0)
    throw Error("Invalid data size, not multiple of block size");

  Lock lock(key->mutex);

  unsigned char ivec[MAX_IVLENGTH];

  int dstLen = 0, tmpLen = 0;
  setIVec(ivec, iv64, key);
  const void * iv_gc = ivec;


  if (gcry_cipher_setiv(key->gcryptBlockCipher, iv_gc, MAX_IVLENGTH) != 0)
    RLOG(WARNING) << "Error gcry_cipher_setiv";

  if (gcry_cipher_encrypt(key->gcryptBlockCipher, buf, size, NULL, 0) != 0)
    RLOG(WARNING) << "Error gcry_cipher_encrypt";

  dstLen = size;

  if (dstLen != size) {
    RLOG(ERROR) << "encoding " << size << " bytes, got back " << dstLen << " ("
                << tmpLen << " in final_ex)";
  }

  return true;
}

bool GCrypt_Cipher::blockDecode(unsigned char *buf, int size, uint64_t iv64,
                             const CipherKey &ckey) const {
  rAssert(size > 0);
  std::shared_ptr<GCryptKey> key = dynamic_pointer_cast<GCryptKey>(ckey);
  rAssert(key->keySize == _keySize);
  rAssert(key->ivLength == _ivLength);

  // data must be integer number of blocks
  //const int blockMod = size % EVP_CIPHER_CTX_block_size(key->block_dec);
  const int blockMod = size % gcry_cipher_get_algo_blklen(_gcryptAlgo);
  if (blockMod != 0)
    throw Error("Invalid data size, not multiple of block size");

  Lock lock(key->mutex);

  unsigned char ivec[MAX_IVLENGTH];

  int dstLen = 0, tmpLen = 0;
  setIVec(ivec, iv64, key);

  const void * iv_gc = ivec;


  if (gcry_cipher_setiv(key->gcryptBlockCipher, iv_gc, MAX_IVLENGTH) != 0)
    RLOG(WARNING) << "Error gcry_cipher_setiv";

  if (gcry_cipher_decrypt(key->gcryptBlockCipher, buf, size, NULL, 0) != 0)
    RLOG(WARNING) << "Error gcry_cipher_decrypt";


  dstLen = size;


  if (dstLen != size) {
    RLOG(ERROR) << "decoding " << size << " bytes, got back " << dstLen << " ("
                << tmpLen << " in final_ex)";
  }

  return true;
}

int GCrypt_Cipher::getIntImplementation() const {return 2;}

//int GCrypt_Cipher::getIntImplementation() const {return typeid(GCrypt_Cipher).name();}

bool GCrypt_Cipher::Enabled() { return true; }

}  // namespace encfs
