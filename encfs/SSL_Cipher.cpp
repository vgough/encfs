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

#include "internal/easylogging++.h"
#include <cstring>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/ossl_typ.h>
#include <openssl/rand.h>
#include <pthread.h>
#include <string>
#include <sys/mman.h>
#include <sys/time.h>

#include "Cipher.h"
#include "Error.h"
#include "Interface.h"
#include "Mutex.h"
#include "Range.h"
#include "SSL_Cipher.h"
#include "intl/gettext.h"

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
int BytesToKey(int keyLen, int ivLen, const EVP_MD *md,
               const unsigned char *data, int dataLen, unsigned int rounds,
               unsigned char *key, unsigned char *iv) {
  if (data == NULL || dataLen == 0)
    return 0;  // OpenSSL returns nkey here, but why?  It is a failure..

  unsigned char mdBuf[EVP_MAX_MD_SIZE];
  unsigned int mds = 0;
  int addmd = 0;
  int nkey = key ? keyLen : 0;
  int niv = iv ? ivLen : 0;

  EVP_MD_CTX cx;
  EVP_MD_CTX_init(&cx);

  for (;;) {
    EVP_DigestInit_ex(&cx, md, NULL);
    if (addmd++) EVP_DigestUpdate(&cx, mdBuf, mds);
    EVP_DigestUpdate(&cx, data, dataLen);
    EVP_DigestFinal_ex(&cx, mdBuf, &mds);

    for (unsigned int i = 1; i < rounds; ++i) {
      EVP_DigestInit_ex(&cx, md, NULL);
      EVP_DigestUpdate(&cx, mdBuf, mds);
      EVP_DigestFinal_ex(&cx, mdBuf, &mds);
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
  EVP_MD_CTX_cleanup(&cx);
  OPENSSL_cleanse(mdBuf, sizeof(mdBuf));

  return keyLen;
}

long time_diff(const timeval &end, const timeval &start) {
  return (end.tv_sec - start.tv_sec) * 1000 * 1000 +
         (end.tv_usec - start.tv_usec);
}

int TimedPBKDF2(const char *pass, int passlen, const unsigned char *salt,
                int saltlen, int keylen, unsigned char *out,
                long desiredPDFTime) {
  int iter = 1000;
  timeval start, end;

  for (;;) {
    gettimeofday(&start, 0);
    int res =
        PKCS5_PBKDF2_HMAC_SHA1(pass, passlen, const_cast<unsigned char *>(salt),
                               saltlen, iter, keylen, out);
    if (res != 1) return -1;

    gettimeofday(&end, 0);

    long delta = time_diff(end, start);
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

#ifndef OPENSSL_NO_BF

static Range BFKeyRange(128, 256, 32);
static Range BFBlockRange(64, 4096, 8);

static std::shared_ptr<Cipher> NewBFCipher(const Interface &iface, int keyLen) {
  if (keyLen <= 0) keyLen = 160;

  keyLen = BFKeyRange.closest(keyLen);

  const EVP_CIPHER *blockCipher = EVP_bf_cbc();
  const EVP_CIPHER *streamCipher = EVP_bf_cfb();

  return std::shared_ptr<Cipher>(new SSL_Cipher(
      iface, BlowfishInterface, blockCipher, streamCipher, keyLen / 8));
}

static bool BF_Cipher_registered =
    Cipher::Register("Blowfish",
                     // xgroup(setup)
                     gettext_noop("8 byte block cipher"), BlowfishInterface,
                     BFKeyRange, BFBlockRange, NewBFCipher);
#endif

#ifndef OPENSSL_NO_AES

static Range AESKeyRange(128, 256, 64);
static Range AESBlockRange(64, 4096, 16);

static std::shared_ptr<Cipher> NewAESCipher(const Interface &iface,
                                            int keyLen) {
  if (keyLen <= 0) keyLen = 192;

  keyLen = AESKeyRange.closest(keyLen);

  const EVP_CIPHER *blockCipher = 0;
  const EVP_CIPHER *streamCipher = 0;

  switch (keyLen) {
    case 128:
      blockCipher = EVP_aes_128_cbc();
      streamCipher = EVP_aes_128_cfb();
      break;

    case 192:
      blockCipher = EVP_aes_192_cbc();
      streamCipher = EVP_aes_192_cfb();
      break;

    case 256:
    default:
      blockCipher = EVP_aes_256_cbc();
      streamCipher = EVP_aes_256_cfb();
      break;
  }

  return std::shared_ptr<Cipher>(new SSL_Cipher(
      iface, AESInterface, blockCipher, streamCipher, keyLen / 8));
}

static bool AES_Cipher_registered =
    Cipher::Register("AES", "16 byte block cipher", AESInterface, AESKeyRange,
                     AESBlockRange, NewAESCipher);
#endif

class SSLKey : public AbstractCipherKey {
 public:
  pthread_mutex_t mutex;

  unsigned int keySize;  // in bytes
  unsigned int ivLength;

  // key data is first _keySize bytes,
  // followed by iv of _ivLength bytes,
  unsigned char *buffer;

  EVP_CIPHER_CTX block_enc;
  EVP_CIPHER_CTX block_dec;
  EVP_CIPHER_CTX stream_enc;
  EVP_CIPHER_CTX stream_dec;

  HMAC_CTX mac_ctx;

  SSLKey(int keySize, int ivLength);
  ~SSLKey();
};

SSLKey::SSLKey(int keySize_, int ivLength_) {
  this->keySize = keySize_;
  this->ivLength = ivLength_;
  pthread_mutex_init(&mutex, 0);
  buffer = (unsigned char *)OPENSSL_malloc(keySize + ivLength);
  memset(buffer, 0, keySize + ivLength);

  // most likely fails unless we're running as root, or a user-page-lock
  // kernel patch is applied..
  mlock(buffer, keySize + ivLength);

  EVP_CIPHER_CTX_init(&block_enc);
  EVP_CIPHER_CTX_init(&block_dec);
  EVP_CIPHER_CTX_init(&stream_enc);
  EVP_CIPHER_CTX_init(&stream_dec);
  HMAC_CTX_init(&mac_ctx);
}

SSLKey::~SSLKey() {
  memset(buffer, 0, keySize + ivLength);

  OPENSSL_free(buffer);
  munlock(buffer, keySize + ivLength);

  keySize = 0;
  ivLength = 0;
  buffer = 0;

  EVP_CIPHER_CTX_cleanup(&block_enc);
  EVP_CIPHER_CTX_cleanup(&block_dec);
  EVP_CIPHER_CTX_cleanup(&stream_enc);
  EVP_CIPHER_CTX_cleanup(&stream_dec);

  HMAC_CTX_cleanup(&mac_ctx);

  pthread_mutex_destroy(&mutex);
}

inline unsigned char *KeyData(const std::shared_ptr<SSLKey> &key) {
  return key->buffer;
}
inline unsigned char *IVData(const std::shared_ptr<SSLKey> &key) {
  return key->buffer + key->keySize;
}

void initKey(const std::shared_ptr<SSLKey> &key, const EVP_CIPHER *_blockCipher,
             const EVP_CIPHER *_streamCipher, int _keySize) {
  Lock lock(key->mutex);
  // initialize the cipher context once so that we don't have to do it for
  // every block..
  EVP_EncryptInit_ex(&key->block_enc, _blockCipher, NULL, NULL, NULL);
  EVP_DecryptInit_ex(&key->block_dec, _blockCipher, NULL, NULL, NULL);
  EVP_EncryptInit_ex(&key->stream_enc, _streamCipher, NULL, NULL, NULL);
  EVP_DecryptInit_ex(&key->stream_dec, _streamCipher, NULL, NULL, NULL);

  EVP_CIPHER_CTX_set_key_length(&key->block_enc, _keySize);
  EVP_CIPHER_CTX_set_key_length(&key->block_dec, _keySize);
  EVP_CIPHER_CTX_set_key_length(&key->stream_enc, _keySize);
  EVP_CIPHER_CTX_set_key_length(&key->stream_dec, _keySize);

  EVP_CIPHER_CTX_set_padding(&key->block_enc, 0);
  EVP_CIPHER_CTX_set_padding(&key->block_dec, 0);
  EVP_CIPHER_CTX_set_padding(&key->stream_enc, 0);
  EVP_CIPHER_CTX_set_padding(&key->stream_dec, 0);

  EVP_EncryptInit_ex(&key->block_enc, NULL, NULL, KeyData(key), NULL);
  EVP_DecryptInit_ex(&key->block_dec, NULL, NULL, KeyData(key), NULL);
  EVP_EncryptInit_ex(&key->stream_enc, NULL, NULL, KeyData(key), NULL);
  EVP_DecryptInit_ex(&key->stream_dec, NULL, NULL, KeyData(key), NULL);

  HMAC_Init_ex(&key->mac_ctx, KeyData(key), _keySize, EVP_sha1(), 0);
}

SSL_Cipher::SSL_Cipher(const Interface &iface_, const Interface &realIface_,
                       const EVP_CIPHER *blockCipher,
                       const EVP_CIPHER *streamCipher, int keySize_) {
  this->iface = iface_;
  this->realIface = realIface_;
  this->_blockCipher = blockCipher;
  this->_streamCipher = streamCipher;
  this->_keySize = keySize_;
  this->_ivLength = EVP_CIPHER_iv_length(_blockCipher);

  rAssert(_ivLength == 8 || _ivLength == 16);

  VLOG(1) << "allocated cipher " << iface.name() << ", keySize " << _keySize
          << ", ivlength " << _ivLength;

  if ((EVP_CIPHER_key_length(_blockCipher) != (int)_keySize) &&
      iface.current() == 1) {
    RLOG(WARNING) << "Running in backward compatibilty mode for 1.0 - "
                     "key is really "
                  << EVP_CIPHER_key_length(_blockCipher) * 8 << " bits, not "
                  << _keySize * 8;
  }
}

SSL_Cipher::~SSL_Cipher() {}

Interface SSL_Cipher::interface() const { return realIface; }

/**
    create a key from the password.
    Use SHA to distribute entropy from the password into the key.

    This algorithm must remain constant for backward compatibility, as this key
    is used to encipher/decipher the master key.
*/
CipherKey SSL_Cipher::newKey(const char *password, int passwdLength,
                             int &iterationCount, long desiredDuration,
                             const unsigned char *salt, int saltLen) {
  std::shared_ptr<SSLKey> key(new SSLKey(_keySize, _ivLength));

  if (iterationCount == 0) {
    // timed run, fills in iteration count
    int res =
        TimedPBKDF2(password, passwdLength, salt, saltLen, _keySize + _ivLength,
                    KeyData(key), 1000 * desiredDuration);
    if (res <= 0) {
      RLOG(WARNING) << "openssl error, PBKDF2 failed";
      return CipherKey();
    } else
      iterationCount = res;
  } else {
    // known iteration length
    if (PKCS5_PBKDF2_HMAC_SHA1(
            password, passwdLength, const_cast<unsigned char *>(salt), saltLen,
            iterationCount, _keySize + _ivLength, KeyData(key)) != 1) {
      RLOG(WARNING) << "openssl error, PBKDF2 failed";
      return CipherKey();
    }
  }

  initKey(key, _blockCipher, _streamCipher, _keySize);

  return key;
}

CipherKey SSL_Cipher::newKey(const char *password, int passwdLength) {
  std::shared_ptr<SSLKey> key(new SSLKey(_keySize, _ivLength));

  int bytes = 0;
  if (iface.current() > 1) {
    // now we use BytesToKey, which can deal with Blowfish keys larger then
    // 128 bits.
    bytes =
        BytesToKey(_keySize, _ivLength, EVP_sha1(), (unsigned char *)password,
                   passwdLength, 16, KeyData(key), IVData(key));

    // the reason for moving from EVP_BytesToKey to BytesToKey function..
    if (bytes != (int)_keySize) {
      RLOG(WARNING) << "newKey: BytesToKey returned " << bytes << ", expecting "
                    << _keySize << " key bytes";
    }
  } else {
    // for backward compatibility with filesystems created with 1:0
    bytes = EVP_BytesToKey(_blockCipher, EVP_sha1(), NULL,
                           (unsigned char *)password, passwdLength, 16,
                           KeyData(key), IVData(key));
  }

  initKey(key, _blockCipher, _streamCipher, _keySize);

  return key;
}

/**
    Create a random key.
    We use the OpenSSL library to generate random bytes, then take the hash of
    those bytes to use as the key.

    This algorithm can change at any time without affecting backward
    compatibility.
*/
CipherKey SSL_Cipher::newRandomKey() {
  const int bufLen = MAX_KEYLENGTH;
  unsigned char tmpBuf[bufLen];
  int saltLen = 20;
  unsigned char saltBuf[saltLen];

  if (!randomize(tmpBuf, bufLen, true) || !randomize(saltBuf, saltLen, true))
    return CipherKey();

  std::shared_ptr<SSLKey> key(new SSLKey(_keySize, _ivLength));

  // doesn't need to be versioned, because a random key is a random key..
  // Doesn't need to be reproducable..
  if (PKCS5_PBKDF2_HMAC_SHA1((char *)tmpBuf, bufLen, saltBuf, saltLen, 1000,
                             _keySize + _ivLength, KeyData(key)) != 1) {
    RLOG(WARNING) << "openssl error, PBKDF2 failed";
    return CipherKey();
  }

  OPENSSL_cleanse(tmpBuf, bufLen);

  initKey(key, _blockCipher, _streamCipher, _keySize);

  return key;
}

/**
    compute a 64-bit check value for the data using HMAC.
*/
static uint64_t _checksum_64(SSLKey *key, const unsigned char *data,
                             int dataLen, uint64_t *chainedIV) {
  rAssert(dataLen > 0);
  Lock lock(key->mutex);

  unsigned char md[EVP_MAX_MD_SIZE];
  unsigned int mdLen = EVP_MAX_MD_SIZE;

  HMAC_Init_ex(&key->mac_ctx, 0, 0, 0, 0);
  HMAC_Update(&key->mac_ctx, data, dataLen);
  if (chainedIV) {
    // toss in the chained IV as well
    uint64_t tmp = *chainedIV;
    unsigned char h[8];
    for (unsigned int i = 0; i < 8; ++i) {
      h[i] = tmp & 0xff;
      tmp >>= 8;
    }

    HMAC_Update(&key->mac_ctx, h, 8);
  }

  HMAC_Final(&key->mac_ctx, md, &mdLen);

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
 * See "man 3 RAND_bytes" for the effect of strongRandom
 */
bool SSL_Cipher::randomize(unsigned char *buf, int len,
                           bool strongRandom) const {
  // to avoid warnings of uninitialized data from valgrind
  memset(buf, 0, len);
  int result;
  if (strongRandom) {
    result = RAND_bytes(buf, len);
  } else {
    result = RAND_pseudo_bytes(buf, len);
  }

  if (result != 1) {
    char errStr[120];  // specs require string at least 120 bytes long..
    unsigned long errVal = 0;
    if ((errVal = ERR_get_error()) != 0) {
      RLOG(WARNING) << "openssl error: " << ERR_error_string(errVal, errStr);
    }

    return false;
  } else {
    return true;
  }
}

uint64_t SSL_Cipher::MAC_64(const unsigned char *data, int len,
                            const CipherKey &key, uint64_t *chainedIV) const {
  std::shared_ptr<SSLKey> mk = dynamic_pointer_cast<SSLKey>(key);
  uint64_t tmp = _checksum_64(mk.get(), data, len, chainedIV);

  if (chainedIV) *chainedIV = tmp;

  return tmp;
}

CipherKey SSL_Cipher::readKey(const unsigned char *data,
                              const CipherKey &masterKey, bool checkKey) {
  std::shared_ptr<SSLKey> mk = dynamic_pointer_cast<SSLKey>(masterKey);
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

  std::shared_ptr<SSLKey> key(new SSLKey(_keySize, _ivLength));

  memcpy(key->buffer, tmpBuf, _keySize + _ivLength);
  memset(tmpBuf, 0, sizeof(tmpBuf));

  initKey(key, _blockCipher, _streamCipher, _keySize);

  return key;
}

void SSL_Cipher::writeKey(const CipherKey &ckey, unsigned char *data,
                          const CipherKey &masterKey) {
  std::shared_ptr<SSLKey> key = dynamic_pointer_cast<SSLKey>(ckey);
  rAssert(key->keySize == _keySize);
  rAssert(key->ivLength == _ivLength);

  std::shared_ptr<SSLKey> mk = dynamic_pointer_cast<SSLKey>(masterKey);
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

bool SSL_Cipher::compareKey(const CipherKey &A, const CipherKey &B) const {
  std::shared_ptr<SSLKey> key1 = dynamic_pointer_cast<SSLKey>(A);
  std::shared_ptr<SSLKey> key2 = dynamic_pointer_cast<SSLKey>(B);

  rAssert(key1->keySize == _keySize);
  rAssert(key2->keySize == _keySize);

  if (memcmp(key1->buffer, key2->buffer, _keySize + _ivLength) != 0)
    return false;
  else
    return true;
}

int SSL_Cipher::encodedKeySize() const {
  return _keySize + _ivLength + KEY_CHECKSUM_BYTES;
}

int SSL_Cipher::keySize() const { return _keySize; }

int SSL_Cipher::cipherBlockSize() const {
  return EVP_CIPHER_block_size(_blockCipher);
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
void SSL_Cipher::setIVec(unsigned char *ivec, uint64_t seed,
                         const std::shared_ptr<SSLKey> &key) const {
  if (iface.current() >= 3) {
    memcpy(ivec, IVData(key), _ivLength);

    unsigned char md[EVP_MAX_MD_SIZE];
    unsigned int mdLen = EVP_MAX_MD_SIZE;

    for (int i = 0; i < 8; ++i) {
      md[i] = (unsigned char)(seed & 0xff);
      seed >>= 8;
    }

    // combine ivec and seed with HMAC
    HMAC_Init_ex(&key->mac_ctx, 0, 0, 0, 0);
    HMAC_Update(&key->mac_ctx, ivec, _ivLength);
    HMAC_Update(&key->mac_ctx, md, 8);
    HMAC_Final(&key->mac_ctx, md, &mdLen);
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
void SSL_Cipher::setIVec_old(unsigned char *ivec, unsigned int seed,
                             const std::shared_ptr<SSLKey> &key) const {
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
bool SSL_Cipher::streamEncode(unsigned char *buf, int size, uint64_t iv64,
                              const CipherKey &ckey) const {
  rAssert(size > 0);
  std::shared_ptr<SSLKey> key = dynamic_pointer_cast<SSLKey>(ckey);
  rAssert(key->keySize == _keySize);
  rAssert(key->ivLength == _ivLength);

  Lock lock(key->mutex);

  unsigned char ivec[MAX_IVLENGTH];
  int dstLen = 0, tmpLen = 0;

  shuffleBytes(buf, size);

  setIVec(ivec, iv64, key);
  EVP_EncryptInit_ex(&key->stream_enc, NULL, NULL, NULL, ivec);
  EVP_EncryptUpdate(&key->stream_enc, buf, &dstLen, buf, size);
  EVP_EncryptFinal_ex(&key->stream_enc, buf + dstLen, &tmpLen);

  flipBytes(buf, size);
  shuffleBytes(buf, size);

  setIVec(ivec, iv64 + 1, key);
  EVP_EncryptInit_ex(&key->stream_enc, NULL, NULL, NULL, ivec);
  EVP_EncryptUpdate(&key->stream_enc, buf, &dstLen, buf, size);
  EVP_EncryptFinal_ex(&key->stream_enc, buf + dstLen, &tmpLen);

  dstLen += tmpLen;
  if (dstLen != size) {
    RLOG(ERROR) << "encoding " << size << " bytes, got back " << dstLen << " ("
                << tmpLen << " in final_ex)";
  }

  return true;
}

bool SSL_Cipher::streamDecode(unsigned char *buf, int size, uint64_t iv64,
                              const CipherKey &ckey) const {
  rAssert(size > 0);
  std::shared_ptr<SSLKey> key = dynamic_pointer_cast<SSLKey>(ckey);
  rAssert(key->keySize == _keySize);
  rAssert(key->ivLength == _ivLength);

  Lock lock(key->mutex);

  unsigned char ivec[MAX_IVLENGTH];
  int dstLen = 0, tmpLen = 0;

  setIVec(ivec, iv64 + 1, key);
  EVP_DecryptInit_ex(&key->stream_dec, NULL, NULL, NULL, ivec);
  EVP_DecryptUpdate(&key->stream_dec, buf, &dstLen, buf, size);
  EVP_DecryptFinal_ex(&key->stream_dec, buf + dstLen, &tmpLen);

  unshuffleBytes(buf, size);
  flipBytes(buf, size);

  setIVec(ivec, iv64, key);
  EVP_DecryptInit_ex(&key->stream_dec, NULL, NULL, NULL, ivec);
  EVP_DecryptUpdate(&key->stream_dec, buf, &dstLen, buf, size);
  EVP_DecryptFinal_ex(&key->stream_dec, buf + dstLen, &tmpLen);

  unshuffleBytes(buf, size);

  dstLen += tmpLen;
  if (dstLen != size) {
    RLOG(ERROR) << "decoding " << size << " bytes, got back " << dstLen << " ("
                << tmpLen << " in final_ex)";
  }

  return true;
}

bool SSL_Cipher::blockEncode(unsigned char *buf, int size, uint64_t iv64,
                             const CipherKey &ckey) const {
  rAssert(size > 0);
  std::shared_ptr<SSLKey> key = dynamic_pointer_cast<SSLKey>(ckey);
  rAssert(key->keySize == _keySize);
  rAssert(key->ivLength == _ivLength);

  // data must be integer number of blocks
  const int blockMod = size % EVP_CIPHER_CTX_block_size(&key->block_enc);
  if (blockMod != 0)
    throw Error("Invalid data size, not multiple of block size");

  Lock lock(key->mutex);

  unsigned char ivec[MAX_IVLENGTH];

  int dstLen = 0, tmpLen = 0;
  setIVec(ivec, iv64, key);

  EVP_EncryptInit_ex(&key->block_enc, NULL, NULL, NULL, ivec);
  EVP_EncryptUpdate(&key->block_enc, buf, &dstLen, buf, size);
  EVP_EncryptFinal_ex(&key->block_enc, buf + dstLen, &tmpLen);
  dstLen += tmpLen;

  if (dstLen != size) {
    RLOG(ERROR) << "encoding " << size << " bytes, got back " << dstLen << " ("
                << tmpLen << " in final_ex)";
  }

  return true;
}

bool SSL_Cipher::blockDecode(unsigned char *buf, int size, uint64_t iv64,
                             const CipherKey &ckey) const {
  rAssert(size > 0);
  std::shared_ptr<SSLKey> key = dynamic_pointer_cast<SSLKey>(ckey);
  rAssert(key->keySize == _keySize);
  rAssert(key->ivLength == _ivLength);

  // data must be integer number of blocks
  const int blockMod = size % EVP_CIPHER_CTX_block_size(&key->block_dec);
  if (blockMod != 0)
    throw Error("Invalid data size, not multiple of block size");

  Lock lock(key->mutex);

  unsigned char ivec[MAX_IVLENGTH];

  int dstLen = 0, tmpLen = 0;
  setIVec(ivec, iv64, key);

  EVP_DecryptInit_ex(&key->block_dec, NULL, NULL, NULL, ivec);
  EVP_DecryptUpdate(&key->block_dec, buf, &dstLen, buf, size);
  EVP_DecryptFinal_ex(&key->block_dec, buf + dstLen, &tmpLen);
  dstLen += tmpLen;

  if (dstLen != size) {
    RLOG(ERROR) << "decoding " << size << " bytes, got back " << dstLen << " ("
                << tmpLen << " in final_ex)";
  }

  return true;
}

bool SSL_Cipher::Enabled() { return true; }

}  // namespace encfs
