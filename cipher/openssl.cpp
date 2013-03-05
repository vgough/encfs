/*****************************************************************************
 * Author:   Valient Gough <vgough@pobox.com>
 *
 *****************************************************************************
 * Copyright (c) 2007-2013, Valient Gough
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

#include "cipher/openssl.h"

#include <cstring>
#include <ctime>
#include <pthread.h>
#include <sys/mman.h>
#include <sys/time.h>

#include <glog/logging.h>

#include "base/config.h"

#define NO_DES
#include <openssl/ssl.h>
#include <openssl/rand.h>
#ifndef OPENSSL_NO_ENGINE
#include <openssl/engine.h>
#endif

#include <openssl/blowfish.h>
#include <openssl/err.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <openssl/sha.h>

#include "base/Error.h"
#include "base/i18n.h"
#include "base/Mutex.h"
#include "base/Range.h"

#include "cipher/BlockCipher.h"
#include "cipher/MAC.h"
#include "cipher/MemoryPool.h"
#include "cipher/PBKDF.h"
#include "cipher/StreamCipher.h"

using namespace std;

namespace encfs {

const int MAX_KEYLENGTH = 64; // in bytes (256 bit)
const int MAX_IVLENGTH = 16;
const int KEY_CHECKSUM_BYTES = 4;

#ifndef MIN
inline int MIN(int a, int b)
{
  return (a < b) ? a : b;
}
#endif


// Base for {Block,Stream}Cipher implementation.
class OpenSSLCipher : public BlockCipher {
 public:
  OpenSSLCipher() {
    EVP_CIPHER_CTX_init( &enc );
    EVP_CIPHER_CTX_init( &dec );
  }

  virtual ~OpenSSLCipher() {
    EVP_CIPHER_CTX_cleanup( &enc );
    EVP_CIPHER_CTX_cleanup( &dec );
  }

  bool rekey(const EVP_CIPHER *cipher, const CipherKey &key) {
    VLOG(1) << "setting key length " << key.size();
    EVP_EncryptInit_ex( &enc, cipher, NULL, NULL, NULL);
    EVP_CIPHER_CTX_set_key_length( &enc, key.size() );
    EVP_CIPHER_CTX_set_padding( &enc, 0 );
    EVP_EncryptInit_ex( &enc, NULL, NULL, key.data(), NULL);

    EVP_DecryptInit_ex( &dec, cipher, NULL, NULL, NULL);
    EVP_CIPHER_CTX_set_key_length( &dec, key.size() );
    EVP_CIPHER_CTX_set_padding( &dec, 0 );
    EVP_DecryptInit_ex( &dec, NULL, NULL, key.data(), NULL);
    return true;
  }

  static bool randomize(CipherKey *key) {
    int result = RAND_bytes( key->data(), key->size() );
    if(result != 1)
    {
      char errStr[120]; // specs require string at least 120 bytes long..
      unsigned long errVal = 0;
      if((errVal = ERR_get_error()) != 0)
        LOG(ERROR) << "openssl error: " << ERR_error_string( errVal, errStr );

      return false;
    }
    return true;
  }
  
  static bool pseudoRandomize(byte *out, int length) {
    int result = RAND_pseudo_bytes( out, length );
    if(result != 1)
    {
      char errStr[120]; // specs require string at least 120 bytes long..
      unsigned long errVal = 0;
      if((errVal = ERR_get_error()) != 0)
        LOG(ERROR) << "openssl error: " << ERR_error_string( errVal, errStr );

      return false;
    }
    return true;
  }

  // Rekey with random key.
  bool rekey(const EVP_CIPHER *cipher, int keyLength) {
    CipherKey key(keyLength);

    if (!randomize(&key))
      return false;

    return rekey(cipher, key);
  }

  virtual int blockSize() const {
    return EVP_CIPHER_CTX_block_size(&enc);
  }

  virtual bool encrypt(const byte *ivec, const byte *in,
                       byte *out, int size) {
    int dstLen = 0, tmpLen = 0;
    EVP_EncryptInit_ex( &enc, NULL, NULL, NULL, ivec);
    EVP_EncryptUpdate( &enc, out, &dstLen, in, size);
    EVP_EncryptFinal_ex( &enc, out+dstLen, &tmpLen );
    dstLen += tmpLen;

    if (dstLen != size) {
      LOG(ERROR) << "encoding " << size
          << " bytes, got back " << dstLen << " (" << tmpLen << " in final_ex)";
      return false;
    }

    return true;
  }

  virtual bool decrypt(const byte *ivec, const byte *in,
                       byte *out, int size) {
    int dstLen = 0, tmpLen = 0;
    EVP_DecryptInit_ex( &dec, NULL, NULL, NULL, ivec);
    EVP_DecryptUpdate( &dec, out, &dstLen, in, size );
    EVP_DecryptFinal_ex( &dec, out+dstLen, &tmpLen );
    dstLen += tmpLen;

    if (dstLen != size) {
      LOG(ERROR) << "decoding " << size
          << " bytes, got back " << dstLen << " (" << tmpLen << " in final_ex)";
      return false;
    }

    return true;
  }

 private:
  EVP_CIPHER_CTX enc;
  EVP_CIPHER_CTX dec;
};


#if defined(HAVE_EVP_BF)
static Range BfKeyRange(128,256,32);
class BfCbcBlockCipher : public OpenSSLCipher {
 public:
  BfCbcBlockCipher() {}
  virtual ~BfCbcBlockCipher() {}

  virtual bool setKey(const CipherKey &key) {
    if (BfKeyRange.allowed(key.size() * 8))
      return rekey(EVP_bf_cbc(), key);
    else
      return false;
  }

  static Properties GetProperties() {
    Properties props;
    props.keySize = BfKeyRange;
    props.cipher = "Blowfish";
    props.mode = "CBC";
    props.library = "OpenSSL";
    return props;
  }
};
REGISTER_CLASS(BfCbcBlockCipher, BlockCipher);

class BfCfbStreamCipher : public OpenSSLCipher {
 public:
  BfCfbStreamCipher() {}
  virtual ~BfCfbStreamCipher() {}

  virtual bool setKey(const CipherKey &key) {
    return BfKeyRange.allowed(key.size() * 8) && rekey(EVP_bf_cfb(), key);
  }

  static Properties GetProperties() {
    Properties props;
    props.keySize = BfKeyRange;
    props.cipher = "Blowfish";
    props.mode = "CFB";
    props.library = "OpenSSL";
    return props;
  }
};
REGISTER_CLASS(BfCfbStreamCipher, StreamCipher);
#endif


#if defined(HAVE_EVP_AES)
static Range AesKeyRange(128,256,64);
class AesCbcBlockCipher : public OpenSSLCipher {
 public:
  AesCbcBlockCipher() {}
  virtual ~AesCbcBlockCipher() {}

  virtual bool setKey(const CipherKey& key) {
    const EVP_CIPHER *cipher = getCipher(key.size());
    return (cipher != NULL) && rekey(cipher, key);
  }

  static const EVP_CIPHER *getCipher(int keyLength) {
    switch(keyLength * 8)
    {
      case 128: return EVP_aes_128_cbc();
      case 192: return EVP_aes_192_cbc();
      case 256: return EVP_aes_256_cbc();
      default:
                LOG(INFO) << "Unsupported key length: " << keyLength;
                return NULL;
    }
  }

  static Properties GetProperties() {
    Properties props;
    props.keySize = AesKeyRange;
    props.cipher = "AES";
    props.mode = "CBC";
    props.library = "OpenSSL";
    return props;
  }
};
REGISTER_CLASS(AesCbcBlockCipher, BlockCipher);

class AesCfbStreamCipher : public OpenSSLCipher {
 public:
  AesCfbStreamCipher() {}
  virtual ~AesCfbStreamCipher() {}

  virtual bool setKey(const CipherKey& key) {
    const EVP_CIPHER *cipher = getCipher(key.size());
    return (cipher != NULL) && rekey(cipher, key);
  }

  static const EVP_CIPHER *getCipher(int keyLength) {
    switch(keyLength * 8)
    {
      case 128: return EVP_aes_128_cfb();
      case 192: return EVP_aes_192_cfb();
      case 256: return EVP_aes_256_cfb();
      default:
                LOG(INFO) << "Unsupported key length: " << keyLength;
                return NULL;
    }
  }

  static Properties GetProperties() {
    Properties props;
    props.keySize = AesKeyRange;
    props.cipher = "AES";
    props.mode = "CFB";
    props.library = "OpenSSL";
    return props;
  }
};
REGISTER_CLASS(AesCfbStreamCipher, StreamCipher);
#endif

#if defined(HAVE_EVP_AES_XTS)
static Range AesXtsKeyRange(128,256,128);
class AesXtsBlockCipher : public OpenSSLCipher {
 public:
  AesXtsBlockCipher() {}
  virtual ~AesXtsBlockCipher() {}

  virtual bool setKey(const CipherKey &key) {
    const EVP_CIPHER *cipher = getCipher(key.size());
    return (cipher != NULL) && rekey(cipher, key);
  }

  static const EVP_CIPHER *getCipher(int keyLength) {
    switch(keyLength * 8)
    {
      case 128: return EVP_aes_128_xts();
      case 256: return EVP_aes_256_xts();
      default:  return NULL;
    }
  }

  static Properties GetProperties() {
    Properties props;
    props.keySize = AesXtsKeyRange;
    props.cipher = "AES";
    props.mode = "XTS";
    props.library = "OpenSSL";
    return props;
  }
};
REGISTER_CLASS(AesXtsBlockCipher, BlockCipher);
#endif

class Sha1HMac : public MAC {
 public:
  Sha1HMac() {
    HMAC_CTX_init(&ctx);
  }
  virtual ~Sha1HMac() {
    HMAC_CTX_cleanup(&ctx);
  }

  virtual int outputSize() const {
    return 20; // 160 bit.
  }

  virtual bool setKey(const CipherKey &key) {
    HMAC_Init_ex(&ctx, key.data(), key.size(), EVP_sha1(), 0);
    return true;
  }

  virtual void reset() {
    HMAC_Init_ex(&ctx, 0, 0, 0, 0);
  }
 
  virtual bool update(const byte *in, int length) {
    HMAC_Update(&ctx, in, length);
    return true;
  }

  virtual bool write(byte *out) {
#ifdef HAVE_VALGRIND_MEMCHECK_H
    if (VALGRIND_CHECK_MEM_IS_ADDRESSABLE(out, 20) != 0) {
      return false;
    }
#endif
    unsigned int outSize = 0;
    HMAC_Final(&ctx, (unsigned char *)out, &outSize);
    CHECK_EQ(outputSize(), outSize) << "Invalid HMAC output size";
    return true;
  }

  static Properties GetProperties() {
    Properties props;
    props.blockSize = 20;
    props.hashFunction = "SHA-1";
    props.mode = "HMAC";
    props.library = "OpenSSL";
    return props;
  }
 private:
  HMAC_CTX ctx;
};
REGISTER_CLASS(Sha1HMac, MAC);


class PbkdfPkcs5HmacSha1 : public PBKDF {
 public:
  PbkdfPkcs5HmacSha1() {}
  virtual ~PbkdfPkcs5HmacSha1() {}

  virtual bool makeKey(const char *password, int passwordLength,
                       const byte *salt, int saltLength,
                       int numIterations,
                       CipherKey *outKey) {
    return PKCS5_PBKDF2_HMAC_SHA1(
        password, passwordLength,
        const_cast<byte *>(salt), saltLength,
        numIterations, outKey->size(), outKey->data()) == 1;
  }

  virtual CipherKey randomKey(int length) {
    CipherKey key(length);
    if (!OpenSSLCipher::randomize(&key))
      key.reset();
    return key;
  }

  virtual bool pseudoRandom(byte *out, int length) {
    return OpenSSLCipher::pseudoRandomize(out, length);
  }

  static Properties GetProperties() {
    Properties props;
    props.mode = NAME_PKCS5_PBKDF2_HMAC_SHA1;
    props.library = "OpenSSL";
    return props;
  }
};
REGISTER_CLASS(PbkdfPkcs5HmacSha1, PBKDF);


unsigned long pthreads_thread_id()
{
  return (unsigned long)pthread_self();
}

static pthread_mutex_t *crypto_locks = NULL;
void pthreads_locking_callback( int mode, int n,
    const char *caller_file, int caller_line )
{
  (void)caller_file;
  (void)caller_line;

  if(!crypto_locks)
  {
    VLOG(1) << "Allocating " << CRYPTO_num_locks() << " locks for OpenSSL";
    crypto_locks = new pthread_mutex_t[ CRYPTO_num_locks() ];
    for(int i=0; i<CRYPTO_num_locks(); ++i)
      pthread_mutex_init( crypto_locks+i, 0 );
  }

  if(mode & CRYPTO_LOCK)
  {
    pthread_mutex_lock( crypto_locks + n );
  } else
  {
    pthread_mutex_unlock( crypto_locks + n );
  }
}

void pthreads_locking_cleanup()
{
  if(crypto_locks)
  {
    for(int i=0; i<CRYPTO_num_locks(); ++i)
      pthread_mutex_destroy( crypto_locks+i );
    delete[] crypto_locks;
    crypto_locks = NULL;
  }
}

void OpenSSL::init(bool threaded)
{
  // initialize the SSL library
  SSL_load_error_strings();
  SSL_library_init();

  unsigned int randSeed = 0;
  RAND_bytes( (unsigned char*)&randSeed, sizeof(randSeed) );
  srand( randSeed );

#ifndef OPENSSL_NO_ENGINE
  /* Load all bundled ENGINEs into memory and make them visible */
  ENGINE_load_builtin_engines();
  /* Register all of them for every algorithm they collectively implement */
  ENGINE_register_all_complete();
#endif // NO_ENGINE

  if(threaded)
  {
    // provide locking functions to OpenSSL since we'll be running with
    // threads accessing openssl in parallel.
    CRYPTO_set_id_callback( pthreads_thread_id );
    CRYPTO_set_locking_callback( pthreads_locking_callback );
  }
}

void OpenSSL::shutdown(bool threaded)
{
#ifndef OPENSSL_NO_ENGINE
  ENGINE_cleanup();
#endif

  if(threaded)
    pthreads_locking_cleanup();
}

void OpenSSL::registerCiphers()
{
  // Nothing required.. Just need to reference this code block to get static
  // initializers.
}

}  // namespace encfs
