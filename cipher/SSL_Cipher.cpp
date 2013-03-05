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

#include "base/config.h"

#include <openssl/blowfish.h>
#include <openssl/sha.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <openssl/hmac.h>

#include "cipher/SSL_Cipher.h"
#include "cipher/MemoryPool.h"
#include "base/Error.h"
#include "base/Mutex.h"
#include "base/Range.h"

#include <cstring>
#include <ctime>

#include <sys/mman.h>
#include <sys/time.h>

#include <glog/logging.h>

#include "base/i18n.h"

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

/*
   This produces the same result as OpenSSL's EVP_BytesToKey.  The difference
   is that here we can explicitly specify the key size, instead of relying on
   the state of EVP_CIPHER struct.  EVP_BytesToKey will only produce 128 bit
   keys for the EVP Blowfish interface, which is not what we want.

   DEPRECATED: this is here for backward compatibilty only.  Use PBKDF
*/
int BytesToKey( int keyLen, int ivLen, const EVP_MD *md,
               const byte *data, int dataLen, 
               unsigned int rounds, byte *key, byte *iv)
{
  if( data == NULL || dataLen == 0 )
    return 0; // OpenSSL returns nkey here, but why?  It is a failure..
    
  byte mdBuf[ EVP_MAX_MD_SIZE ];
  unsigned int mds=0;
  int addmd =0;
  int nkey = key ? keyLen : 0;
  int niv = iv ? ivLen : 0;

  EVP_MD_CTX cx;
  EVP_MD_CTX_init( &cx );

  for(;;)
  {
    EVP_DigestInit_ex( &cx, md, NULL );
    if( addmd++ )
      EVP_DigestUpdate( &cx, mdBuf, mds );
    EVP_DigestUpdate( &cx, data, dataLen );
    EVP_DigestFinal_ex( &cx, mdBuf, &mds );

    for(unsigned int i=1; i < rounds; ++i)
    {
      EVP_DigestInit_ex( &cx, md, NULL );
      EVP_DigestUpdate( &cx, mdBuf, mds );
      EVP_DigestFinal_ex( &cx, mdBuf, &mds );
    }

    int offset = 0;
    int toCopy = MIN( nkey, (int)mds - offset );
    if( toCopy )
    {
      memcpy( key, mdBuf+offset, toCopy );
      key += toCopy;
      nkey -= toCopy;
      offset += toCopy;
    }
    toCopy = MIN( niv, (int)mds - offset );
    if( toCopy )
    {
      memcpy( iv, mdBuf+offset, toCopy );
      iv += toCopy;
	    niv -= toCopy;
      offset += toCopy;
    }
    if((nkey == 0) && (niv == 0)) break;
  }
  EVP_MD_CTX_cleanup( &cx );
  OPENSSL_cleanse( mdBuf, sizeof(mdBuf) );

  return keyLen;
}

long time_diff(const timeval &end, const timeval &start)
{
  return (end.tv_sec - start.tv_sec) * 1000 * 1000 +
      (end.tv_usec - start.tv_usec);
}

int SSL_Cipher::TimedPBKDF2(const char *pass, int passlen,
                            const byte *salt, int saltlen,
                            int keylen, byte *out,
                            long desiredPDFTime)
{
  int iter = 1000;
  timeval start, end;

  for(;;)
  {
    gettimeofday( &start, 0 );
    int res = PKCS5_PBKDF2_HMAC_SHA1(
        pass, passlen, const_cast<byte*>(salt), saltlen, 
        iter, keylen, out);
    if(res != 1)
      return -1;

    gettimeofday( &end, 0 );

    long delta = time_diff(end, start);
    if(delta < desiredPDFTime / 8)
    {
      iter *= 4;
    } else if(delta < (5 * desiredPDFTime / 6))
    {   
      // estimate number of iterations to get close to desired time
      iter = (int)((double)iter * (double)desiredPDFTime 
                   / (double)delta);
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
// - Version 3:1 adds ssl/aes_xts
static Interface BlowfishInterface = makeInterface( "ssl/blowfish", 3, 0, 2 );
static Interface AESInterface = makeInterface( "ssl/aes", 3, 0, 2 );
static Interface AesXtsInterface = makeInterface( "ssl/aes_xts", 3, 1, 2 );

#if defined(HAVE_EVP_BF)

static Range BFKeyRange(128,256,32);
static Range BFBlockRange(64,4096,8);

static shared_ptr<Cipher> NewBFCipher( const Interface &iface, int keyLen )
{
  if( keyLen <= 0 )
    keyLen = 160;

  keyLen = BFKeyRange.closest( keyLen );

  const EVP_CIPHER *blockCipher = EVP_bf_cbc();
  const EVP_CIPHER *streamCipher = EVP_bf_cfb();

  return shared_ptr<Cipher>( new SSL_Cipher(iface, BlowfishInterface,
                                            blockCipher, streamCipher, keyLen / 8) );
}

static bool BF_Cipher_registered = Cipher::Register(
    "Blowfish", 
    // xgroup(setup)
    gettext_noop("8 byte block cipher"), 
    BlowfishInterface, BFKeyRange, BFBlockRange, NewBFCipher, true);
#endif


#if defined(HAVE_EVP_AES)

static Range AESKeyRange(128,256,64);
static Range AESBlockRange(64,4096,16);

static shared_ptr<Cipher> NewAESCipher( const Interface &iface, int keyLen )
{
  if( keyLen <= 0 )
    keyLen = 192;

  keyLen = AESKeyRange.closest( keyLen );

  const EVP_CIPHER *blockCipher = 0;
  const EVP_CIPHER *streamCipher = 0;

  switch(keyLen)
  {
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

  return shared_ptr<Cipher>( new SSL_Cipher(iface, AESInterface, 
                                            blockCipher, streamCipher, keyLen / 8) );
}

static bool AES_Cipher_registered = Cipher::Register(
    "AES", "16 byte block cipher", 
    AESInterface, AESKeyRange, AESBlockRange, NewAESCipher, true);
#endif

#if defined(HAVE_EVP_AES_XTS)

static Range AesXtsKeyRange(128,256,128);
static Range AesXtsBlockRange(1024,8192,256);

static shared_ptr<Cipher> NewAesXtsCipher( const Interface &iface, int keyLen )
{
  if( keyLen <= 0 )
    keyLen = 256;

  keyLen = AesXtsKeyRange.closest( keyLen );

  const EVP_CIPHER *blockCipher = 0;

  switch(keyLen)
  {
    case 128:
      blockCipher = EVP_aes_128_xts();
      break;

    case 256:
    default:
      blockCipher = EVP_aes_256_xts();
      break;
  }

  // XTS uses 2 keys, so the key size is doubled here.
  // Eg XTS-AES-256 uses two 256 bit keys.
  return shared_ptr<Cipher>( new SSL_Cipher(iface, AesXtsInterface, 
                                            blockCipher, NULL, 2 * keyLen / 8) );
}

static bool AES_XTS_Cipher_registered = Cipher::Register(
    "AES_XTS", "Tweakable wide-block cipher", 
    AesXtsInterface, AesXtsKeyRange, AesXtsBlockRange, NewAesXtsCipher, false);
#endif

class SSLKey : public AbstractCipherKey
{
 public:
  pthread_mutex_t mutex;

  unsigned int keySize; // in bytes
  unsigned int ivLength;

  // key data is first _keySize bytes, 
  // followed by iv of _ivLength bytes,
  SecureMem buf;

  EVP_CIPHER_CTX block_enc;
  EVP_CIPHER_CTX block_dec;
  EVP_CIPHER_CTX stream_enc;
  EVP_CIPHER_CTX stream_dec;

  HMAC_CTX mac_ctx;

  SSLKey(int keySize, int ivLength);
  ~SSLKey();
};

SSLKey::SSLKey(int keySize_, int ivLength_)
  : buf(keySize_ + ivLength_)
{
  rAssert(keySize_ >= 8);
  rAssert(ivLength_ >= 8);

  this->keySize = keySize_;
  this->ivLength = ivLength_;
  pthread_mutex_init( &mutex, 0 );
}

SSLKey::~SSLKey()
{
  keySize = 0;
  ivLength = 0;

  EVP_CIPHER_CTX_cleanup( &block_enc );
  EVP_CIPHER_CTX_cleanup( &block_dec );

  EVP_CIPHER_CTX_cleanup( &stream_enc );
  EVP_CIPHER_CTX_cleanup( &stream_dec );

  HMAC_CTX_cleanup( &mac_ctx );

  pthread_mutex_destroy( &mutex );
}

inline byte* KeyData( const shared_ptr<SSLKey> &key )
{
  return (byte *)key->buf.data;
}

inline byte* IVData( const shared_ptr<SSLKey> &key )
{
  return (byte *)key->buf.data + key->keySize;
}

void initKey(const shared_ptr<SSLKey> &key, const EVP_CIPHER *_blockCipher,
             const EVP_CIPHER *_streamCipher, int _keySize)
{
  Lock lock( key->mutex );
  // initialize the cipher context once so that we don't have to do it for
  // every block..
  EVP_CIPHER_CTX_init( &key->block_enc );
  EVP_CIPHER_CTX_init( &key->block_dec );
  EVP_EncryptInit_ex( &key->block_enc, _blockCipher, NULL, NULL, NULL);
  EVP_DecryptInit_ex( &key->block_dec, _blockCipher, NULL, NULL, NULL);
  EVP_CIPHER_CTX_set_key_length( &key->block_enc, _keySize );
  EVP_CIPHER_CTX_set_key_length( &key->block_dec, _keySize );
  EVP_CIPHER_CTX_set_padding( &key->block_enc, 0 );
  EVP_CIPHER_CTX_set_padding( &key->block_dec, 0 );
  EVP_EncryptInit_ex( &key->block_enc, NULL, NULL, KeyData(key), NULL);
  EVP_DecryptInit_ex( &key->block_dec, NULL, NULL, KeyData(key), NULL);

  EVP_CIPHER_CTX_init( &key->stream_enc );
  EVP_CIPHER_CTX_init( &key->stream_dec );
  if (_streamCipher != NULL)
  {
    EVP_EncryptInit_ex( &key->stream_enc, _streamCipher, NULL, NULL, NULL);
    EVP_DecryptInit_ex( &key->stream_dec, _streamCipher, NULL, NULL, NULL);
    EVP_CIPHER_CTX_set_key_length( &key->stream_enc, _keySize );
    EVP_CIPHER_CTX_set_key_length( &key->stream_dec, _keySize );
    EVP_CIPHER_CTX_set_padding( &key->stream_enc, 0 );
    EVP_CIPHER_CTX_set_padding( &key->stream_dec, 0 );
    EVP_EncryptInit_ex( &key->stream_enc, NULL, NULL, KeyData(key), NULL);
    EVP_DecryptInit_ex( &key->stream_dec, NULL, NULL, KeyData(key), NULL);
  }

  HMAC_CTX_init( &key->mac_ctx );
  HMAC_Init_ex( &key->mac_ctx, KeyData(key), _keySize, EVP_sha1(), 0 );
}


SSL_Cipher::SSL_Cipher(const Interface &iface_,
                       const Interface &realIface_,
                       const EVP_CIPHER *blockCipher, 
                       const EVP_CIPHER *streamCipher,
                       int keySize_)
{
  this->iface = iface_;
  this->realIface = realIface_;
  this->_blockCipher = blockCipher;
  this->_streamCipher = streamCipher;
  this->_keySize = keySize_;
  this->_ivLength = EVP_CIPHER_iv_length( _blockCipher );

  rAssert(_ivLength == 8 || _ivLength == 16);
  rAssert(_ivLength <= _keySize);

  VLOG(1) << "allocated cipher " << iface.name() 
          << ", keySize " << _keySize
          << ", ivlength " << _ivLength;

  // EVP_CIPHER_key_length isn't useful for variable-length ciphers like
  // Blowfish. Version 1 relied upon it incorrectly.
  if( (EVP_CIPHER_key_length( _blockCipher ) != (int )_keySize) 
     && iface.major() == 1)
  {
    LOG(WARNING) << "Running in backward compatibilty mode for 1.0 - \n"
             << "key is really " << EVP_CIPHER_key_length( _blockCipher ) * 8
             << " bits, not " << _keySize * 8;
  }
}

SSL_Cipher::~SSL_Cipher()
{
}

Interface SSL_Cipher::interface() const
{
  return realIface;
}

/*
   Create a key from the password.
   Use SHA to distribute entropy from the password into the key.

   This algorithm must remain constant for backward compatibility, as this key
   is used to encipher/decipher the master key.
*/
CipherKey SSL_Cipher::newKey(const char *password, int passwdLength,
                             int &iterationCount, long desiredDuration,
                             const byte *salt, int saltLen)
{
  shared_ptr<SSLKey> key( new SSLKey( _keySize, _ivLength) );

  if(iterationCount == 0)
  {
    // timed run, fills in iteration count
    int res = TimedPBKDF2(password, passwdLength, 
                          salt, saltLen,
                          _keySize+_ivLength, KeyData(key),
                          1000 * desiredDuration);
    if(res <= 0)
    {
      LOG(ERROR) << "openssl error, PBKDF2 failed";
      return CipherKey();
    } else
      iterationCount = res;
  } else
  {
    // known iteration length
    if(PKCS5_PBKDF2_HMAC_SHA1(
            password, passwdLength, 
            const_cast<byte*>(salt), saltLen, 
            iterationCount, _keySize + _ivLength, KeyData(key)) != 1)
    {
      LOG(ERROR) << "openssl error, PBKDF2 failed";
      return CipherKey();
    }
  }

  initKey( key, _blockCipher, _streamCipher, _keySize );

  return key;
}

CipherKey SSL_Cipher::newKey(const char *password, int passwdLength)
{
  shared_ptr<SSLKey> key( new SSLKey( _keySize, _ivLength) );

  int bytes = 0;
  if( iface.major() > 1 )
  {
    // now we use BytesToKey, which can deal with Blowfish keys larger then
    // 128 bits.
    bytes = BytesToKey( _keySize, _ivLength, EVP_sha1(), 
                       (byte *)password, passwdLength, 16,
                       KeyData(key), IVData(key) );

    // the reason for moving from EVP_BytesToKey to BytesToKey function..
    if(bytes != (int)_keySize)
    {
      LOG(WARNING) << "newKey: BytesToKey returned " << bytes 
                   << ", expecting " << _keySize << " key bytes";
    }
  } else
  {
    // for backward compatibility with filesystems created with 1:0
    bytes = EVP_BytesToKey( _blockCipher, EVP_sha1(), NULL,
                           (byte *)password, passwdLength, 16,
                           KeyData(key), IVData(key) );
  }

  initKey( key, _blockCipher, _streamCipher, _keySize );

  return key;
}

/*
   Create a random key.
   We use the OpenSSL library to generate random bytes, then take the hash of
   those bytes to use as the key.

   This algorithm can change at any time without affecting backward
   compatibility.
*/
CipherKey SSL_Cipher::newRandomKey()
{
  const int bufLen = MAX_KEYLENGTH;
  byte tmpBuf[ bufLen ];
  int saltLen = 20;
  byte saltBuf[ saltLen ];

  if(!randomize(tmpBuf, bufLen, true) ||
     !randomize(saltBuf, saltLen, true))
    return CipherKey();

  shared_ptr<SSLKey> key( new SSLKey( _keySize, _ivLength) );

  // doesn't need to be versioned, because a random key is a random key..
  // Doesn't need to be reproducable..
  if(PKCS5_PBKDF2_HMAC_SHA1((char*)tmpBuf, bufLen, saltBuf, saltLen, 
                            1000, _keySize + _ivLength, KeyData(key)) != 1)
  {
    LOG(ERROR) << "openssl error, PBKDF2 failed";
    return CipherKey();
  }

  OPENSSL_cleanse(tmpBuf, bufLen);

  initKey( key, _blockCipher, _streamCipher, _keySize );

  return key;
}

/*
   Compute a 64-bit check value for the data using HMAC.
*/
static uint64_t _checksum_64(SSLKey *key,
                             const byte *data,
                             int dataLen,
                             uint64_t *chainedIV)
{
  rAssert( dataLen > 0 );
  Lock lock( key->mutex );

  byte md[EVP_MAX_MD_SIZE];
  unsigned int mdLen = EVP_MAX_MD_SIZE;

  HMAC_Init_ex( &key->mac_ctx, 0, 0, 0, 0 );
  HMAC_Update( &key->mac_ctx, data, dataLen );
  if(chainedIV)
  {
    // toss in the chained IV as well
    uint64_t tmp = *chainedIV;
    byte h[8];
    for(unsigned int i=0; i<8; ++i)
    {
      h[i] = tmp & 0xff;
      tmp >>= 8;
    }

    HMAC_Update( &key->mac_ctx, h, 8 );
  }

  HMAC_Final( &key->mac_ctx, md, &mdLen );

  rAssert(mdLen >= 8);

  // chop this down to a 64bit value..
  byte h[8] = {0,0,0,0,0,0,0,0};
  for(unsigned int i=0; i<(mdLen-1); ++i)
    h[i%8] ^= (byte)(md[i]);

  uint64_t value = (uint64_t)h[0];
  for(int i=1; i<8; ++i)
    value = (value << 8) | (uint64_t)h[i];

  return value;
}

bool SSL_Cipher::randomize( byte *buf, int len,
                           bool strongRandom ) const
{
  // to avoid warnings of uninitialized data from valgrind
  memset(buf, 0, len); 
  int result;
  if(strongRandom)
    result = RAND_bytes( buf, len );
  else
    result = RAND_pseudo_bytes( buf, len );

  if(result != 1)
  {
    char errStr[120]; // specs require string at least 120 bytes long..
    unsigned long errVal = 0;
    if((errVal = ERR_get_error()) != 0)
      LOG(ERROR) << "openssl error: " << ERR_error_string( errVal, errStr );

    return false;
  } else
    return true;
}

uint64_t SSL_Cipher::MAC_64( const byte *data, int len,
                            const CipherKey &key, uint64_t *chainedIV ) const
{
  shared_ptr<SSLKey> mk = dynamic_pointer_cast<SSLKey>(key);
  uint64_t tmp = _checksum_64( mk.get(), data, len, chainedIV );

  if(chainedIV)
    *chainedIV = tmp;

  return tmp;
}

CipherKey SSL_Cipher::readKey(const byte *data, 
                              const CipherKey &masterKey, bool checkKey)
{
  shared_ptr<SSLKey> mk = dynamic_pointer_cast<SSLKey>(masterKey);
  rAssert(mk->keySize == _keySize);

  byte tmpBuf[ 2 * MAX_KEYLENGTH ];

  // First N bytes are checksum bytes.
  unsigned int checksum = 0;
  for(int i=0; i<KEY_CHECKSUM_BYTES; ++i)
    checksum = (checksum << 8) | (unsigned int)data[i];

  if (_streamCipher != NULL)
  {
    memcpy( tmpBuf, data+KEY_CHECKSUM_BYTES, _keySize + _ivLength );
    streamDecode(tmpBuf, _keySize + _ivLength, checksum, masterKey);
  } else
  {
    memcpy( tmpBuf, data+KEY_CHECKSUM_BYTES, 2 * _keySize );
    blockDecode(tmpBuf, 2 * _keySize, checksum, masterKey);
  }

  // check for success
  unsigned int checksum2 = MAC_32( tmpBuf, _keySize + _ivLength, masterKey );
  if(checksum2 != checksum && checkKey)
  {
    VLOG(1) << "checksum mismatch: expected " << checksum 
            << ", got " << checksum2
            << "on decode of " << _keySize + _ivLength << " bytes";
    OPENSSL_cleanse(tmpBuf, sizeof(tmpBuf));
    return CipherKey();
  }

  shared_ptr<SSLKey> key( new SSLKey( _keySize, _ivLength) );

  rAssert(_keySize + _ivLength == (unsigned int)key->buf.size );
  memcpy( key->buf.data, tmpBuf, key->buf.size );
  OPENSSL_cleanse(tmpBuf, sizeof(tmpBuf));

  initKey( key, _blockCipher, _streamCipher, _keySize );

  return key;
}

void SSL_Cipher::writeKey(const CipherKey &ckey, byte *data, 
                          const CipherKey &masterKey)
{
  shared_ptr<SSLKey> key = dynamic_pointer_cast<SSLKey>(ckey);
  rAssert(key->keySize == _keySize);
  rAssert(key->ivLength == _ivLength);

  shared_ptr<SSLKey> mk = dynamic_pointer_cast<SSLKey>(masterKey);
  rAssert(mk->keySize == _keySize);
  rAssert(mk->ivLength == _ivLength);

  byte tmpBuf[ 2 * MAX_KEYLENGTH ];

  unsigned int bufLen = key->buf.size;
  rAssert(_keySize + _ivLength == bufLen );
  memcpy( tmpBuf, key->buf.data, bufLen );

  unsigned int checksum = MAC_32( tmpBuf, bufLen, masterKey );

  if (_streamCipher != NULL)
    streamEncode(tmpBuf, bufLen, checksum, masterKey);
  else
  {
    bufLen = 2 * _keySize;
    blockEncode(tmpBuf, bufLen, checksum, masterKey);
  }

  memcpy( data+KEY_CHECKSUM_BYTES, tmpBuf, bufLen );

  // first N bytes contain HMAC derived checksum..
  for(int i=1; i<=KEY_CHECKSUM_BYTES; ++i)
  {
    data[KEY_CHECKSUM_BYTES-i] = checksum & 0xff;
    checksum >>= 8;
  }

  OPENSSL_cleanse(tmpBuf, sizeof(tmpBuf));
}

bool SSL_Cipher::compareKey( const CipherKey &A, const CipherKey &B) const
{
  shared_ptr<SSLKey> key1 = dynamic_pointer_cast<SSLKey>(A);
  shared_ptr<SSLKey> key2 = dynamic_pointer_cast<SSLKey>(B);

  rAssert(key1->buf.size == key2->buf.size);

  if(memcmp(key1->buf.data, key2->buf.data, key1->buf.size) != 0)
    return false;
  else
    return true;
}

int SSL_Cipher::encodedKeySize() const
{
  if (_streamCipher != NULL)
    return _keySize + _ivLength + KEY_CHECKSUM_BYTES;
  else
    return 2 * _keySize + KEY_CHECKSUM_BYTES;
}

int SSL_Cipher::keySize() const
{
  return _keySize;
}

int SSL_Cipher::cipherBlockSize() const
{
  int size = EVP_CIPHER_block_size( _blockCipher );
  // OpenSSL (1.0.1-4ubuntu5.5) reports a block size of 1 for aes_xts.
  // If this happens, use a single key width (ie 32 bytes for aes-xts-256).
  if (size == 1)
    size = _keySize / 2;
  return size;
}

void SSL_Cipher::setIVec(byte *ivec, uint64_t seed,
                         const shared_ptr<SSLKey> &key) const
{
  if (iface.major() >= 3)
  {
    memcpy( ivec, IVData(key), _ivLength );

    byte md[EVP_MAX_MD_SIZE];
    unsigned int mdLen = EVP_MAX_MD_SIZE;

    for(int i=0; i<8; ++i)
    {
      md[i] = (byte)(seed & 0xff);
      seed >>= 8;
    }

    // combine ivec and seed with HMAC
    HMAC_Init_ex( &key->mac_ctx, 0, 0, 0, 0 );
    HMAC_Update( &key->mac_ctx, ivec, _ivLength );
    HMAC_Update( &key->mac_ctx, md, 8 );
    HMAC_Final( &key->mac_ctx, md, &mdLen );
    rAssert(mdLen >= _ivLength);

    memcpy( ivec, md, _ivLength );
  } else
  {
    setIVec_old(ivec, seed, key);
  }
}

// Deprecated: For backward compatibility only.
// A watermark attack was discovered against this IV setup.  If an attacker
// could get a victim to store a carefully crafted file, they could later
// determine if the victim had the file in encrypted storage (without decrypting
// the file).
void SSL_Cipher::setIVec_old(byte *ivec,
                             unsigned int seed,
                             const shared_ptr<SSLKey> &key) const
{
  unsigned int var1 = 0x060a4011 * seed; 
  unsigned int var2 = 0x0221040d * (seed ^ 0xD3FEA11C);
    
  memcpy( ivec, IVData(key), _ivLength );

  ivec[0] ^= (var1 >> 24) & 0xff;
  ivec[1] ^= (var2 >> 16) & 0xff;
  ivec[2] ^= (var1 >> 8 ) & 0xff;
  ivec[3] ^= (var2      ) & 0xff;
  ivec[4] ^= (var2 >> 24) & 0xff;
  ivec[5] ^= (var1 >> 16) & 0xff;
  ivec[6] ^= (var2 >> 8 ) & 0xff;
  ivec[7] ^= (var1      ) & 0xff;

  if(_ivLength > 8)
  {
    ivec[8+0] ^= (var1      ) & 0xff;
    ivec[8+1] ^= (var2 >> 8 ) & 0xff;
    ivec[8+2] ^= (var1 >> 16) & 0xff;
    ivec[8+3] ^= (var2 >> 24) & 0xff;
    ivec[8+4] ^= (var1 >> 24) & 0xff;
    ivec[8+5] ^= (var2 >> 16) & 0xff;
    ivec[8+6] ^= (var1 >> 8 ) & 0xff;
    ivec[8+7] ^= (var2      ) & 0xff;
  }
}

static void flipBytes(byte *buf, int size)
{
  byte revBuf[64];

  int bytesLeft = size;
  while(bytesLeft)
  {
    int toFlip = MIN( (int)sizeof(revBuf), bytesLeft );

    for(int i=0; i<toFlip; ++i)
      revBuf[i] = buf[toFlip - (i+1)];

    memcpy( buf, revBuf, toFlip );
    bytesLeft -= toFlip;
    buf += toFlip;
  }
  memset(revBuf, 0, sizeof(revBuf));
}

static void shuffleBytes(byte *buf, int size)
{
  for(int i=0; i<size-1; ++i)
    buf[i+1] ^= buf[i];
}

static void unshuffleBytes(byte *buf, int size)
{
  for(int i=size-1; i; --i)
    buf[i] ^= buf[i-1];
}

/* Partial blocks are encoded with a stream cipher.  We make multiple passes on
   the data to ensure that the ends of the data depend on each other.
 */
bool SSL_Cipher::streamEncode(byte *buf, int size, 
                              uint64_t iv64, const CipherKey &ckey) const
{
  rAssert( size > 0 );
  shared_ptr<SSLKey> key = dynamic_pointer_cast<SSLKey>(ckey);
  rAssert(key->keySize == _keySize);
  rAssert(key->ivLength == _ivLength);
  rAssert( key->stream_enc.key_len > 0 );

  Lock lock( key->mutex );

  byte ivec[ MAX_IVLENGTH ];
  int dstLen=0, tmpLen=0;

  shuffleBytes( buf, size );

  setIVec( ivec, iv64, key );
  EVP_EncryptInit_ex( &key->stream_enc, NULL, NULL, NULL, ivec);
  EVP_EncryptUpdate( &key->stream_enc, buf, &dstLen, buf, size );
  EVP_EncryptFinal_ex( &key->stream_enc, buf+dstLen, &tmpLen );

  flipBytes( buf, size );
  shuffleBytes( buf, size );

  setIVec( ivec, iv64 + 1, key );
  EVP_EncryptInit_ex( &key->stream_enc, NULL, NULL, NULL, ivec);
  EVP_EncryptUpdate( &key->stream_enc, buf, &dstLen, buf, size );
  EVP_EncryptFinal_ex( &key->stream_enc, buf+dstLen, &tmpLen );

  dstLen += tmpLen;
  LOG_IF(ERROR, dstLen != size) << "encoding " << size 
    << " bytes, got back " << dstLen << " (" << tmpLen << " in final_ex)";

  return true;
}

bool SSL_Cipher::streamDecode(byte *buf, int size, 
                              uint64_t iv64, const CipherKey &ckey) const
{
  rAssert( size > 0 );
  shared_ptr<SSLKey> key = dynamic_pointer_cast<SSLKey>(ckey);
  rAssert(key->keySize == _keySize);
  rAssert(key->ivLength == _ivLength);
  rAssert( key->stream_dec.key_len > 0 );

  Lock lock( key->mutex );

  byte ivec[ MAX_IVLENGTH ];
  int dstLen=0, tmpLen=0;

  setIVec( ivec, iv64 + 1, key );
  EVP_DecryptInit_ex( &key->stream_dec, NULL, NULL, NULL, ivec);
  EVP_DecryptUpdate( &key->stream_dec, buf, &dstLen, buf, size );
  EVP_DecryptFinal_ex( &key->stream_dec, buf+dstLen, &tmpLen );

  unshuffleBytes( buf, size );
  flipBytes( buf, size );

  setIVec( ivec, iv64, key );
  EVP_DecryptInit_ex( &key->stream_dec, NULL, NULL, NULL, ivec);
  EVP_DecryptUpdate( &key->stream_dec, buf, &dstLen, buf, size );
  EVP_DecryptFinal_ex( &key->stream_dec, buf+dstLen, &tmpLen );

  unshuffleBytes( buf, size );

  dstLen += tmpLen;
  LOG_IF(ERROR, dstLen != size) << "encoding " << size
    << " bytes, got back " << dstLen << " (" << tmpLen << " in final_ex)";

  return true;
}


bool SSL_Cipher::blockEncode(byte *buf, int size, 
                             uint64_t iv64, const CipherKey &ckey ) const
{
  rAssert( size > 0 );
  shared_ptr<SSLKey> key = dynamic_pointer_cast<SSLKey>(ckey);
  rAssert(key->keySize == _keySize);
  rAssert(key->ivLength == _ivLength);

  // data must be integer number of blocks
  const int blockMod = size % EVP_CIPHER_CTX_block_size( &key->block_enc );
  rAssert(blockMod == 0);

  Lock lock( key->mutex );

  byte ivec[ MAX_IVLENGTH ];

  int dstLen = 0, tmpLen = 0;
  setIVec( ivec, iv64, key );

  EVP_EncryptInit_ex( &key->block_enc, NULL, NULL, NULL, ivec);
  EVP_EncryptUpdate( &key->block_enc, buf, &dstLen, buf, size );
  EVP_EncryptFinal_ex( &key->block_enc, buf+dstLen, &tmpLen );
  dstLen += tmpLen;

  LOG_IF(ERROR, dstLen != size) << "encoding " << size
    << " bytes, got back " << dstLen << " (" << tmpLen << " in final_ex)";

  return true;
}

bool SSL_Cipher::blockDecode(byte *buf, int size, 
                             uint64_t iv64, const CipherKey &ckey ) const
{
  rAssert( size > 0 );
  shared_ptr<SSLKey> key = dynamic_pointer_cast<SSLKey>(ckey);
  rAssert(key->keySize == _keySize);
  rAssert(key->ivLength == _ivLength);

  // data must be integer number of blocks
  const int blockMod = size % EVP_CIPHER_CTX_block_size( &key->block_dec );
  rAssert(blockMod == 0);

  Lock lock( key->mutex );

  byte ivec[ MAX_IVLENGTH ];

  int dstLen = 0, tmpLen = 0;
  setIVec( ivec, iv64, key );

  EVP_DecryptInit_ex( &key->block_dec, NULL, NULL, NULL, ivec);
  EVP_DecryptUpdate( &key->block_dec, buf, &dstLen, buf, size );
  EVP_DecryptFinal_ex( &key->block_dec, buf+dstLen, &tmpLen );
  dstLen += tmpLen;

  LOG_IF(ERROR, dstLen != size) << "decoding " << size
    << " bytes, got back " << dstLen << " (" << tmpLen << " in final_ex)";

  return true;
}

bool SSL_Cipher::Enabled()
{
  return true;
}

bool SSL_Cipher::hasStreamMode() const
{
  return false;
}

}  // namespace encfs
