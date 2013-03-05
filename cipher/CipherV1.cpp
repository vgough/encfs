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

#include "cipher/CipherV1.h"
#include "base/config.h"

#include <cstring>
#include <ctime>

#include <sys/mman.h>
#include <sys/time.h>

#include <glog/logging.h>

#ifdef HAVE_VALGRIND_MEMCHECK_H
#include <valgrind/memcheck.h>
#endif

#include "base/base64.h"
#include "base/Error.h"
#include "base/i18n.h"
#include "base/Mutex.h"
#include "base/Range.h"

#include "cipher/MemoryPool.h"
#include "cipher/MAC.h"
#include "cipher/BlockCipher.h"
#include "cipher/PBKDF.h"
#include "cipher/StreamCipher.h"

#ifdef WITH_OPENSSL
#include "cipher/openssl.h"
#endif

using std::list;
using std::string;
using std::vector;

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

void CipherV1::init(bool threaded) {
#ifdef WITH_OPENSSL
  OpenSSL::init(threaded);
#endif
}

void CipherV1::shutdown(bool threaded) {
#ifdef WITH_OPENSSL
  OpenSSL::shutdown(threaded);
#endif
}

/*
   DEPRECATED: this is here for backward compatibilty only.  Use PBKDF

   This duplicated some code in OpenSSL, correcting an issue with key lengths
   produced for Blowfish.
*/
bool BytesToKey(const byte *data, int dataLen, 
                unsigned int rounds, CipherKey *key)
{
  Registry<MAC> registry = MAC::GetRegistry();
  shared_ptr<MAC> sha1(registry.CreateForMatch("SHA-1"));
  if (!sha1)
    return false;

  if( data == NULL || dataLen == 0 )
    return false; // OpenSSL returns nkey here, but why?  It is a failure..

  SecureMem mdBuf( sha1->outputSize() );
  int addmd = 0;
  int remaining = key->size();

  for(;;)
  {
    sha1->init();
    if( addmd++ )
      sha1->update(mdBuf.data, mdBuf.size);
    sha1->update(data, dataLen);
    sha1->write(mdBuf.data);

    for(unsigned int i=1; i < rounds; ++i)
    {
      sha1->init();
      sha1->update(mdBuf.data, mdBuf.size);
      sha1->write(mdBuf.data);
    }

    int offset = 0;
    int toCopy = MIN( remaining, (int)mdBuf.size - offset );
    if( toCopy )
    {
      memcpy( key->data(), mdBuf.data+offset, toCopy );
      key += toCopy;
      remaining -= toCopy;
      offset += toCopy;
    }
    if(remaining == 0) break;
  }

  return true;
}

long time_diff(const timeval &end, const timeval &start)
{
  return (end.tv_sec - start.tv_sec) * 1000 * 1000 +
      (end.tv_usec - start.tv_usec);
}

int CipherV1::TimedPBKDF2(const char *pass, int passlen,
                          const byte *salt, int saltlen,
                          CipherKey *key, long desiredPDFTime)
{
#ifdef HAVE_VALGRIND_MEMCHECK_H
  VALGRIND_CHECK_MEM_IS_DEFINED(pass, passlen);
  VALGRIND_CHECK_MEM_IS_DEFINED(salt, saltlen);
#endif
  Registry<PBKDF> registry = PBKDF::GetRegistry();
  shared_ptr<PBKDF> impl(registry.CreateForMatch(NAME_PKCS5_PBKDF2_HMAC_SHA1));
  if (!impl)
    return -1;

  int iter = 1000;
  timeval start, end;

  for(;;)
  {
    gettimeofday( &start, 0 );
    if (!impl->makeKey(pass, passlen, salt, saltlen, iter, key))
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
// - Version 3:1 drops support for verison 1:0 blowfish keys, in order to avoid
// having to duplicate the behavior of old EVP_BytesToKey implementations.
static Interface BlowfishInterface = makeInterface( "ssl/blowfish", 3, 1, 1 );
static Interface AESInterface = makeInterface( "ssl/aes", 3, 1, 2 );

static Interface NullCipherInterface = makeInterface( "nullCipher", 1, 0, 0);

static Range BFKeyRange(128,256,32);
static int BFDefaultKeyLen = 160;

static Range AESKeyRange(128,256,64);
static int AESDefaultKeyLen = 192;

list<CipherV1::CipherAlgorithm> CipherV1::GetAlgorithmList() 
{
  list<CipherV1::CipherAlgorithm> result;
  Registry<BlockCipher> blockCipherRegistry = BlockCipher::GetRegistry();

  if (blockCipherRegistry.GetPropertiesForMatch(NAME_AES_CBC) != NULL) {
    CipherV1::CipherAlgorithm alg;
    alg.name = "AES";
    alg.description = "16 byte block cipher";
    alg.iface = AESInterface;
    alg.keyLength = AESKeyRange;
    alg.blockSize = Range(64, 4096, 16);
    result.push_back(alg);   
  }

  if (blockCipherRegistry.GetPropertiesForMatch(NAME_BLOWFISH_CBC) != NULL) {
    CipherV1::CipherAlgorithm alg;
    alg.name = "Blowfish";
    alg.description = "8 byte block cipher";
    alg.iface = BlowfishInterface;
    alg.keyLength = BFKeyRange;
    alg.blockSize = Range(64, 4096, 8);
    result.push_back(alg);   
  }

  CipherV1::CipherAlgorithm alg;
  alg.name = "Null";
  alg.description = "Pass-through cipher, for testing only!";
  alg.iface = NullCipherInterface;
  alg.keyLength = Range(0);
  alg.blockSize = Range(64, 4096, 8);
  result.push_back(alg);   
  
  return result;
}

shared_ptr<CipherV1> CipherV1::New(const std::string& name, int keyLen) {
  for (auto &it : GetAlgorithmList()) {
    if (it.name == name)
      return New(it.iface, keyLen);
  }

  return shared_ptr<CipherV1>();
}

shared_ptr<CipherV1> CipherV1::New(const Interface &iface, int keyLen) {
  shared_ptr<CipherV1> result(new CipherV1());
  if (!result->initCiphers(iface, iface, keyLen))
    result.reset();
  return result;
}

CipherV1::CipherV1()
{
}

bool CipherV1::initCiphers(const Interface &iface, const Interface &realIface,
                           int keyLength)
{
  this->iface = iface;
  this->realIface = realIface;

  Registry<BlockCipher> blockCipherRegistry = BlockCipher::GetRegistry();
  Registry<StreamCipher> streamCipherRegistry = StreamCipher::GetRegistry();

  int defaultKeyLength;
  Range keyRange;

  if (implements(AESInterface, iface)) {
    keyRange = AESKeyRange; 
    defaultKeyLength = AESDefaultKeyLen;
    _blockCipher.reset( blockCipherRegistry.CreateForMatch(NAME_AES_CBC) );
    _streamCipher.reset( streamCipherRegistry.CreateForMatch(NAME_AES_CFB) );
  } else if (implements(BlowfishInterface, iface)) {
    keyRange = BFKeyRange;
    defaultKeyLength = BFDefaultKeyLen;
    _blockCipher.reset( blockCipherRegistry.CreateForMatch(NAME_BLOWFISH_CBC) );
    _streamCipher.reset( streamCipherRegistry.CreateForMatch
                        (NAME_BLOWFISH_CFB) );
  } else if (implements(NullCipherInterface, iface)) {
    keyRange = Range(0);
    defaultKeyLength = 0;
    _blockCipher.reset( blockCipherRegistry.CreateForMatch("NullCipher") );
    _streamCipher.reset( streamCipherRegistry.CreateForMatch("NullCipher") );
  }

  if (!_blockCipher || !_streamCipher) {
    LOG(INFO) << "Unsupported cipher " << iface.name();
    return false;
  }

  if (keyLength <= 0)
    _keySize = defaultKeyLength / 8;
  else
    _keySize = keyRange.closest(keyLength) / 8;

  _pbkdf.reset(PBKDF::GetRegistry().CreateForMatch(
               NAME_PKCS5_PBKDF2_HMAC_SHA1));
  if (!_pbkdf) {
    LOG(ERROR) << "PBKDF missing";
    return false;
  }

  // Initialize the cipher with a temporary key in order to determine the block
  // size.
  CipherKey tmpKey = _pbkdf->randomKey(_keySize);
  _blockCipher->setKey(tmpKey);
  _ivLength = _blockCipher->blockSize();
  _iv.reset(new SecureMem(_ivLength));
  _keySet = false;

  Lock l(_hmacMutex);
  _hmac.reset(MAC::GetRegistry().CreateForMatch(NAME_SHA1_HMAC));
  if (!_hmac) {
    LOG(ERROR) << "SHA1_HMAC not available";
    return false;
  }

  return true;
}

CipherV1::~CipherV1()
{
}

Interface CipherV1::interface() const
{
  return realIface;
}

/*
   Create a key from the password.
   Use SHA to distribute entropy from the password into the key.

   This algorithm must remain constant for backward compatibility, as this key
   is used to encipher/decipher the master key.
 */
CipherKey CipherV1::newKey(const char *password, int passwdLength,
                           int *iterationCount, long desiredDuration,
                           const byte *salt, int saltLen)
{
#ifdef HAVE_VALGRIND_MEMCHECK_H
  VALGRIND_CHECK_MEM_IS_DEFINED(password, passwdLength);
  VALGRIND_CHECK_MEM_IS_DEFINED(salt, saltLen);
#endif
  CipherKey key(_keySize + _ivLength);

  if(*iterationCount == 0)
  {
    // timed run, fills in iteration count
    int res = TimedPBKDF2(password, passwdLength, 
                          salt, saltLen, &key,
                          1000 * desiredDuration);
    if(res <= 0)
    {
      LOG(ERROR) << "openssl error, PBKDF2 failed";
      return CipherKey();
    } else
      *iterationCount = res;
  } else
  {
    // known iteration length
    if (!_pbkdf->makeKey(password, passwdLength,
                         salt, saltLen, *iterationCount, &key))
    {
      LOG(ERROR) << "openssl error, PBKDF2 failed";
      return CipherKey();
    }
  }

  return key;
}

// Deprecated - for use only with filesystems which used a fixed-round PBKDF.
// Such configurations are replaced with a new PBKDF2 implementation when the
// password is changed or configuration is rewritten.
CipherKey CipherV1::newKey(const char *password, int passwdLength)
{
#ifdef HAVE_VALGRIND_MEMCHECK_H
  VALGRIND_CHECK_MEM_IS_DEFINED(password, passwdLength);
#endif
  CipherKey key(_keySize + _ivLength);

  bool ok = BytesToKey((byte *)password, passwdLength, 16, &key);
  LOG_IF(ERROR, !ok) << "newKey: BytesToKey failed";
  if (!ok)
    throw Error("BytesToKey failed");

  return key;
}

CipherKey CipherV1::newRandomKey()
{
  return _pbkdf->randomKey(_keySize + _ivLength);
}

bool CipherV1::pseudoRandomize( byte *buf, int len )
{
  return _pbkdf->pseudoRandom(buf, len);
}

bool CipherV1::setKey(const CipherKey &keyIv) {
  Lock l(_hmacMutex);

  // Key is actually key plus iv, so extract the different parts.
  CipherKey key(_keySize);
  memcpy(key.data(), keyIv.data(), _keySize);
  memcpy(_iv->data, keyIv.data() + _keySize, _ivLength);

  if (_blockCipher->setKey(key)
      && _streamCipher->setKey(key)
      && _hmac->setKey(key)) {
    _keySet = true;
    return true;
  }

  return false;
}

uint64_t CipherV1::MAC_64(const byte *data, int len,
                          uint64_t *chainedIV ) const
{
  rAssert( len > 0 );
  rAssert( _keySet );

  byte md[_hmac->outputSize()];
  
  Lock l(_hmacMutex);

  _hmac->init();
  _hmac->update(data, len);
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

    _hmac->update(h, 8);
  }

  bool ok = _hmac->write(md);
  rAssert(ok);

  // chop this down to a 64bit value..
  byte h[8] = {0,0,0,0,0,0,0,0};

  // XXX: the last byte off the hmac isn't used.  This minor inconsistency
  // must be maintained in order to maintain backward compatiblity with earlier
  // releases.
  for(int i=0; i<_hmac->outputSize()-1; ++i)
    h[i%8] ^= (byte)(md[i]);

  uint64_t value = (uint64_t)h[0];
  for(int i=1; i<8; ++i)
    value = (value << 8) | (uint64_t)h[i];

  // TODO: should not be here.
  if(chainedIV)
    *chainedIV = value;

  return value;
}

unsigned int CipherV1::reduceMac32(uint64_t mac64) 
{
  return ((mac64 >> 32) & 0xffffffff) ^ (mac64 & 0xffffffff);
}

unsigned int CipherV1::reduceMac16(uint64_t mac64)
{
  unsigned int mac32 = reduceMac32(mac64);
  return ((mac32 >> 16) & 0xffff) ^ (mac32 & 0xffff);
}

CipherKey CipherV1::readKey(const byte *data, bool checkKey)
{
  rAssert( _keySet );
  CipherKey key(_keySize + _ivLength);

  // First N bytes are checksum bytes.
  unsigned int checksum = 0;
  for(int i=0; i<KEY_CHECKSUM_BYTES; ++i)
    checksum = (checksum << 8) | (unsigned int)data[i];

  memcpy( key.data(), data+KEY_CHECKSUM_BYTES, key.size() );
  if (!streamDecode(key.data(), key.size(), checksum)) {
    LOG(ERROR) << "stream decode failure";
    return CipherKey();
  }

  // check for success
#ifdef HAVE_VALGRIND_MEMCHECK_H
  VALGRIND_CHECK_MEM_IS_DEFINED(key.data(), key.size());
#endif

  unsigned int checksum2 = reduceMac32(
      MAC_64( key.data(), key.size(), NULL ));

#ifdef HAVE_VALGRIND_MEMCHECK_H
  VALGRIND_CHECK_VALUE_IS_DEFINED(checksum2);
  VALGRIND_CHECK_VALUE_IS_DEFINED(checksum);
#endif

  if(checkKey && (checksum2 != checksum))
  {
    LOG(INFO) << "checksum mismatch: expected " << checksum 
        << ", got " << checksum2
        << "on decode of " << _keySize + _ivLength << " bytes";
    return CipherKey();
  }

  return key;
}

void CipherV1::writeKey(const CipherKey &ckey, byte *out)
{
  rAssert( _keySet );

  SecureMem tmpBuf(ckey.size());
  memcpy(tmpBuf.data, ckey.data(), tmpBuf.size);

  unsigned int checksum = reduceMac32(
      MAC_64(tmpBuf.data, tmpBuf.size, NULL));
  streamEncode(tmpBuf.data, tmpBuf.size, checksum);

  // first N bytes contain HMAC derived checksum..
  for(int i=1; i<=KEY_CHECKSUM_BYTES; ++i)
  {
    out[KEY_CHECKSUM_BYTES-i] = checksum & 0xff;
    checksum >>= 8;
  }

  memcpy( out+KEY_CHECKSUM_BYTES, tmpBuf.data, tmpBuf.size );
}

std::string CipherV1::encodeAsString(const CipherKey &key)
{
  rAssert( _keySet );
  int encodedSize = encodedKeySize();
  vector<byte> buf(encodedSize);
  writeKey(key, buf.data());

  int b64Len = B256ToB64Bytes( encodedSize );
  byte *b64Key = new byte[b64Len + 1];

  changeBase2( buf.data(), encodedSize, 8, b64Key, b64Len, 6);
  B64ToAscii( b64Key, b64Len );
  b64Key[ b64Len - 1 ] = '\0';

  return string( (const char *)b64Key );
}

int CipherV1::encodedKeySize() const
{
  return _keySize + _ivLength + KEY_CHECKSUM_BYTES;
}

int CipherV1::keySize() const
{
  return _keySize;
}

int CipherV1::cipherBlockSize() const
{
  rAssert( _keySet );
  return _blockCipher->blockSize();
}

// Deprecated: For backward compatibility only.
// A watermark attack was discovered against this IV construction.  If an
// attacker could get a victim to store a carefully crafted file, they could
// later determine if the victim had the file in encrypted storage (without
// decrypting the file).
static void setIVec_old(byte *ivec, int ivLen, unsigned int seed)
{
  unsigned int var1 = 0x060a4011 * seed; 
  unsigned int var2 = 0x0221040d * (seed ^ 0xD3FEA11C);

  ivec[0] ^= (var1 >> 24) & 0xff;
  ivec[1] ^= (var2 >> 16) & 0xff;
  ivec[2] ^= (var1 >> 8 ) & 0xff;
  ivec[3] ^= (var2      ) & 0xff;
  ivec[4] ^= (var2 >> 24) & 0xff;
  ivec[5] ^= (var1 >> 16) & 0xff;
  ivec[6] ^= (var2 >> 8 ) & 0xff;
  ivec[7] ^= (var1      ) & 0xff;

  if(ivLen > 8)
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

void CipherV1::setIVec(byte *ivec, uint64_t seed) const
{
  rAssert( _keySet );
  memcpy( ivec, _iv->data, _ivLength );
  if (iface.major() < 3)
  {
    // Backward compatible mode.
    setIVec_old(ivec, _ivLength, seed);
    return;
  }

  vector<byte> md(_hmac->outputSize());
  for(int i=0; i<8; ++i)
  {
    md[i] = (byte)(seed & 0xff);
    seed >>= 8;
  }

  // combine ivec and seed with HMAC
  Lock l(_hmacMutex);
  _hmac->init();
  _hmac->update(ivec, _ivLength);
  _hmac->update(md.data(), 8);
  _hmac->write(md.data());

  memcpy(ivec, md.data(), _ivLength);
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
bool CipherV1::streamEncode(byte *buf, int size, uint64_t iv64) const
{
  rAssert( _keySet );
  rAssert( size > 0 );

  vector<byte> ivec(_ivLength);
  shuffleBytes( buf, size );

  setIVec( ivec.data(), iv64 );
  if (!_streamCipher->encrypt(ivec.data(), buf, buf, size))
    return false;

  flipBytes( buf, size );
  shuffleBytes( buf, size );

  setIVec( ivec.data(), iv64 + 1 );
  if (!_streamCipher->encrypt(ivec.data(), buf, buf, size))
    return false;

  return true;
}

bool CipherV1::streamDecode(byte *buf, int size, uint64_t iv64) const
{
  rAssert( _keySet );
  rAssert( size > 0 );

  vector<byte> ivec(_ivLength);
  setIVec( ivec.data(), iv64 + 1 );
  if (!_streamCipher->decrypt(ivec.data(), buf, buf, size))
    return false;

  unshuffleBytes( buf, size );
  flipBytes( buf, size );

  setIVec( ivec.data(), iv64 );
  if (!_streamCipher->decrypt(ivec.data(), buf, buf, size))
    return false;

  unshuffleBytes( buf, size );

  return true;
}


bool CipherV1::blockEncode(byte *buf, int size, uint64_t iv64) const
{
  rAssert( _keySet );
  rAssert( size > 0 );

  vector<byte> ivec(_ivLength);
  setIVec( ivec.data(), iv64 );
  return _blockCipher->encrypt(ivec.data(), buf, buf, size);
}

bool CipherV1::blockDecode(byte *buf, int size, uint64_t iv64) const
{
  rAssert( _keySet );
  rAssert( size > 0 );

  vector<byte> ivec(_ivLength);
  setIVec( ivec.data(), iv64 );
  return _blockCipher->decrypt(ivec.data(), buf, buf, size);
}

}  // namespace encfs
