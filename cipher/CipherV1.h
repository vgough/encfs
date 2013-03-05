/*****************************************************************************
 * Author:   Valient Gough <vgough@pobox.com>
 *
 *****************************************************************************
 * Copyright (c) 2004-2013, Valient Gough
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

#ifndef _CipherV1_incl_
#define _CipherV1_incl_

#include "base/Interface.h"
#include "base/Mutex.h"
#include "base/shared_ptr.h"

#include "cipher/BlockCipher.h"
#include "cipher/StreamCipher.h"
#include "cipher/MAC.h"
#include "cipher/PBKDF.h"

namespace encfs {

class SecureMem;

/*
   Implements Encfs V1.x ciphers support.

   Design:
   Variable algorithm, key size, and block size.

   Partial blocks, keys, and names are encrypted using the cipher in a pseudo
   stream mode (CFB).

   Keys are encrypted with 2-4 (KEY_CHECKSUM_BYTES define) checksum bytes
   derived from an HMAC over both they key data and the initial value vector
   associated with the key.  This allows a good chance at detecting an
   incorrect password when we try and decrypt the master key.

   File names are encrypted in the same way, with 2 checksum bytes derived
   from an HMAC over the filename.  This is done not to allow checking the
   results, but to make the output much more random.  Changing one letter in a
   filename should result in a completely different encrypted filename, to
   help frustrate any attempt to guess information about files from their
   encrypted names.

   Stream encryption involves two encryption passes over the data, implemented
   as:
   1. shuffle
   2. encrypt
   3. reverse
   4. shuffle
   5. encrypt
   The reason for the shuffle and reverse steps (and the second encrypt pass)
   is to try and propogate any changed bits to a larger set.  If only a single
   pass was made with the stream cipher in CFB mode, then a change to one byte
   may only affect one byte of output, allowing some XOR attacks.

   The shuffle/encrypt is used as above in filename encryption as well,
   although it is not necessary as they have checksum bytes which augment the
   initial value vector to randomize the output.  But it makes the code
   simpler to reuse the encryption algorithm as is.
*/
class CipherV1
{
  Interface iface;
  Interface realIface;

  shared_ptr<BlockCipher> _blockCipher;
  shared_ptr<StreamCipher> _streamCipher;
  shared_ptr<PBKDF> _pbkdf;

  // HMac is stateful, so access is controlled via mutex.
  mutable Mutex _hmacMutex;
  mutable shared_ptr<MAC> _hmac;

  unsigned int _keySize; // in bytes
  unsigned int _ivLength;

  shared_ptr<SecureMem> _iv;
  bool _keySet;

 public:

  struct CipherAlgorithm
  {
    std::string name;
    std::string description;
    Interface iface;
    Range keyLength;
    Range blockSize;
  };

  static void init(bool threaded);
  static void shutdown(bool threaded);

  // Returns a list of supported algorithms.
  static std::list<CipherAlgorithm> GetAlgorithmList();
  static shared_ptr<CipherV1> New(const std::string &name, int keyLen = -1);
  static shared_ptr<CipherV1> New(const Interface &alg, int keyLen = -1);

  // Password-based key derivation function which determines the
  // number of iterations based on a desired execution time (in microseconds).
  // Returns the number of iterations applied.
  static int TimedPBKDF2(const char *pass, int passLen,
                         const byte *salt, int saltLen,
                         CipherKey *out, long desiredPDFTimeMicroseconds);

  CipherV1();
  ~CipherV1();

  bool initCiphers(const Interface &iface,
                   const Interface &realIface, int keyLength);

  // returns the real interface, not the one we're emulating (if any)..
  Interface interface() const;

  // create a new key based on a password
  CipherKey newKey(const char *password, int passwdLength,
                   int *iterationCount, long desiredDuration,
                   const byte *salt, int saltLen);
  // deprecated - for backward compatibility
  CipherKey newKey(const char *password, int passwdLength);
  // create a new random key
  CipherKey newRandomKey();

  // Read and decrypt a key.
  // data must be len keySize()
  CipherKey readKey(const byte *data, bool checkKey);

  // Encrypt and write the given key.
  void writeKey(const CipherKey &key, byte *data); 

  // Encrypt and store a key as a string.
  std::string encodeAsString(const CipherKey &key);
              

  // meta-data about the cypher
  int keySize() const;
  int encodedKeySize() const;
  int cipherBlockSize() const;

  bool pseudoRandomize(byte *buf, int len);

  // Sets the key used for encoding / decoding, and MAC operations.
  bool setKey(const CipherKey &key);

  uint64_t MAC_64(const byte *src, int len,
                  uint64_t *augment = NULL) const;

  static unsigned int reduceMac32(uint64_t mac64);
  static unsigned int reduceMac16(uint64_t mac64);

  // functional interfaces
  /*
     Stream encoding in-place.
   */
  bool streamEncode(byte *data, int len, uint64_t iv64) const;
  bool streamDecode(byte *data, int len, uint64_t iv64) const;

  /*
     Block encoding is done in-place.  Partial blocks are supported, but
     blocks are always expected to begin on a block boundary.  See
     blockSize().
   */
  bool blockEncode(byte *buf, int size, uint64_t iv64) const;
  bool blockDecode(byte *buf, int size, uint64_t iv64) const;

 private:
  void setIVec(byte *out, uint64_t seed) const;
};

}  // namespace encfs

#endif

