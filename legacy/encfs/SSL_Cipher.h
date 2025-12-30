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

#ifndef _SSL_Cipher_incl_
#define _SSL_Cipher_incl_

#include <memory>
#include <stdint.h>

#include "Cipher.h"
#include "CipherKey.h"
#include "Interface.h"

#ifndef EVP_CIPHER
struct evp_cipher_st;

using EVP_CIPHER = struct evp_cipher_st;
#endif

namespace encfs {

class SSLKey;

/*
    Implements Cipher interface for OpenSSL's ciphers.

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
class SSL_Cipher : public Cipher {
  Interface iface;
  Interface realIface;
  const EVP_CIPHER *_blockCipher;
  const EVP_CIPHER *_streamCipher;
  unsigned int _keySize;  // in bytes
  unsigned int _ivLength;

 public:
  SSL_Cipher(const Interface &iface, const Interface &realIface,
             const EVP_CIPHER *blockCipher, const EVP_CIPHER *streamCipher,
             int keyLength);
  virtual ~SSL_Cipher();

  // returns the real interface, not the one we're emulating (if any)..
  virtual Interface interface() const;

  // create a new key based on a password
  virtual CipherKey newKey(const char *password, int passwdLength,
                           int &iterationCount, long desiredDuration,
                           const unsigned char *salt, int saltLen);
  // deprecated - for backward compatibility
  virtual CipherKey newKey(const char *password, int passwdLength);
  // create a new random key
  virtual CipherKey newRandomKey();

  // data must be len keySize()
  virtual CipherKey readKey(const unsigned char *data,
                            const CipherKey &encodingKey, bool checkKey);
  virtual void writeKey(const CipherKey &key, unsigned char *data,
                        const CipherKey &encodingKey);
  virtual bool compareKey(const CipherKey &A, const CipherKey &B) const;

  // meta-data about the cypher
  virtual int keySize() const;
  virtual int encodedKeySize() const;
  virtual int cipherBlockSize() const;

  virtual bool randomize(unsigned char *buf, int len, bool strongRandom) const;

  virtual uint64_t MAC_64(const unsigned char *src, int len,
                          const CipherKey &key, uint64_t *augment) const;

  // functional interfaces
  /*
      Stream encoding in-place.
  */
  virtual bool streamEncode(unsigned char *in, int len, uint64_t iv64,
                            const CipherKey &key) const;
  virtual bool streamDecode(unsigned char *in, int len, uint64_t iv64,
                            const CipherKey &key) const;

  /*
      Block encoding is done in-place.  Partial blocks are supported, but
      blocks are always expected to begin on a block boundary.  See
      blockSize().
  */
  virtual bool blockEncode(unsigned char *buf, int size, uint64_t iv64,
                           const CipherKey &key) const;
  virtual bool blockDecode(unsigned char *buf, int size, uint64_t iv64,
                           const CipherKey &key) const;

  // hack to help with static builds
  static bool Enabled();

 private:
  void setIVec(unsigned char *ivec, uint64_t seed,
               const std::shared_ptr<SSLKey> &key) const;

  // deprecated - for backward compatibility
  void setIVec_old(unsigned char *ivec, unsigned int seed,
                   const std::shared_ptr<SSLKey> &key) const;
};

}  // namespace encfs

#endif
