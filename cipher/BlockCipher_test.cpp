
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

#include <list>

#include <gtest/gtest.h>

#include "base/shared_ptr.h"
#include "cipher/BlockCipher.h"
#include "cipher/MemoryPool.h"
#include "cipher/PBKDF.h"
#include "cipher/testing.h"

using namespace encfs;
using std::list;
using std::string;

namespace {

void compare(const byte *a, const byte *b, int size) {
  for (int i = 0; i < size; i++) {
    bool match = (a[i] == b[i]);
    ASSERT_TRUE(match) << "mismatched data at offset " << i 
        << " of " << size;
    if (!match)
      break;
  }
}

TEST(RequiredBlockCiphers, BlockCipher) {
  auto aes_cbc = BlockCipher::GetRegistry().CreateForMatch(NAME_AES_CBC);
  ASSERT_TRUE(aes_cbc != NULL);

  auto bf_cbc = BlockCipher::GetRegistry().CreateForMatch(NAME_BLOWFISH_CBC);
  ASSERT_TRUE(bf_cbc != NULL);
}

TEST(RequiredStreamCiphers, StreamCipher) {
  auto aes_cfb = StreamCipher::GetRegistry().CreateForMatch(NAME_AES_CFB);
  ASSERT_TRUE(aes_cfb != NULL);

  auto bf_cfb = StreamCipher::GetRegistry().CreateForMatch(NAME_BLOWFISH_CFB);
  ASSERT_TRUE(bf_cfb != NULL);
}

TEST(BlowfishTestVector, BlockCihper) {
  auto cbc = BlockCipher::GetRegistry().CreateForMatch(NAME_BLOWFISH_CBC);
  auto cfb = StreamCipher::GetRegistry().CreateForMatch(NAME_BLOWFISH_CFB);

  CipherKey key(16);
  setDataFromHex(key.data(), key.size(), "0123456789abcdeff0e1d2c3b4a59687");
  cbc->setKey(key);
  cfb->setKey(key);

  byte iv[8];
  setDataFromHex(iv, 8, "fedcba9876543210");

  byte data[32];
  setDataFromHex(data, 32,
           "37363534333231204e6f77206973207468652074696d6520666f722000000000");

  byte cipherData[32];
  cbc->encrypt(iv, data, cipherData, 32);

  ASSERT_EQ("6b77b4d63006dee605b156e27403979358deb9e7154616d959f1652bd5ff92cc",
            stringToHex(cipherData, 32));

  cfb->encrypt(iv, data, cipherData, 29);
  ASSERT_EQ("e73214a2822139caf26ecf6d2eb9e76e3da3de04d1517200519d57a6c3",
            stringToHex(cipherData, 29));
}

TEST(BlockEncryptionTest, BlockCipher) {
  Registry<BlockCipher> registry = BlockCipher::GetRegistry();

  shared_ptr<PBKDF> pbkdf(
      PBKDF::GetRegistry().CreateForMatch(NAME_PKCS5_PBKDF2_HMAC_SHA1));

  list<string> ciphers = registry.GetAll(); 
  for (const string &name : ciphers) {
    const BlockCipher::Properties *properties =
        registry.GetProperties(name.c_str());
    SCOPED_TRACE(testing::Message() << "Cipher " << name);

    for (int keySize = properties->keySize.min();
         keySize <= properties->keySize.max();
         keySize += properties->keySize.inc()) {
      SCOPED_TRACE(testing::Message() << "Key size " << keySize);

      shared_ptr<BlockCipher> cipher (registry.Create(name.c_str()));

      CipherKey key = pbkdf->randomKey(keySize / 8);
      ASSERT_TRUE(key.valid());
      cipher->setKey(key);

      // Create some data to encrypt.
      int blockSize = cipher->blockSize();
      MemBlock mb;
      mb.allocate(16 * blockSize);

      for (int i = 0; i < 16 * blockSize; i++) {
        mb.data[i] = i % 256;
      }

      MemBlock iv;
      iv.allocate(blockSize);
      for (int i = 0; i < blockSize; i++) {
        iv.data[i] = i;
      }

      // Encrypt.
      MemBlock encrypted;
      encrypted.allocate(16 * blockSize);

      ASSERT_TRUE(cipher->encrypt(iv.data, mb.data,
                                  encrypted.data, 16 * blockSize));

      // Decrypt.
      MemBlock decrypted;
      decrypted.allocate(16 * blockSize);
      ASSERT_TRUE(cipher->decrypt(iv.data, encrypted.data,
                                  decrypted.data, 16 * blockSize));

      compare(mb.data, decrypted.data, 16 * blockSize);
    }
  }
}

}  // namespace
