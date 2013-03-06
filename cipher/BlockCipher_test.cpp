
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

#include "base/config.h"
#include "base/shared_ptr.h"
#include "cipher/BlockCipher.h"
#include "cipher/MemoryPool.h"
#include "cipher/PBKDF.h"
#include "cipher/testing.h"

#ifdef HAVE_VALGRIND_MEMCHECK_H
#include <valgrind/memcheck.h>
#endif

using namespace encfs;
using std::list;
using std::string;

namespace {

void compare(const byte *a, const byte *b, int size) {
#ifdef HAVE_VALGRIND_MEMCHECK_H
  ASSERT_EQ(0, VALGRIND_CHECK_MEM_IS_DEFINED(a, size));
  ASSERT_EQ(0, VALGRIND_CHECK_MEM_IS_DEFINED(b, size));
#endif
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

template <typename T>
void checkTestVector(const char *cipherName,
                     const char *hexKey,
                     const char *hexIv,
                     const char *hexPlaintext,
                     const char *hexCipher) {
  SCOPED_TRACE(testing::Message() << "Testing cipher: " << cipherName
               << ", key = " << hexKey << ", plaintext = " << hexPlaintext);

  auto cipher = T::GetRegistry().CreateForMatch(cipherName);
  ASSERT_TRUE(cipher != NULL);

  CipherKey key(strlen(hexKey)/2);
  setDataFromHex(key.data(), key.size(), hexKey);
  ASSERT_TRUE(cipher->setKey(key));

  byte iv[strlen(hexIv)/2];
  setDataFromHex(iv, sizeof(iv), hexIv);

  byte plaintext[strlen(hexPlaintext)/2];
  setDataFromHex(plaintext, sizeof(plaintext), hexPlaintext);

  byte ciphertext[sizeof(plaintext)];
  ASSERT_TRUE(cipher->encrypt(iv, plaintext, ciphertext, sizeof(ciphertext)));

  ASSERT_EQ(hexCipher, stringToHex(ciphertext, sizeof(ciphertext)));

  byte decypered[sizeof(plaintext)];
  ASSERT_TRUE(cipher->decrypt(iv, ciphertext, decypered, sizeof(ciphertext)));

  for (unsigned int i = 0; i < sizeof(plaintext); ++i) {
    ASSERT_EQ(plaintext[i], decypered[i]);
  }
}

TEST(TestVectors, BlockCipher) {
  // BF128 CBC
  checkTestVector<BlockCipher>(NAME_BLOWFISH_CBC,
      "0123456789abcdeff0e1d2c3b4a59687",
      "fedcba9876543210",
      "37363534333231204e6f77206973207468652074696d6520666f722000000000",
      "6b77b4d63006dee605b156e27403979358deb9e7154616d959f1652bd5ff92cc");

  // BF128 CFB
  checkTestVector<StreamCipher>(NAME_BLOWFISH_CFB,
      "0123456789abcdeff0e1d2c3b4a59687",
      "fedcba9876543210",
      "37363534333231204e6f77206973207468652074696d6520666f722000",
      "e73214a2822139caf26ecf6d2eb9e76e3da3de04d1517200519d57a6c3");
 
  // AES128 CBC
  checkTestVector<BlockCipher>(NAME_AES_CBC,
      "2b7e151628aed2a6abf7158809cf4f3c",
      "000102030405060708090a0b0c0d0e0f",
      "6bc1bee22e409f96e93d7e117393172a",
      "7649abac8119b246cee98e9b12e9197d");
  
  // AES128 CFB
  checkTestVector<StreamCipher>(NAME_AES_CFB,
      "2b7e151628aed2a6abf7158809cf4f3c",
      "000102030405060708090a0b0c0d0e0f",
      "6bc1bee22e409f96e93d7e117393172a",
      "3b3fd92eb72dad20333449f8e83cfb4a");

  // AES256 CBC
  checkTestVector<BlockCipher>(NAME_AES_CBC,
      "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4",
      "000102030405060708090a0b0c0d0e0f",
      "6bc1bee22e409f96e93d7e117393172a",
      "f58c4c04d6e5f1ba779eabfb5f7bfbd6");
  
  // AES256 CFB
  checkTestVector<StreamCipher>(NAME_AES_CFB,
      "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4",
      "000102030405060708090a0b0c0d0e0f",
      "6bc1bee22e409f96e93d7e117393172a",
      "dc7e84bfda79164b7ecd8486985d3860");
}

TEST(BlockEncryptionTest, BlockCipher) {
  Registry<BlockCipher> registry = BlockCipher::GetRegistry();

  shared_ptr<PBKDF> pbkdf(
      PBKDF::GetRegistry().CreateForMatch(NAME_PBKDF2_HMAC_SHA1));

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
      ASSERT_TRUE(cipher->setKey(key));

      // Create some data to encrypt.
      int blockSize = cipher->blockSize();
      SCOPED_TRACE(testing::Message() << "blockSize " << blockSize);

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
