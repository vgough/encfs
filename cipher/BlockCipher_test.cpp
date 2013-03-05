
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

TEST(BlockEncryptionTest, BlockCipher) {
    Registry<BlockCipher> registry = BlockCipher::GetRegistry();
    list<string> ciphers = registry.GetAll(); 
    for (const string &name : ciphers) {
        const BlockCipher::Properties *properties = registry.GetProperties(name.c_str());
        SCOPED_TRACE(testing::Message() << "Cipher " << name);

        for (int keySize = properties->keySize.min();
                 keySize <= properties->keySize.max();
                 keySize += properties->keySize.inc()) {
            SCOPED_TRACE(testing::Message() << "Key size " << keySize);

            shared_ptr<BlockCipher> cipher (registry.Create(name.c_str()));

            ASSERT_TRUE(cipher->randomKey(keySize / 8));

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
