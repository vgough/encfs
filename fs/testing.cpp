
/*****************************************************************************
 * Author:   Valient Gough <vgough@pobox.com>
 *
 *****************************************************************************
 * Copyright (c) 2012 Valient Gough
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


#include "fs/testing.h"

#include <list>
#include <string>

#include <gtest/gtest.h>

#include "cipher/CipherV1.h"
#include "cipher/MemoryPool.h"

#include "fs/FSConfig.h"
#include "fs/fsconfig.pb.h"
#include "fs/FileUtils.h"
#include "fs/MACFileIO.h"
#include "fs/MemFileIO.h"

using namespace std;

namespace encfs {

FSConfigPtr makeConfig(const shared_ptr<CipherV1>& cipher, int blockSize) {
  FSConfigPtr cfg = FSConfigPtr(new FSConfig);
  cfg->cipher = cipher;
  cfg->key = cipher->newRandomKey();
  cfg->cipher->setKey(cfg->key);
  cfg->config.reset(new EncfsConfig);
  cfg->config->set_block_size(blockSize);
  cfg->opts.reset(new EncFS_Opts);

  return cfg;
}

void runWithCipher(const string& cipherName, int blockSize,
                   void (*func)(FSConfigPtr& config)) {
  shared_ptr<CipherV1> cipher = CipherV1::New(cipherName);
  ASSERT_TRUE(cipher.get() != NULL);

  FSConfigPtr cfg = makeConfig(cipher, blockSize);
  ASSERT_NO_FATAL_FAILURE(func(cfg));
}

void runWithAllCiphers(void (*func)(FSConfigPtr& config)) {
  list<CipherV1::CipherAlgorithm> algorithms = CipherV1::GetAlgorithmList();
  list<CipherV1::CipherAlgorithm>::const_iterator it;
  for (it = algorithms.begin(); it != algorithms.end(); ++it) {
    int blockSize = it->blockSize.closest(512);
    int keyLength = it->keyLength.closest(128);
    SCOPED_TRACE(testing::Message() << "Testng with cipher " << it->name 
        << ", blocksize " << blockSize << ", keyLength " << keyLength);
    shared_ptr<CipherV1> cipher = CipherV1::New(it->iface, keyLength);
    ASSERT_TRUE(cipher.get() != NULL);

    FSConfigPtr cfg = makeConfig(cipher, blockSize);
    ASSERT_NO_FATAL_FAILURE(func(cfg));
  }
}

void truncate(FileIO* a, FileIO* b, int len) {
  SCOPED_TRACE(testing::Message() << "Truncate from " << a->getSize()
      << " to len " << len);
  a->truncate(len);
  ASSERT_EQ(len, a->getSize());

  b->truncate(len);
  ASSERT_EQ(len, b->getSize());

  compare(a, b, 0, len);
}

void writeRandom(FSConfigPtr& cfg, FileIO* a, FileIO* b, int offset, int len) {
  SCOPED_TRACE(testing::Message() << "Write random " << offset << ", " << len);

  if (a->getSize() < offset + len)
    a->truncate(offset + len);

  unsigned char *buf = new unsigned char[len];
  ASSERT_TRUE(cfg->cipher->pseudoRandomize(buf, len));

  IORequest req;
  req.data = new unsigned char[len];
  req.dataLen = len;
 
  memcpy(req.data, buf, len);
  req.offset = offset;
  ASSERT_TRUE(a->write(req));
  
  memcpy(req.data, buf, len);
  req.offset = offset;
  ASSERT_TRUE(b->write(req));

  compare(a, b, offset, len);

  delete[] buf;
}

void compare(FileIO* a, FileIO* b, int offset, int len) {
  SCOPED_TRACE(testing::Message() << "compare " << offset << ", " << len
      << " from file length " << a->getSize());
  unsigned char *buf1 = new unsigned char[len];
  unsigned char *buf2 = new unsigned char[len];
  memset(buf1, 0, len);
  memset(buf2, 0, len);

  IORequest req;
  req.offset = offset;
  req.data = buf1;
  req.dataLen = len;
  ssize_t size1 = a->read(req);

  req.offset = offset;
  req.data = buf2;
  req.dataLen = len;
  ssize_t size2 = b->read(req);

  ASSERT_EQ(size1, size2);
  for(int i = 0; i < len; i++) {
    bool match = (buf1[i] == buf2[i]);
    ASSERT_TRUE(match) << "mismatched data at offset " << i << " of " << len;
    if(!match) {
        break;
    }
  }

  delete[] buf1;
  delete[] buf2;
}

void comparisonTest(FSConfigPtr& cfg, FileIO* a, FileIO* b) {
  const int size = 18*1024;
  writeRandom(cfg, a, b, 0, size);
  if (testing::Test::HasFatalFailure()) return;
  compare(a, b, 0, size);
  if (testing::Test::HasFatalFailure()) return;

  for (int i = 0; i < 10000; i++) {
    SCOPED_TRACE(testing::Message() << "Test Loop " << i);
    int len = 128 + random() % 2048;
    int offset = (len == a->getSize()) ? 0 
        : random() % (a->getSize() - len);
    writeRandom(cfg, a, b, offset, len);
    if (testing::Test::HasFatalFailure()) return;
    ASSERT_EQ(a->getSize(), b->getSize());
  }

  SCOPED_TRACE("Final Compare");
  compare(a, b, 0, a->getSize());
}

int main(int argc, char **argv) {
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}

}  // namespace encfs

