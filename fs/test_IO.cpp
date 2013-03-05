
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

#include <list>

#include <gtest/gtest.h>
#include "fs/testing.h"

#include "cipher/Cipher.h"
#include "cipher/MemoryPool.h"

#include "fs/CipherFileIO.h"
#include "fs/FileUtils.h"
#include "fs/FSConfig.h"
#include "fs/MACFileIO.h"
#include "fs/MemFileIO.h"

using namespace encfs;

namespace {

TEST(MemIOTest, BasicIO) {
  MemFileIO io(1024);
  ASSERT_EQ(1024, io.getSize());

  MemBlock mb;
  mb.allocate(256);

  IORequest req;
  req.offset = 0;
  req.data = mb.data;
  req.dataLen = 256;

  for (int i = 0; i < 4; i++) {
    req.offset = i * 256;
    memset(req.data, 0, req.dataLen);
    ASSERT_TRUE(io.write(req));
  }

  for (int i = 0; i < 4; i++) {
    req.offset = i * 256;
    ASSERT_EQ(req.dataLen, io.read(req));
  }
}

void testMacIO(FSConfigPtr& cfg) {
  shared_ptr<MemFileIO> base(new MemFileIO(0));
  shared_ptr<MACFileIO> test(new MACFileIO(base, cfg));

  shared_ptr<MemFileIO> dup(new MemFileIO(0));
  comparisonTest(cfg, test.get(), dup.get());
}

TEST(IOTest, NullMacIO) {
  runWithCipher("Null", 512, testMacIO);
}

TEST(IOTest, MacIO) {
  runWithAllCiphers(testMacIO);
}

void testCipherIO(FSConfigPtr& cfg) {
  shared_ptr<MemFileIO> base(new MemFileIO(0));
  shared_ptr<CipherFileIO> test(new CipherFileIO(base, cfg));

  shared_ptr<MemFileIO> dup(new MemFileIO(0));
  comparisonTest(cfg, test.get(), dup.get());
}

TEST(IOTest, NullCipherFileIO) {
  runWithCipher("Null", 512, testCipherIO);
}

TEST(IOTest, CipherFileIO) {
  runWithAllCiphers(testCipherIO);
}

}  // namespace

