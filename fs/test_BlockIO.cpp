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

#include "cipher/MemoryPool.h"

#include "fs/testing.h"
#include "fs/FileUtils.h"
#include "fs/FSConfig.h"
#include "fs/MemFileIO.h"
#include "fs/MemBlockFileIO.h"

using namespace encfs;

namespace {

TEST(BlockFileIOTest, BasicIO) {
  // Base for comparison.
  MemFileIO base(1024);
  ASSERT_EQ(1024, base.getSize());

  FSConfigPtr cfg = makeConfig( CipherV1::New("Null"), 512);
  MemBlockFileIO block(512, cfg);
  block.truncate(1024);
  ASSERT_EQ(1024, block.getSize());

  MemBlock mb;
  mb.allocate(256);

  IORequest req;
  req.offset = 0;
  req.data = mb.data;
  req.dataLen = 256;

  for (int i = 0; i < 4; i++) {
    req.offset = i * 256;
    memset(req.data, 0, req.dataLen);
    ASSERT_TRUE(base.write(req));
    
    req.offset = i * 256;
    memset(req.data, 0, req.dataLen);
    ASSERT_TRUE(block.write(req));
  }

  ASSERT_NO_FATAL_FAILURE(compare(&base, &block, 0, 1024));
}

}  // namespace encfs

