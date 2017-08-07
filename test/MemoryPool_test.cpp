#include "gtest/gtest.h"

#include "encfs/MemoryPool.h"

using namespace encfs;

TEST(MemoryPool, Allocate) {
  auto block = MemoryPool::allocate(1024);
  ASSERT_TRUE(block.data != nullptr);
  ASSERT_TRUE(block.internalData != nullptr);
  MemoryPool::release(block);
}