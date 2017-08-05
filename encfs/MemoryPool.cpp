/*****************************************************************************
 * Author:   Valient Gough <vgough@pobox.com>
 *
 *****************************************************************************
 * Copyright (c) 2003, Valient Gough
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

#include "config.h"
#include "MemoryPool.h"

#include <cstring>
#include <openssl/ossl_typ.h>

#ifdef HAVE_VALGRIND_MEMCHECK_H
#include <valgrind/memcheck.h>
#else
#define VALGRIND_MAKE_MEM_NOACCESS(a, b)
#define VALGRIND_MAKE_MEM_UNDEFINED(a, b)
#endif

#include <openssl/buffer.h>

namespace encfs {

static thread_local BlockList *gMemPool = nullptr;

struct BlockList {
  BlockList *next;
  BUF_MEM *buf;

  unsigned char *get();
  int size();
  void clear();

  explicit BlockList(int size);
  ~BlockList();

  BlockList(const BlockList &) = delete;
  BlockList &operator=(const BlockList &) = delete;
};

unsigned char *BlockList::get() {
  return reinterpret_cast<unsigned char *>(buf->data);
}

int BlockList::size() { return buf->max; }

void BlockList::clear() {
  VALGRIND_MAKE_MEM_UNDEFINED(buf->data, buf->max);
  memset(buf->data, 0, buf->max);
  VALGRIND_MAKE_MEM_NOACCESS(buf->data, buf->max);
}

BlockList::BlockList(int sz) {
  buf = BUF_MEM_new();
  BUF_MEM_grow(buf, sz);
  VALGRIND_MAKE_MEM_NOACCESS(buf->data, buf->max);
}

BlockList::~BlockList() {
  VALGRIND_MAKE_MEM_UNDEFINED(buf->data, buf->max);
  BUF_MEM_free(buf);
}

static BlockList *allocateBlock(int size) {
  // check if we already have a large enough block available..
  BlockList *parent = nullptr;
  BlockList *block = gMemPool;
  while (block != nullptr && block->size() < size) {
    parent = block;
    block = block->next;
  }

  if (block == nullptr) {
    // Allocate a new block.
    return new BlockList(size);
  }

  // unlink block from list
  if (parent == nullptr) {
    gMemPool = block->next;
  } else {
    parent->next = block->next;
  }
  block->next = nullptr;
  VALGRIND_MAKE_MEM_UNDEFINED(block->get(), size);
  return block;
}

MemBlock::MemBlock(int size) : bl(nullptr) { allocate(size); }

MemBlock::~MemBlock() {
  if (bl == nullptr) {
    return;
  }

  bl->clear();
  bl->next = gMemPool;
  gMemPool = bl;
  bl = nullptr;
  data = nullptr;
}

void MemBlock::allocate(int size) {
  if (bl != nullptr) {
    if (size <= bl->size()) {
      return;
    }

    // Return existing block.
    bl->clear();
    bl->next = gMemPool;
    gMemPool = bl;
  }

  bl = allocateBlock(size);
  data = bl->get();
}

void MemBlock::freeAll() {
  while (gMemPool != nullptr) {
    BlockList *next = gMemPool->next;

    delete gMemPool;
    gMemPool = next;
  }
}

}  // namespace encfs
