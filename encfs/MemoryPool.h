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

#ifndef _MemoryPool_incl_
#define _MemoryPool_incl_

namespace encfs {

struct BlockList;

// MemBlock holds a memory block stored in secure memory
// (if possible with the crypto backend).  Blocks should be
// of consistent size, as the allocator is meant for working with
// file crypt blocks.
//
// To get a block, construct a MemBlock and call allocate(), or
// use the constructor with size.  This either grabs a block from
// the thread-local block queue, or else constructs a new block.
//
// When the MemBlock instance is destroyed, the block is returned
// to the list for reuse.
class MemBlock {
public:
  MemBlock() =default;
  explicit MemBlock(int size);
  ~MemBlock();

  bool valid() const;
  void allocate(int size);

  unsigned char *get() const;

  static void freeAll();

private:
  unsigned char *data;
  BlockList *bl;
};

inline bool MemBlock::valid() const {
  return bl != nullptr;
}

inline unsigned char *MemBlock::get() const {
  return data;
}

}  // namespace encfs

#endif
