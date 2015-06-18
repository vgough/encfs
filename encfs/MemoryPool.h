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

struct MemBlock {
  unsigned char *data;

  void *internalData;

  MemBlock();
};

inline MemBlock::MemBlock() : data(0), internalData(0) {}

/*
    Memory Pool for fixed sized objects.

    Usage:
    MemBlock mb = MemoryPool::allocate( size );
    // do things with storage in   mb.data
    unsigned char *buffer = mb.data;
    MemoryPool::release( mb );
*/
namespace MemoryPool {
MemBlock allocate(int size);
void release(const MemBlock &el);
void destroyAll();
}

}  // namespace encfs

#endif
