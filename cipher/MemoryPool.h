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

#include "base/config.h"
#include "base/types.h"

#ifdef WITH_BOTAN
namespace Botan {
template <typename T> class SecureVector;
}
#endif

namespace encfs {

/*
    Memory Pool for fixed sized objects.
    Use SecureMem if storing sensitive information.

    Usage:
    MemBlock mb;
    mb.allocate( size );
    // do things with storage in   mb.data
    byte *buffer = mb.data;

    // memblock freed when destructed
*/
struct MemBlock
{
    byte *data;
    int size;

    MemBlock();
    ~MemBlock();

    void allocate(int size);
};

inline MemBlock::MemBlock()
    : data(0), size(0)
{
}

class SecureMem
{
 public:
  byte* data() const;
  int size() const;

  explicit SecureMem(int len);
  ~SecureMem();

 private:
#ifdef WITH_BOTAN
  Botan::SecureVector<unsigned char> *data_;
#else
  byte *data_;
  int size_;
#endif
};

#ifndef WITH_BOTAN
inline byte* SecureMem::data() const {
  return data_;
}
inline int SecureMem::size() const {
  return size_;
}
#endif

bool operator == (const SecureMem &a, const SecureMem &b);

}  // namespace encfs

#endif

