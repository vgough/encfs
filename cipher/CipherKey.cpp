
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

#include "cipher/CipherKey.h"

#include "base/shared_ptr.h"
#include "base/types.h"
#include "cipher/MemoryPool.h"

namespace encfs {

CipherKey::CipherKey()
    : _valid(false)
{
}

CipherKey::CipherKey(int length)
    : _valid(true)
{
  if (length > 0)
    _mem.reset(new SecureMem(length));
}

CipherKey::CipherKey(const byte *data, int length)
    : _valid(true)
{
  _mem.reset(new SecureMem(length));
  memcpy(_mem->data(), data, length);
}

CipherKey::CipherKey(const CipherKey& src)
    : _valid(src._valid),
      _mem(src._mem)
{
}

CipherKey::~CipherKey() 
{
}

void CipherKey::operator = (const CipherKey& src) 
{
  _mem = src._mem;
  _valid = src._valid;
}

byte *CipherKey::data() const 
{
  return !_mem ? NULL : _mem->data();
}

int CipherKey::size() const 
{
  return !_mem ? 0 : _mem->size();
}

void CipherKey::reset() 
{
  _mem.reset();
  _valid = false;
}

bool CipherKey::valid() const 
{
  return _valid;
}

bool operator == (const CipherKey &a, const CipherKey &b) {
  if (a.size() != b.size())
      return false;
  return memcmp(a.data(), b.data(), a.size()) == 0;
}

}  // namespace encfs

