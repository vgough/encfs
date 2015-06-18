/*****************************************************************************
 * Author:   Valient Gough <vgough@pobox.com>
 *
 *****************************************************************************
 * Copyright (c) 2004, Valient Gough
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

#ifndef _BlockFileIO_incl_
#define _BlockFileIO_incl_

#include <sys/types.h>

#include "FSConfig.h"
#include "FileIO.h"

namespace encfs {

/*
    Implements block scatter / gather interface.  Requires derived classes to
    implement readOneBlock() / writeOneBlock() at a minimum.

    When a partial block write is requested it will be turned into a read of
    the existing block, merge with the write request, and a write of the full
    block.
*/
class BlockFileIO : public FileIO {
 public:
  BlockFileIO(int blockSize, const FSConfigPtr &cfg);
  virtual ~BlockFileIO();

  // implemented in terms of blocks.
  virtual ssize_t read(const IORequest &req) const;
  virtual bool write(const IORequest &req);

  virtual int blockSize() const;

 protected:
  int truncateBase(off_t size, FileIO *base);
  void padFile(off_t oldSize, off_t newSize, bool forceWrite);

  // same as read(), except that the request.offset field is guarenteed to be
  // block aligned, and the request size will not be larger then 1 block.
  virtual ssize_t readOneBlock(const IORequest &req) const = 0;
  virtual bool writeOneBlock(const IORequest &req) = 0;

  ssize_t cacheReadOneBlock(const IORequest &req) const;
  bool cacheWriteOneBlock(const IORequest &req);

  int _blockSize;
  bool _allowHoles;
  bool _noCache;

  // cache last block for speed...
  mutable IORequest _cache;
};

}  // namespace encfs

#endif
