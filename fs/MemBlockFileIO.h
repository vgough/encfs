
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

#ifndef _MEMBLOCKFILEIO_incl_
#define _MEMBLOCKFILEIO_incl_

#include "fs/BlockFileIO.h"

#include <string>
#include <vector>

namespace encfs {

class MemFileIO;

class MemBlockFileIO : public BlockFileIO {
 public:
  MemBlockFileIO(int blockSize, const FSConfigPtr &cfg);
  virtual ~MemBlockFileIO();

  virtual Interface interface() const;

  virtual void setFileName(const char *name);
  virtual const char *getFileName() const;

  virtual int open(int flags);
  
  virtual int getAttr(struct stat *stbuf) const;
  virtual off_t getSize() const;

  virtual bool isWritable() const;

  virtual int truncate(off_t size);
 protected:
  virtual ssize_t readOneBlock(const IORequest &req) const;
  virtual bool writeOneBlock(const IORequest &req);

 private:
  MemFileIO *impl;
};

}  // namespace encfs

#endif

