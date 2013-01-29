
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

#ifndef _MEMFILEIO_incl_
#define _MEMFILEIO_incl_

#include "FileIO.h"

#include <string>
#include <vector>

class MemFileIO : public FileIO {
 public:
  MemFileIO(int size);
  virtual ~MemFileIO();

  virtual Interface interface() const;

  virtual void setFileName(const char *name);
  virtual const char *getFileName() const;

  virtual int open(int flags);
  
  virtual int getAttr(struct stat *stbuf) const;
  virtual off_t getSize() const;

  virtual ssize_t read(const IORequest& req) const;
  virtual bool write(const IORequest& req);

  virtual int truncate(off_t size);
  virtual bool isWritable() const;

 private:
  std::vector<char> buf;
  std::string name;
  bool writable;
};

#endif

